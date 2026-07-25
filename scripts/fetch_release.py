#!/usr/bin/env python3
"""Select and securely unpack the expected APK archives from a Plezy release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import IO, Any
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

UPSTREAM_RELEASE_API = "https://api.github.com/repos/edde746/plezy/releases/latest"
PUBLISHED_STATE_URL = "https://aldobarr.github.io/plezy-fdroid/status.json"
GITHUB_API_VERSION = "2026-03-10"
EXPECTED_ARCHIVES = {
    "arm64-v8a": "plezy-android-arm64-v8a.tar.gz",
    "armeabi-v7a": "plezy-android-armeabi-v7a.tar.gz",
    "x86_64": "plezy-android-x86_64.tar.gz",
}
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_APK_BYTES = 256 * 1024 * 1024


class ReleaseError(RuntimeError):
    """Raised when upstream release data violates the publication contract."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_stream(source: IO[bytes], destination: Path, maximum_bytes: int) -> int:
    written = 0
    with destination.open("wb") as output:
        while chunk := source.read(1024 * 1024):
            written += len(chunk)
            if written > maximum_bytes:
                raise ReleaseError(f"download exceeds {maximum_bytes} bytes")
            output.write(chunk)
    return written


def _download(url: str, destination: Path, allow_local_assets: bool) -> int:
    parsed = urlparse(url)
    if parsed.scheme == "file":
        if not allow_local_assets:
            raise ReleaseError("local release assets are allowed only in explicit test mode")
    elif (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or not parsed.path.startswith("/edde746/plezy/releases/download/")
    ):
        raise ReleaseError(f"unexpected release asset URL: {url}")

    request = Request(url, headers={"User-Agent": "plezy-fdroid-publisher/1"})
    with urlopen(request, timeout=120) as response:
        return _copy_stream(response, destination, MAX_ARCHIVE_BYTES)


def _read_json_url(
    url: str,
    *,
    github_token: str | None = None,
    allow_not_found: bool = False,
) -> dict[str, Any] | None:
    parsed = urlparse(url)
    allowed = (
        parsed.scheme == "https"
        and (
            (parsed.hostname == "api.github.com" and url == UPSTREAM_RELEASE_API)
            or (
                parsed.hostname == "aldobarr.github.io"
                and parsed.path == "/plezy-fdroid/status.json"
            )
        )
    )
    if not allowed:
        raise ReleaseError(f"unexpected JSON endpoint: {url}")

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "plezy-fdroid-publisher/1",
    }
    if parsed.hostname == "api.github.com":
        headers["X-GitHub-Api-Version"] = GITHUB_API_VERSION
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=30) as response:
            value = json.load(response)
    except HTTPError as error:
        if allow_not_found and error.code == 404:
            return None
        raise ReleaseError(f"request for {url} failed with HTTP {error.code}") from error
    if not isinstance(value, dict):
        raise ReleaseError(f"{url} did not return a JSON object")
    return value


def _safe_extract_apk(archive_path: Path, apk_path: Path) -> None:
    with tarfile.open(archive_path, mode="r:gz") as archive:
        regular_files = []
        for member in archive.getmembers():
            member_path = PurePosixPath(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ReleaseError(f"unsafe archive member: {member.name}")
            if member.issym() or member.islnk() or member.isdev():
                raise ReleaseError(f"unsupported archive member: {member.name}")
            if member.isfile():
                regular_files.append(member)

        if len(regular_files) != 1 or PurePosixPath(regular_files[0].name).name != "plezy.apk":
            raise ReleaseError("each release archive must contain exactly one plezy.apk")

        member = regular_files[0]
        if member.size > MAX_APK_BYTES:
            raise ReleaseError(f"APK exceeds {MAX_APK_BYTES} bytes")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise ReleaseError(f"could not read {member.name}")
        written = _copy_stream(extracted, apk_path, MAX_APK_BYTES)
        if written != member.size:
            raise ReleaseError(
                f"APK size mismatch for {member.name}: expected {member.size}, received {written}"
            )


def _validate_release(release: dict[str, Any]) -> dict[str, Any]:
    if release.get("draft") or release.get("prerelease"):
        raise ReleaseError("release must be published, non-draft, and non-prerelease")
    if not isinstance(release.get("id"), int):
        raise ReleaseError("release ID is missing or invalid")
    for field in ("tag_name", "published_at", "html_url"):
        if not isinstance(release.get(field), str) or not release[field]:
            raise ReleaseError(f"release field {field} is missing or invalid")
    if not isinstance(release.get("assets"), list):
        raise ReleaseError("release assets are missing or invalid")
    return release


def _select_assets(release: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    assets_by_name: dict[str, list[dict[str, Any]]] = {}
    for asset in release["assets"]:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            continue
        assets_by_name.setdefault(asset["name"], []).append(asset)

    selected = []
    for abi, archive_name in EXPECTED_ARCHIVES.items():
        candidates = assets_by_name.get(archive_name, [])
        if len(candidates) != 1:
            raise ReleaseError(f"expected exactly one release asset named {archive_name}")
        selected.append((abi, candidates[0]))
    return selected


def _parse_timestamp(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReleaseError(f"{field_name} is not a valid ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ReleaseError(f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _asset_identity(abi: str, asset: dict[str, Any]) -> dict[str, Any]:
    digest_value = asset.get("digest")
    if not isinstance(digest_value, str) or not digest_value.startswith("sha256:"):
        raise ReleaseError(f"{asset.get('name')} has no GitHub SHA-256 digest")
    digest = digest_value.removeprefix("sha256:").lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ReleaseError(f"{asset.get('name')} has an invalid SHA-256 digest")
    if not isinstance(asset.get("id"), int) or not isinstance(asset.get("size"), int):
        raise ReleaseError(f"{asset.get('name')} has invalid identity metadata")
    return {
        "abi": abi,
        "id": asset["id"],
        "name": asset["name"],
        "size": asset["size"],
        "sha256": digest,
    }


def _publication_decision(
    release: dict[str, Any],
    selected_assets: list[tuple[str, dict[str, Any]]],
    published_state: dict[str, Any] | None,
    now: datetime,
    refresh_after_days: int,
    force_refresh: bool,
) -> tuple[bool, str]:
    if published_state is None:
        return True, "new-release"

    upstream = published_state.get("upstream")
    if not isinstance(upstream, dict):
        raise ReleaseError("published state has no valid upstream section")
    same_release = (
        upstream.get("release_id") == release["id"]
        and upstream.get("tag") == release["tag_name"]
    )
    if not same_release:
        return True, "new-release"

    published_assets = upstream.get("assets")
    if not isinstance(published_assets, list):
        raise ReleaseError("published state has no valid upstream asset list")
    expected = {
        identity["name"]: {
            "id": identity["id"],
            "name": identity["name"],
            "size": identity["size"],
            "sha256": identity["sha256"],
        }
        for identity in (
            _asset_identity(abi, asset) for abi, asset in selected_assets
        )
    }
    actual = {
        item.get("name"): {
            "id": item.get("id"),
            "name": item.get("name"),
            "size": item.get("size"),
            "sha256": item.get("sha256"),
        }
        for item in published_assets
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    if actual != expected:
        raise ReleaseError("upstream assets changed beneath the already-published release tag")

    if force_refresh:
        return True, "forced-signed-index-refresh"

    deployed_at = published_state.get("last_successful_deployment")
    if not isinstance(deployed_at, str):
        raise ReleaseError("published state has no deployment timestamp")
    refresh_at = _parse_timestamp(
        deployed_at, "last_successful_deployment"
    ) + timedelta(days=refresh_after_days)
    if now < refresh_at:
        return False, "current-release-is-fresh"
    return True, "signed-index-refresh"


def _previous_publication(
    published_state: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if published_state is None:
        return None
    upstream = published_state.get("upstream")
    apks = published_state.get("apks")
    if not isinstance(upstream, dict) or not isinstance(apks, list):
        raise ReleaseError("published state is missing release or APK identity")
    if not isinstance(upstream.get("release_id"), int) or not isinstance(
        upstream.get("tag"), str
    ):
        raise ReleaseError("published state has an invalid release identity")
    return {
        "release_id": upstream["release_id"],
        "tag": upstream["tag"],
        "apks": apks,
    }


def fetch_release(args: argparse.Namespace) -> dict[str, Any]:
    if args.release_metadata:
        release_value = json.loads(
            Path(args.release_metadata).read_text(encoding="utf-8")
        )
    else:
        release_value = _read_json_url(
            UPSTREAM_RELEASE_API,
            github_token=os.environ.get(args.github_token_env),
        )
    if not isinstance(release_value, dict):
        raise ReleaseError("release metadata must be a JSON object")
    release = _validate_release(release_value)
    selected_assets = _select_assets(release)
    published_state = None
    if args.published_state:
        published_state = json.loads(
            Path(args.published_state).read_text(encoding="utf-8")
        )
        if not isinstance(published_state, dict):
            raise ReleaseError("published state must be a JSON object")
    elif not args.ignore_published_state and not args.release_metadata:
        published_state = _read_json_url(
            PUBLISHED_STATE_URL,
            allow_not_found=True,
        )
    now = (
        _parse_timestamp(args.now, "now")
        if args.now
        else datetime.now(timezone.utc)
    )
    publish, reason = _publication_decision(
        release,
        selected_assets,
        published_state,
        now,
        args.refresh_after_days,
        args.force_refresh,
    )
    previous_publication = _previous_publication(published_state)
    output_dir = Path(args.output_dir)
    if not publish:
        result = {
            "schema_version": 1,
            "publish": False,
            "reason": reason,
            "release": {
                "id": release["id"],
                "tag": release["tag_name"],
                "name": release.get("name") or release["tag_name"],
                "url": release["html_url"],
                "published_at": release["published_at"],
            },
            "assets": [
                _asset_identity(abi, asset)
                for abi, asset in selected_assets
            ],
        }
        if previous_publication is not None:
            result["previous_publication"] = previous_publication
        return result

    apk_dir = output_dir / "apks"
    apk_dir.mkdir(parents=True, exist_ok=True)

    manifest_assets = []
    for abi, asset in selected_assets:
        identity = _asset_identity(abi, asset)
        expected_digest = identity["sha256"]

        archive_path = output_dir / f"{abi}.tar.gz"
        received_size = _download(
            str(asset.get("browser_download_url", "")),
            archive_path,
            args.allow_local_assets,
        )
        if received_size != asset.get("size"):
            raise ReleaseError(
                f"size mismatch for {asset['name']}: expected {asset.get('size')}, "
                f"received {received_size}"
            )
        actual_digest = _sha256(archive_path)
        if actual_digest != expected_digest:
            raise ReleaseError(
                f"digest mismatch for {asset['name']}: expected {expected_digest}, "
                f"received {actual_digest}"
            )

        apk_path = apk_dir / f"{abi}.apk"
        _safe_extract_apk(archive_path, apk_path)
        archive_path.unlink()
        manifest_assets.append(
            {
                "abi": abi,
                "id": identity["id"],
                "name": asset["name"],
                "size": received_size,
                "sha256": actual_digest,
                "apk_path": apk_path.relative_to(output_dir).as_posix(),
                "apk_sha256": _sha256(apk_path),
            }
        )

    result = {
        "schema_version": 1,
        "publish": True,
        "reason": reason,
        "release": {
            "id": release["id"],
            "tag": release["tag_name"],
            "name": release.get("name") or release["tag_name"],
            "url": release["html_url"],
            "published_at": release["published_at"],
        },
        "assets": manifest_assets,
    }
    if previous_publication is not None:
        result["previous_publication"] = previous_publication
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-metadata")
    state_group = parser.add_mutually_exclusive_group()
    state_group.add_argument("--published-state")
    state_group.add_argument("--ignore-published-state", action="store_true")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--now")
    parser.add_argument("--refresh-after-days", type=int, default=6)
    parser.add_argument("--force-refresh", action="store_true")
    parser.add_argument("--github-token-env", default="GITHUB_TOKEN")
    parser.add_argument("--allow-local-assets", action="store_true")
    args = parser.parse_args(argv)
    if args.refresh_after_days < 1:
        parser.error("--refresh-after-days must be at least 1")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        manifest = fetch_release(args)
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = output_dir / "release.json"
        temporary_path = manifest_path.with_suffix(".json.tmp")
        temporary_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        shutil.move(temporary_path, manifest_path)
    except (OSError, ValueError, tarfile.TarError, ReleaseError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
