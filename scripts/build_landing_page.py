#!/usr/bin/env python3
"""Build the static repository landing page and public status document."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

import segno

REPOSITORY_URL = "https://aldobarr.github.io/plezy-fdroid/fdroid/repo"
SOURCE_URL = "https://github.com/edde746/plezy"
EXPECTED_ABIS = {"arm64-v8a", "armeabi-v7a", "x86_64"}
EXPECTED_APK_SIGNER = (
    "903b862cf5e3a0bfbad9b5e049ec3de703f83422bba9c5559a7b019716316e72"
)
PLACEHOLDER = re.compile(r"{{([A-Z0-9_]+)}}")


class LandingPageError(RuntimeError):
    """Raised when verified publication data is incomplete or inconsistent."""


def _fingerprint(value: str, name: str) -> str:
    normalized = value.replace(":", "").lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise LandingPageError(f"{name} must be a SHA-256 fingerprint")
    return normalized


def _timestamp(value: str | None) -> str:
    if value is None:
        parsed = datetime.now(timezone.utc)
    else:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise LandingPageError("--timestamp must be an ISO-8601 timestamp") from error
        if parsed.tzinfo is None:
            raise LandingPageError("--timestamp must include a timezone")
        parsed = parsed.astimezone(timezone.utc)
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _render(template: str, values: dict[str, str]) -> str:
    missing = sorted(set(PLACEHOLDER.findall(template)) - set(values))
    if missing:
        raise LandingPageError(f"template placeholders have no values: {', '.join(missing)}")
    rendered = PLACEHOLDER.sub(lambda match: values[match.group(1)], template)
    unresolved = PLACEHOLDER.findall(rendered)
    if unresolved:
        raise LandingPageError(f"unresolved template placeholders: {', '.join(unresolved)}")
    return rendered


def _validated_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise LandingPageError("verified manifest must be a JSON object")
    release = value.get("release")
    assets = value.get("upstream_assets")
    apks = value.get("apks")
    if not isinstance(release, dict) or not isinstance(assets, list) or not isinstance(
        apks, list
    ):
        raise LandingPageError("verified manifest is incomplete")
    if {item.get("abi") for item in apks if isinstance(item, dict)} != EXPECTED_ABIS:
        raise LandingPageError("verified manifest must contain exactly the expected ABIs")
    if len(apks) != len(EXPECTED_ABIS) or len(assets) != len(EXPECTED_ABIS):
        raise LandingPageError("verified manifest contains an unexpected package count")
    if {
        _fingerprint(str(item.get("signer_sha256", "")), "APK signer")
        for item in apks
    } != {EXPECTED_APK_SIGNER}:
        raise LandingPageError("verified manifest does not use the pinned APK signer")
    return value


def build_landing_page(args: argparse.Namespace) -> None:
    manifest = _validated_manifest(Path(args.manifest))
    release = manifest["release"]
    apks = sorted(manifest["apks"], key=lambda item: item["abi"])
    assets = sorted(manifest["upstream_assets"], key=lambda item: item["abi"])
    repo_fingerprint = _fingerprint(args.repo_fingerprint, "repository fingerprint")
    deployed_at = _timestamp(args.timestamp)
    add_url = f"{REPOSITORY_URL}?fingerprint={repo_fingerprint.upper()}"

    output_dir = Path(args.output_dir)
    public_assets = output_dir / "assets"
    public_assets.mkdir(parents=True, exist_ok=True)
    source_assets = Path(args.assets_dir)
    for filename in ("icon.png", "screenshot.png"):
        source = source_assets / filename
        if not source.is_file():
            raise LandingPageError(f"site asset is missing: {source}")
        shutil.copy2(source, public_assets / filename)

    qr_path = public_assets / "repository-qr.svg"
    segno.make_qr(add_url, error="h").save(
        str(qr_path),
        scale=6,
        border=2,
        dark="#171513",
        light="#ffffff",
        xmldecl=False,
    )

    version_codes = ", ".join(
        f"{item['abi']}: {item['version_code']}" for item in apks
    )
    values = {
        "ADD_URL": escape(add_url, quote=True),
        "APK_FINGERPRINT": escape(EXPECTED_APK_SIGNER.upper()),
        "LAST_DEPLOYMENT": escape(deployed_at),
        "RELEASE_NAME": escape(str(release.get("name") or release["tag"])),
        "RELEASE_TAG": escape(str(release["tag"])),
        "RELEASE_URL": escape(str(release["url"]), quote=True),
        "REPOSITORY_FINGERPRINT": escape(repo_fingerprint.upper()),
        "REPOSITORY_URL": escape(REPOSITORY_URL + "/", quote=True),
        "SOURCE_URL": escape(SOURCE_URL, quote=True),
        "UPSTREAM_PUBLISHED_AT": escape(str(release["published_at"])),
        "VERSION_CODES": escape(version_codes),
    }
    template = Path(args.template).read_text(encoding="utf-8")
    html = _render(template, values)

    status = {
        "schema_version": 1,
        "last_successful_deployment": deployed_at,
        "repository": {
            "url": REPOSITORY_URL,
            "fingerprint": repo_fingerprint,
            "fdroidserver_version": args.fdroidserver_version,
        },
        "upstream": {
            "release_id": release["id"],
            "tag": release["tag"],
            "name": release.get("name") or release["tag"],
            "url": release["url"],
            "published_at": release["published_at"],
            "assets": [
                {
                    "abi": item["abi"],
                    "id": item["id"],
                    "name": item["name"],
                    "size": item["size"],
                    "sha256": item["sha256"],
                }
                for item in assets
            ],
        },
        "apks": [
            {
                "abi": item["abi"],
                "package_id": item["package_id"],
                "version_name": item["version_name"],
                "version_code": item["version_code"],
                "min_sdk": item["min_sdk"],
                "target_sdk": item["target_sdk"],
                "filename": item["repo_filename"],
                "sha256": item["sha256"],
                "signer_sha256": item["signer_sha256"],
            }
            for item in apks
        ],
    }

    for destination, content in (
        (output_dir / "index.html", html),
        (output_dir / "status.json", json.dumps(status, indent=2, sort_keys=True) + "\n"),
    ):
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, destination)
    (output_dir / ".nojekyll").touch()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--repo-fingerprint", required=True)
    parser.add_argument("--fdroidserver-version", required=True)
    parser.add_argument("--template", required=True)
    parser.add_argument("--assets-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--timestamp")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        build_landing_page(parse_args(argv))
    except (KeyError, OSError, TypeError, ValueError, LandingPageError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
