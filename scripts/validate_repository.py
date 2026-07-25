#!/usr/bin/env python3
"""Validate generated F-Droid indexes and packages before Pages upload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

PACKAGE_ID = "com.edde746.plezy"
EXPECTED_ABIS = {"arm64-v8a", "armeabi-v7a", "x86_64"}
REPOSITORY_URL = "https://aldobarr.github.io/plezy-fdroid/fdroid/repo"


class RepositoryError(RuntimeError):
    """Raised when generated output is incomplete, unsigned, or inconsistent."""


def _fingerprint(value: str, name: str) -> str:
    normalized = value.replace(":", "").lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise RepositoryError(f"{name} is not a SHA-256 fingerprint")
    return normalized


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_tool(executable: str, arguments: list[str]) -> str:
    command = [executable, *arguments]
    if os.name == "nt" and Path(executable).suffix.lower() in {".bat", ".cmd"}:
        command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", *command]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    if result.returncode != 0:
        raise RepositoryError(
            f"{Path(executable).name} failed with exit {result.returncode}: {output}"
        )
    return output


def _verify_jar_identity(
    jar_path: Path,
    *,
    jarsigner: str,
    keytool: str,
    expected_fingerprint: str,
) -> None:
    _run_tool(jarsigner, ["-verify", str(jar_path)])
    certificate = _run_tool(keytool, ["-printcert", "-jarfile", str(jar_path)])
    matches = re.findall(r"SHA256:\s*([0-9A-Fa-f:]{64,95})", certificate)
    if not matches:
        raise RepositoryError(f"{jar_path.name} exposes no SHA-256 signer fingerprint")
    actual_fingerprints = {
        _fingerprint(match, f"{jar_path.name} signer") for match in matches
    }
    if actual_fingerprints != {expected_fingerprint}:
        raise RepositoryError(
            f"{jar_path.name} signers {sorted(actual_fingerprints)} do not match "
            f"{expected_fingerprint}"
        )


def _load_json_from_jar(
    path: Path,
    member_name: str,
    description: str,
) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(path) as archive:
            names = [name for name in archive.namelist() if name == member_name]
            if names != [member_name]:
                raise RepositoryError(
                    f"{path.name} must contain exactly one {member_name}"
                )
            value = json.loads(archive.read(member_name))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        raise RepositoryError(f"{path.name} is not a readable {description}") from error
    if not isinstance(value, dict):
        raise RepositoryError(f"{member_name} must contain a JSON object")
    return value


def _validate_signed_entry(
    entry: dict[str, Any],
    index_v2_path: Path,
) -> None:
    if entry.get("maxAge") != 14:
        raise RepositoryError("signed entry must advertise a 14-day maximum age")
    index = entry.get("index")
    if not isinstance(index, dict):
        raise RepositoryError("signed entry has no index-v2 descriptor")
    checks = {
        "name": "/index-v2.json",
        "sha256": _sha256(index_v2_path),
        "size": index_v2_path.stat().st_size,
        "numPackages": 1,
    }
    for field, expected in checks.items():
        if index.get(field) != expected:
            raise RepositoryError(
                f"signed entry index field {field} is {index.get(field)!r}, "
                f"expected {expected!r}"
            )


def _validate_index_v2(
    index: dict[str, Any],
    expected_apks: dict[str, dict[str, Any]],
    repo_dir: Path,
) -> None:
    repo = index.get("repo")
    packages = index.get("packages")
    if not isinstance(repo, dict) or not isinstance(packages, dict):
        raise RepositoryError("index-v2 is missing repository or package metadata")
    if repo.get("address") != REPOSITORY_URL:
        raise RepositoryError("index-v2 contains an unexpected repository URL")
    anti_features = repo.get("antiFeatures")
    categories = repo.get("categories")
    if not isinstance(anti_features, dict) or "Tracking" not in anti_features:
        raise RepositoryError("index-v2 does not define the Tracking anti-feature")
    if not isinstance(categories, dict) or "Multimedia" not in categories:
        raise RepositoryError("index-v2 does not define the Multimedia category")
    if set(packages) != {PACKAGE_ID}:
        raise RepositoryError("index-v2 contains an unexpected package set")

    package = packages[PACKAGE_ID]
    if not isinstance(package, dict):
        raise RepositoryError("index-v2 Plezy package entry is invalid")
    metadata = package.get("metadata")
    versions = package.get("versions")
    if not isinstance(metadata, dict) or not isinstance(versions, dict):
        raise RepositoryError("index-v2 Plezy metadata or versions are invalid")
    expected_signers = {item["signer_sha256"] for item in expected_apks.values()}
    if len(expected_signers) != 1:
        raise RepositoryError("verified APK manifest has inconsistent signers")
    expected_signer = expected_signers.pop()
    metadata_checks = {
        "preferredSigner": expected_signer,
        "categories": ["Multimedia"],
        "license": "GPL-3.0-only",
        "sourceCode": "https://github.com/edde746/plezy",
    }
    for field, expected in metadata_checks.items():
        if metadata.get(field) != expected:
            raise RepositoryError(
                f"index-v2 app metadata field {field} is {metadata.get(field)!r}, "
                f"expected {expected!r}"
            )

    expected_by_hash = {item["sha256"]: item for item in expected_apks.values()}
    if set(versions) != set(expected_by_hash):
        raise RepositoryError("index-v2 version hashes do not match verified APKs")
    for apk_hash, expected in expected_by_hash.items():
        version = versions[apk_hash]
        if not isinstance(version, dict):
            raise RepositoryError(f"index-v2 version {apk_hash} is invalid")
        file_entry = version.get("file")
        manifest = version.get("manifest")
        if not isinstance(file_entry, dict) or not isinstance(manifest, dict):
            raise RepositoryError(f"index-v2 version {apk_hash} is incomplete")
        filename = expected["repo_filename"]
        file_checks = {
            "name": f"/{filename}",
            "sha256": apk_hash,
            "size": (repo_dir / filename).stat().st_size,
        }
        for field, expected_value in file_checks.items():
            if file_entry.get(field) != expected_value:
                raise RepositoryError(
                    f"{filename} index-v2 file field {field} is "
                    f"{file_entry.get(field)!r}, expected {expected_value!r}"
                )
        manifest_checks = {
            "versionCode": expected["version_code"],
            "versionName": expected["version_name"],
            "nativecode": [expected["abi"]],
            "usesSdk": {
                "minSdkVersion": expected["min_sdk"],
                "targetSdkVersion": expected["target_sdk"],
            },
            "signer": {"sha256": [expected["signer_sha256"]]},
        }
        for field, expected_value in manifest_checks.items():
            if manifest.get(field) != expected_value:
                raise RepositoryError(
                    f"{filename} index-v2 manifest field {field} is "
                    f"{manifest.get(field)!r}, expected {expected_value!r}"
                )
        version_anti_features = version.get("antiFeatures")
        if not isinstance(version_anti_features, dict) or "Tracking" not in (
            version_anti_features
        ):
            raise RepositoryError(f"{filename} index-v2 entry omits Tracking")


def validate_repository(args: argparse.Namespace) -> None:
    fdroid_root = Path(args.fdroid_root)
    repo_dir = fdroid_root / "repo"
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("apks"), list):
        raise RepositoryError("verified manifest is incomplete")
    expected_fingerprint = _fingerprint(
        args.repo_fingerprint,
        "repository fingerprint",
    )

    for filename in ("entry.jar", "index.jar", "index-v1.jar", "index-v2.json"):
        if not (repo_dir / filename).is_file():
            raise RepositoryError(f"generated repository is missing {filename}")
    for filename in ("entry.jar", "index.jar", "index-v1.jar"):
        _verify_jar_identity(
            repo_dir / filename,
            jarsigner=args.jarsigner,
            keytool=args.keytool,
            expected_fingerprint=expected_fingerprint,
        )
    try:
        index_v2 = json.loads((repo_dir / "index-v2.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RepositoryError("index-v2.json is invalid") from error
    if not isinstance(index_v2, dict):
        raise RepositoryError("index-v2.json must contain a JSON object")
    entry = _load_json_from_jar(
        repo_dir / "entry.jar",
        "entry.json",
        "signed F-Droid entry",
    )
    _validate_signed_entry(entry, repo_dir / "index-v2.json")

    expected_apks = {
        item["repo_filename"]: item
        for item in manifest["apks"]
        if isinstance(item, dict) and isinstance(item.get("repo_filename"), str)
    }
    if len(expected_apks) != len(EXPECTED_ABIS) or {
        item.get("abi") for item in expected_apks.values()
    } != EXPECTED_ABIS:
        raise RepositoryError("verified manifest must contain exactly the expected ABI set")
    actual_apk_names = {path.name for path in repo_dir.glob("*.apk")}
    if actual_apk_names != set(expected_apks):
        raise RepositoryError(
            f"repository APK set {sorted(actual_apk_names)} does not match verified set "
            f"{sorted(expected_apks)}"
        )
    for filename, expected in expected_apks.items():
        if _sha256(repo_dir / filename) != expected["sha256"]:
            raise RepositoryError(f"{filename} changed after APK verification")

    _validate_index_v2(index_v2, expected_apks, repo_dir)
    index = _load_json_from_jar(
        repo_dir / "index-v1.jar",
        "index-v1.json",
        "F-Droid index",
    )
    repo = index.get("repo")
    if not isinstance(repo, dict):
        raise RepositoryError("index-v1 has no repository metadata")
    if repo.get("address") != REPOSITORY_URL or repo.get("maxage") != 14:
        raise RepositoryError("index-v1 repository identity or maximum age is invalid")
    apps = index.get("apps")
    if not isinstance(apps, list) or len(apps) != 1 or not isinstance(apps[0], dict):
        raise RepositoryError("index-v1 must contain exactly one app entry")
    app = apps[0]
    expected_signer = next(iter(expected_apks.values()))["signer_sha256"]
    app_checks = {
        "packageName": PACKAGE_ID,
        "allowedAPKSigningKeys": [expected_signer],
        "antiFeatures": ["Tracking"],
        "categories": ["Multimedia"],
        "license": "GPL-3.0-only",
        "sourceCode": "https://github.com/edde746/plezy",
    }
    for field, expected_value in app_checks.items():
        if app.get(field) != expected_value:
            raise RepositoryError(
                f"index-v1 app field {field} is {app.get(field)!r}, "
                f"expected {expected_value!r}"
            )
    packages = index.get("packages")
    if not isinstance(packages, dict) or set(packages) != {PACKAGE_ID}:
        raise RepositoryError("index-v1 contains an unexpected package set")
    indexed_versions = packages[PACKAGE_ID]
    if not isinstance(indexed_versions, list) or len(indexed_versions) != len(
        EXPECTED_ABIS
    ):
        raise RepositoryError("index-v1 must contain exactly three Plezy versions")
    indexed_by_name = {
        item.get("apkName"): item
        for item in indexed_versions
        if isinstance(item, dict) and isinstance(item.get("apkName"), str)
    }
    if set(indexed_by_name) != set(expected_apks):
        raise RepositoryError("index-v1 APK names do not match the verified manifest")

    for filename, expected in expected_apks.items():
        indexed = indexed_by_name[filename]
        checks = {
            "versionCode": expected["version_code"],
            "versionName": expected["version_name"],
            "hash": expected["sha256"],
            "hashType": "sha256",
            "nativecode": [expected["abi"]],
        }
        for field, expected_value in checks.items():
            actual_value = indexed.get(field)
            if field == "hash" and isinstance(actual_value, str):
                actual_value = actual_value.lower()
            if actual_value != expected_value:
                raise RepositoryError(
                    f"{filename} index field {field} is {actual_value!r}, "
                    f"expected {expected_value!r}"
                )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fdroid-root", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--repo-fingerprint", required=True)
    parser.add_argument("--jarsigner", required=True)
    parser.add_argument("--keytool", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        validate_repository(args)
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        RepositoryError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("generated repository is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
