from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VALIDATE_REPOSITORY = REPOSITORY_ROOT / "scripts" / "validate_repository.py"
REPOSITORY_FINGERPRINT = "f" * 64
REPOSITORY_URL = "https://aldobarr.github.io/plezy-fdroid/fdroid/repo"
APK_SIGNER = "9" * 64
VERSION_CODES = {
    "arm64-v8a": 2121,
    "armeabi-v7a": 1121,
    "x86_64": 4121,
}


def _write_fake_java_tool(directory: Path, name: str, output: str) -> Path:
    if os.name == "nt":
        wrapper = directory / f"{name}.cmd"
        wrapper.write_text(f"@echo off\r\necho {output}\r\n", encoding="utf-8")
    else:
        wrapper = directory / name
        wrapper.write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\n", encoding="utf-8")
        wrapper.chmod(0o755)
    return wrapper


def _prepare_repository(directory: Path) -> tuple[Path, Path]:
    fdroid_root = directory / "fdroid"
    repo_dir = fdroid_root / "repo"
    repo_dir.mkdir(parents=True)
    apks = []
    index_v1_packages = []
    index_v2_versions = {}
    for abi, version_code in VERSION_CODES.items():
        filename = f"com.edde746.plezy_{version_code}.apk"
        apk_path = repo_dir / filename
        apk_path.write_bytes(f"verified-{abi}".encode())
        digest = hashlib.sha256(apk_path.read_bytes()).hexdigest()
        apk = {
            "abi": abi,
            "package_id": "com.edde746.plezy",
            "version_name": "2.9.1",
            "version_code": version_code,
            "min_sdk": 25,
            "target_sdk": 36,
            "sha256": digest,
            "signer_sha256": APK_SIGNER,
            "repo_filename": filename,
        }
        apks.append(apk)
        index_v1_packages.append(
            {
                "apkName": filename,
                "versionName": "2.9.1",
                "versionCode": version_code,
                "hash": digest,
                "hashType": "sha256",
                "nativecode": [abi],
            }
        )
        index_v2_versions[digest] = {
            "file": {
                "name": f"/{filename}",
                "sha256": digest,
                "size": apk_path.stat().st_size,
            },
            "manifest": {
                "versionCode": version_code,
                "versionName": "2.9.1",
                "nativecode": [abi],
                "usesSdk": {
                    "minSdkVersion": 25,
                    "targetSdkVersion": 36,
                },
                "signer": {"sha256": [APK_SIGNER]},
            },
            "antiFeatures": {"Tracking": {"en-US": "fixture reason"}},
        }

    manifest = {
        "schema_version": 1,
        "release": {
            "id": 12345,
            "tag": "2.9.1",
            "name": "Plezy 2.9.1",
            "url": "https://github.com/edde746/plezy/releases/tag/2.9.1",
            "published_at": "2026-07-13T12:00:00Z",
        },
        "upstream_assets": [],
        "apks": apks,
    }
    manifest_path = directory / "verified.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    index_v1 = {
        "repo": {
            "name": "Plezy",
            "address": REPOSITORY_URL,
            "maxage": 14,
        },
        "apps": [
            {
                "packageName": "com.edde746.plezy",
                "allowedAPKSigningKeys": [APK_SIGNER],
                "antiFeatures": ["Tracking"],
                "categories": ["Multimedia"],
                "license": "GPL-3.0-only",
                "sourceCode": "https://github.com/edde746/plezy",
            }
        ],
        "packages": {"com.edde746.plezy": index_v1_packages},
    }
    with zipfile.ZipFile(repo_dir / "index-v1.jar", "w") as archive:
        archive.writestr("index-v1.json", json.dumps(index_v1))

    index_v2 = {
        "repo": {
            "name": "Plezy",
            "address": REPOSITORY_URL,
            "antiFeatures": {"Tracking": {"name": {"en-US": "Tracking"}}},
            "categories": {"Multimedia": {"name": {"en-US": "Multimedia"}}},
        },
        "packages": {
            "com.edde746.plezy": {
                "metadata": {
                    "preferredSigner": APK_SIGNER,
                    "categories": ["Multimedia"],
                    "license": "GPL-3.0-only",
                    "sourceCode": "https://github.com/edde746/plezy",
                },
                "versions": index_v2_versions,
            }
        },
    }
    index_v2_bytes = (
        json.dumps(index_v2, indent=2, sort_keys=True) + "\n"
    ).encode()
    (repo_dir / "index-v2.json").write_bytes(index_v2_bytes)
    entry = {
        "version": 20002,
        "maxAge": 14,
        "index": {
            "name": "/index-v2.json",
            "sha256": hashlib.sha256(index_v2_bytes).hexdigest(),
            "size": len(index_v2_bytes),
            "numPackages": 1,
        },
        "diffs": {},
    }
    with zipfile.ZipFile(repo_dir / "entry.jar", "w") as archive:
        archive.writestr("entry.json", json.dumps(entry))
    with zipfile.ZipFile(repo_dir / "index.jar", "w") as archive:
        archive.writestr("index.xml", "<fdroid />")
    return fdroid_root, manifest_path


def _run_validator(
    directory: Path,
    fdroid_root: Path,
    manifest_path: Path,
) -> subprocess.CompletedProcess[str]:
    jarsigner = _write_fake_java_tool(directory, "jarsigner", "jar verified.")
    fingerprint_output = ":".join(
        REPOSITORY_FINGERPRINT[index : index + 2].upper()
        for index in range(0, 64, 2)
    )
    keytool = _write_fake_java_tool(
        directory,
        "keytool",
        f"SHA256: {fingerprint_output}",
    )
    return subprocess.run(
        [
            sys.executable,
            str(VALIDATE_REPOSITORY),
            "--fdroid-root",
            str(fdroid_root),
            "--manifest",
            str(manifest_path),
            "--repo-fingerprint",
            REPOSITORY_FINGERPRINT,
            "--jarsigner",
            str(jarsigner),
            "--keytool",
            str(keytool),
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


class ValidateRepositoryCommandTest(unittest.TestCase):
    def test_accepts_only_the_expected_signed_indexes_and_apk_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            fdroid_root, manifest_path = _prepare_repository(temporary_path)

            result = _run_validator(
                temporary_path,
                fdroid_root,
                manifest_path,
            )

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("generated repository is valid", result.stdout)

    def test_rejects_index_v2_that_does_not_match_the_signed_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            fdroid_root, manifest_path = _prepare_repository(temporary_path)
            (fdroid_root / "repo" / "index-v2.json").write_text(
                '{"tampered": true}\n',
                encoding="utf-8",
            )

            result = _run_validator(
                temporary_path,
                fdroid_root,
                manifest_path,
            )

            self.assertNotEqual(0, result.returncode)
            self.assertIn("signed entry index field sha256", result.stderr)


if __name__ == "__main__":
    unittest.main()
