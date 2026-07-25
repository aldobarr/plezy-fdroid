from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VERIFY_RELEASE = REPOSITORY_ROOT / "scripts" / "verify_release.py"
APK_SIGNER_SHA256 = (
    "903b862cf5e3a0bfbad9b5e049ec3de703f83422bba9c5559a7b019716316e72"
)
VERSION_CODES = {
    "arm64-v8a": 2121,
    "armeabi-v7a": 1121,
    "x86_64": 4121,
}


def _write_fake_android_tools(
    directory: Path,
    version_codes: dict[str, int] | None = None,
) -> tuple[Path, Path]:
    tool_version_codes = version_codes or VERSION_CODES
    tool = directory / "fake_android_tool.py"
    tool.write_text(
        f"""
from pathlib import Path
import sys

mode = sys.argv[1]
apk = Path(sys.argv[-1])
abi = apk.stem
codes = {tool_version_codes!r}
if mode == "aapt2":
    print("package: name='com.edde746.plezy' versionCode='%s' versionName='2.9.1'" % codes[abi])
    print("sdkVersion:'25'")
    print("targetSdkVersion:'36'")
    print("native-code: '%s'" % abi)
elif mode == "apksigner":
    print("Verifies")
    print("Verified using v1 scheme (JAR signing): true")
    print("Verified using v2 scheme (APK Signature Scheme v2): true")
    print("Verified using v3 scheme (APK Signature Scheme v3): false")
    print("Signer #1 certificate SHA-256 digest: {APK_SIGNER_SHA256}")
else:
    raise SystemExit("unexpected mode")
""".lstrip(),
        encoding="utf-8",
    )

    wrappers = []
    for mode in ("aapt2", "apksigner"):
        if os.name == "nt":
            wrapper = directory / f"{mode}.cmd"
            wrapper.write_text(
                f'@echo off\r\n"{sys.executable}" "{tool}" {mode} %*\r\n',
                encoding="utf-8",
            )
        else:
            wrapper = directory / mode
            wrapper.write_text(
                f'#!/bin/sh\nexec "{sys.executable}" "{tool}" {mode} "$@"\n',
                encoding="utf-8",
            )
            wrapper.chmod(0o755)
        wrappers.append(wrapper)
    return wrappers[0], wrappers[1]


class VerifyReleaseCommandTest(unittest.TestCase):
    def test_accepts_the_complete_expected_upstream_signed_apk_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            release_dir = temporary_path / "release"
            apk_dir = release_dir / "apks"
            apk_dir.mkdir(parents=True)
            assets = []
            for abi, version_code in VERSION_CODES.items():
                apk_path = apk_dir / f"{abi}.apk"
                apk_path.write_bytes(f"signed-apk-{abi}".encode())
                assets.append(
                    {
                        "abi": abi,
                        "id": version_code,
                        "name": f"plezy-android-{abi}.tar.gz",
                        "size": 123,
                        "sha256": "a" * 64,
                        "apk_path": apk_path.relative_to(release_dir).as_posix(),
                        "apk_sha256": hashlib.sha256(apk_path.read_bytes()).hexdigest(),
                    }
                )

            manifest = {
                "schema_version": 1,
                "publish": True,
                "reason": "new-release",
                "release": {
                    "id": 12345,
                    "tag": "2.9.1",
                    "name": "Plezy 2.9.1",
                    "url": "https://github.com/edde746/plezy/releases/tag/2.9.1",
                    "published_at": "2026-07-13T12:00:00Z",
                },
                "assets": assets,
            }
            manifest_path = release_dir / "release.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            aapt2, apksigner = _write_fake_android_tools(temporary_path)
            verified_path = temporary_path / "verified.json"
            repo_dir = temporary_path / "fdroid" / "repo"

            result = subprocess.run(
                [
                    sys.executable,
                    str(VERIFY_RELEASE),
                    "--manifest",
                    str(manifest_path),
                    "--output-manifest",
                    str(verified_path),
                    "--repo-dir",
                    str(repo_dir),
                    "--aapt2",
                    str(aapt2),
                    "--apksigner",
                    str(apksigner),
                ],
                cwd=REPOSITORY_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(0, result.returncode, result.stderr)
            verified = json.loads(verified_path.read_text(encoding="utf-8"))
            self.assertEqual(
                VERSION_CODES,
                {item["abi"]: item["version_code"] for item in verified["apks"]},
            )
            self.assertEqual(
                {f"com.edde746.plezy_{code}.apk" for code in VERSION_CODES.values()},
                {path.name for path in repo_dir.glob("*.apk")},
            )
            self.assertTrue(
                all(item["signer_sha256"] == APK_SIGNER_SHA256 for item in verified["apks"])
            )

    def test_rejects_a_new_release_with_non_advancing_abi_version_codes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            release_dir = temporary_path / "release"
            apk_dir = release_dir / "apks"
            apk_dir.mkdir(parents=True)
            assets = []
            previous_apks = []
            for abi, version_code in VERSION_CODES.items():
                apk_path = apk_dir / f"{abi}.apk"
                apk_path.write_bytes(f"signed-apk-{abi}".encode())
                assets.append(
                    {
                        "abi": abi,
                        "id": version_code,
                        "name": f"plezy-android-{abi}.tar.gz",
                        "size": 123,
                        "sha256": "a" * 64,
                        "apk_path": apk_path.relative_to(release_dir).as_posix(),
                        "apk_sha256": hashlib.sha256(apk_path.read_bytes()).hexdigest(),
                    }
                )
                previous_apks.append(
                    {
                        "abi": abi,
                        "version_code": version_code,
                        "sha256": "b" * 64,
                    }
                )

            manifest = {
                "schema_version": 1,
                "publish": True,
                "reason": "new-release",
                "release": {
                    "id": 12345,
                    "tag": "2.9.1",
                    "name": "Plezy 2.9.1",
                    "url": "https://github.com/edde746/plezy/releases/tag/2.9.1",
                    "published_at": "2026-07-13T12:00:00Z",
                },
                "assets": assets,
                "previous_publication": {
                    "release_id": 12000,
                    "tag": "2.8.0",
                    "apks": previous_apks,
                },
            }
            manifest_path = release_dir / "release.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            aapt2, apksigner = _write_fake_android_tools(temporary_path)
            repo_dir = temporary_path / "fdroid" / "repo"

            result = subprocess.run(
                [
                    sys.executable,
                    str(VERIFY_RELEASE),
                    "--manifest",
                    str(manifest_path),
                    "--output-manifest",
                    str(temporary_path / "verified.json"),
                    "--repo-dir",
                    str(repo_dir),
                    "--aapt2",
                    str(aapt2),
                    "--apksigner",
                    str(apksigner),
                ],
                cwd=REPOSITORY_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(0, result.returncode)
            self.assertIn("did not advance", result.stderr)
            self.assertFalse(repo_dir.exists())

    def test_rejects_a_non_positive_version_code_before_populating_repo(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            release_dir = temporary_path / "release"
            apk_dir = release_dir / "apks"
            apk_dir.mkdir(parents=True)
            invalid_codes = {**VERSION_CODES, "arm64-v8a": 0}
            assets = []
            for asset_id, abi in enumerate(invalid_codes, start=1):
                apk_path = apk_dir / f"{abi}.apk"
                apk_path.write_bytes(f"signed-apk-{abi}".encode())
                assets.append(
                    {
                        "abi": abi,
                        "id": asset_id,
                        "name": f"plezy-android-{abi}.tar.gz",
                        "size": 123,
                        "sha256": "a" * 64,
                        "apk_path": apk_path.relative_to(release_dir).as_posix(),
                        "apk_sha256": hashlib.sha256(apk_path.read_bytes()).hexdigest(),
                    }
                )

            manifest_path = release_dir / "release.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "publish": True,
                        "reason": "new-release",
                        "release": {
                            "id": 12345,
                            "tag": "2.9.1",
                            "name": "Plezy 2.9.1",
                            "url": (
                                "https://github.com/edde746/plezy/releases/tag/2.9.1"
                            ),
                            "published_at": "2026-07-13T12:00:00Z",
                        },
                        "assets": assets,
                    }
                ),
                encoding="utf-8",
            )
            aapt2, apksigner = _write_fake_android_tools(
                temporary_path,
                invalid_codes,
            )
            repo_dir = temporary_path / "fdroid" / "repo"

            result = subprocess.run(
                [
                    sys.executable,
                    str(VERIFY_RELEASE),
                    "--manifest",
                    str(manifest_path),
                    "--output-manifest",
                    str(temporary_path / "verified.json"),
                    "--repo-dir",
                    str(repo_dir),
                    "--aapt2",
                    str(aapt2),
                    "--apksigner",
                    str(apksigner),
                ],
                cwd=REPOSITORY_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(0, result.returncode)
            self.assertIn("version code must be positive", result.stderr)
            self.assertFalse(repo_dir.exists())


if __name__ == "__main__":
    unittest.main()
