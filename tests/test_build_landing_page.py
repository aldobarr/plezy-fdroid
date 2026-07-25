from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BUILD_LANDING_PAGE = REPOSITORY_ROOT / "scripts" / "build_landing_page.py"
TEMPLATE = REPOSITORY_ROOT / "site" / "index.html.tmpl"
REPOSITORY_FINGERPRINT = "f" * 64
APK_FINGERPRINT = (
    "903b862cf5e3a0bfbad9b5e049ec3de703f83422bba9c5559a7b019716316e72"
)


class BuildLandingPageCommandTest(unittest.TestCase):
    def test_builds_self_contained_install_page_and_sanitized_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            manifest_path = temporary_path / "verified.json"
            assets_dir = temporary_path / "assets"
            output_dir = temporary_path / "public"
            assets_dir.mkdir()
            (assets_dir / "icon.png").write_bytes(b"fixture-icon")
            (assets_dir / "screenshot.png").write_bytes(b"fixture-screenshot")
            verified = {
                "schema_version": 1,
                "release": {
                    "id": 12345,
                    "tag": "2.9.1",
                    "name": "Plezy 2.9.1",
                    "url": "https://github.com/edde746/plezy/releases/tag/2.9.1",
                    "published_at": "2026-07-13T12:00:00Z",
                },
                "upstream_assets": [
                    {
                        "abi": abi,
                        "id": index,
                        "name": f"plezy-android-{abi}.tar.gz",
                        "size": 100 + index,
                        "sha256": str(index) * 64,
                    }
                    for index, abi in enumerate(
                        ("arm64-v8a", "armeabi-v7a", "x86_64"),
                        start=1,
                    )
                ],
                "apks": [
                    {
                        "abi": abi,
                        "package_id": "com.edde746.plezy",
                        "version_name": "2.9.1",
                        "version_code": version_code,
                        "min_sdk": 25,
                        "target_sdk": 36,
                        "sha256": str(index) * 64,
                        "signer_sha256": APK_FINGERPRINT,
                        "repo_filename": f"com.edde746.plezy_{version_code}.apk",
                    }
                    for index, (abi, version_code) in enumerate(
                        (
                            ("arm64-v8a", 2121),
                            ("armeabi-v7a", 1121),
                            ("x86_64", 4121),
                        ),
                        start=4,
                    )
                ],
            }
            manifest_path.write_text(json.dumps(verified), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(BUILD_LANDING_PAGE),
                    "--manifest",
                    str(manifest_path),
                    "--repo-fingerprint",
                    REPOSITORY_FINGERPRINT,
                    "--fdroidserver-version",
                    "2.4.5",
                    "--template",
                    str(TEMPLATE),
                    "--assets-dir",
                    str(assets_dir),
                    "--output-dir",
                    str(output_dir),
                    "--timestamp",
                    "2026-07-25T12:34:56Z",
                ],
                cwd=REPOSITORY_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(0, result.returncode, result.stderr)
            html = (output_dir / "index.html").read_text(encoding="utf-8")
            status = json.loads((output_dir / "status.json").read_text(encoding="utf-8"))
            add_url = (
                "https://aldobarr.github.io/plezy-fdroid/fdroid/repo"
                f"?fingerprint={REPOSITORY_FINGERPRINT.upper()}"
            )

            self.assertIn(add_url, html)
            self.assertIn("Plezy 2.9.1", html)
            self.assertIn("Tracking", html)
            self.assertIn("Both can be disabled in", html)
            self.assertNotIn("<script", html.lower())
            self.assertTrue((output_dir / "assets" / "repository-qr.svg").is_file())
            self.assertEqual(
                "2026-07-25T12:34:56Z",
                status["last_successful_deployment"],
            )
            self.assertEqual(12345, status["upstream"]["release_id"])
            self.assertEqual(REPOSITORY_FINGERPRINT, status["repository"]["fingerprint"])
            self.assertNotIn(str(temporary_path), json.dumps(status))


if __name__ == "__main__":
    unittest.main()
