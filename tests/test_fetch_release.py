from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FETCH_RELEASE = REPOSITORY_ROOT / "scripts" / "fetch_release.py"
ARCHIVES = {
    "arm64-v8a": "plezy-android-arm64-v8a.tar.gz",
    "armeabi-v7a": "plezy-android-armeabi-v7a.tar.gz",
    "x86_64": "plezy-android-x86_64.tar.gz",
}


class FetchReleaseCommandTest(unittest.TestCase):
    def test_downloads_digest_pinned_apks_from_a_stable_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            assets = []
            expected_apks: dict[str, bytes] = {}

            for asset_id, (abi, archive_name) in enumerate(ARCHIVES.items(), start=10):
                apk_bytes = f"fixture-apk-for-{abi}".encode()
                expected_apks[abi] = apk_bytes
                archive_path = temporary_path / archive_name
                with tarfile.open(archive_path, "w:gz") as archive:
                    member = tarfile.TarInfo("plezy.apk")
                    member.size = len(apk_bytes)
                    archive.addfile(member, io.BytesIO(apk_bytes))

                archive_bytes = archive_path.read_bytes()
                assets.append(
                    {
                        "id": asset_id,
                        "name": archive_name,
                        "size": len(archive_bytes),
                        "digest": f"sha256:{hashlib.sha256(archive_bytes).hexdigest()}",
                        "browser_download_url": archive_path.as_uri(),
                    }
                )

            release_metadata = {
                "id": 12345,
                "tag_name": "2.9.1",
                "name": "Plezy 2.9.1",
                "draft": False,
                "prerelease": False,
                "published_at": "2026-07-13T12:00:00Z",
                "html_url": "https://github.com/edde746/plezy/releases/tag/2.9.1",
                "assets": assets,
            }
            metadata_path = temporary_path / "release.json"
            metadata_path.write_text(json.dumps(release_metadata), encoding="utf-8")
            output_path = temporary_path / "output"

            result = subprocess.run(
                [
                    sys.executable,
                    str(FETCH_RELEASE),
                    "--release-metadata",
                    str(metadata_path),
                    "--output-dir",
                    str(output_path),
                    "--allow-local-assets",
                ],
                cwd=REPOSITORY_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(0, result.returncode, result.stderr)
            manifest = json.loads((output_path / "release.json").read_text(encoding="utf-8"))
            self.assertTrue(manifest["publish"])
            self.assertEqual("new-release", manifest["reason"])
            self.assertEqual(12345, manifest["release"]["id"])
            self.assertEqual("2.9.1", manifest["release"]["tag"])
            self.assertEqual(set(ARCHIVES), {asset["abi"] for asset in manifest["assets"]})

            for asset in manifest["assets"]:
                apk_path = output_path / asset["apk_path"]
                self.assertEqual(expected_apks[asset["abi"]], apk_path.read_bytes())
                self.assertEqual(
                    hashlib.sha256(expected_apks[asset["abi"]]).hexdigest(),
                    asset["apk_sha256"],
                )

    def test_skips_download_when_the_published_release_is_still_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            assets = [
                {
                    "id": asset_id,
                    "name": archive_name,
                    "size": 100 + asset_id,
                    "digest": f"sha256:{str(asset_id) * 64}"[:71],
                    "browser_download_url": "https://github.com/should-not-be-downloaded",
                }
                for asset_id, archive_name in enumerate(ARCHIVES.values(), start=1)
            ]
            release_metadata = {
                "id": 12345,
                "tag_name": "2.9.1",
                "name": "Plezy 2.9.1",
                "draft": False,
                "prerelease": False,
                "published_at": "2026-07-13T12:00:00Z",
                "html_url": "https://github.com/edde746/plezy/releases/tag/2.9.1",
                "assets": assets,
            }
            published_state = {
                "schema_version": 1,
                "last_successful_deployment": "2026-07-24T12:00:00Z",
                "upstream": {
                    "release_id": 12345,
                    "tag": "2.9.1",
                    "assets": [
                        {
                            "id": asset["id"],
                            "name": asset["name"],
                            "size": asset["size"],
                            "sha256": str(asset["digest"]).removeprefix("sha256:"),
                        }
                        for asset in assets
                    ],
                },
                "apks": [
                    {
                        "abi": abi,
                        "version_code": 1000 + index,
                        "sha256": str(index) * 64,
                    }
                    for index, abi in enumerate(ARCHIVES, start=1)
                ],
            }
            metadata_path = temporary_path / "release.json"
            state_path = temporary_path / "status.json"
            metadata_path.write_text(json.dumps(release_metadata), encoding="utf-8")
            state_path.write_text(json.dumps(published_state), encoding="utf-8")
            output_path = temporary_path / "output"

            result = subprocess.run(
                [
                    sys.executable,
                    str(FETCH_RELEASE),
                    "--release-metadata",
                    str(metadata_path),
                    "--published-state",
                    str(state_path),
                    "--output-dir",
                    str(output_path),
                    "--now",
                    "2026-07-25T12:00:00Z",
                    "--refresh-after-days",
                    "7",
                ],
                cwd=REPOSITORY_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(0, result.returncode, result.stderr)
            manifest = json.loads((output_path / "release.json").read_text(encoding="utf-8"))
            self.assertFalse(manifest["publish"])
            self.assertEqual("current-release-is-fresh", manifest["reason"])
            self.assertFalse((output_path / "apks").exists())


if __name__ == "__main__":
    unittest.main()
