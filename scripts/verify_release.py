#!/usr/bin/env python3
"""Verify Plezy APK identity and signatures before populating an F-Droid repo."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

PACKAGE_ID = "com.edde746.plezy"
EXPECTED_ABIS = {"arm64-v8a", "armeabi-v7a", "x86_64"}
EXPECTED_SIGNER_SHA256 = (
    "903b862cf5e3a0bfbad9b5e049ec3de703f83422bba9c5559a7b019716316e72"
)


class VerificationError(RuntimeError):
    """Raised when a candidate APK set violates the publication contract."""


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
        check=False,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        output = "\n".join(part for part in (result.stdout, result.stderr) if part)
        raise VerificationError(
            f"{Path(executable).name} rejected the APK (exit {result.returncode}): {output}"
        )
    return "\n".join(part for part in (result.stdout, result.stderr) if part)


def _parse_badging(output: str) -> dict[str, Any]:
    package_line = next(
        (line for line in output.splitlines() if line.startswith("package: ")),
        None,
    )
    if package_line is None:
        raise VerificationError("aapt2 returned no package identity")
    attributes = dict(re.findall(r"(\w+)='([^']*)'", package_line))
    try:
        version_code = int(attributes["versionCode"])
    except (KeyError, ValueError) as error:
        raise VerificationError("aapt2 returned no valid version code") from error

    def quoted_value(prefix: str) -> str | None:
        match = re.search(rf"^{re.escape(prefix)}:'([^']+)'$", output, re.MULTILINE)
        return match.group(1) if match else None

    native_match = re.search(r"^native-code:(.*)$", output, re.MULTILINE)
    native_codes = (
        re.findall(r"'([^']+)'", native_match.group(1)) if native_match else []
    )
    min_sdk = quoted_value("minSdkVersion") or quoted_value("sdkVersion")

    return {
        "package_id": attributes.get("name"),
        "version_code": version_code,
        "version_name": attributes.get("versionName"),
        "min_sdk": int(min_sdk) if min_sdk else None,
        "target_sdk": (
            int(value) if (value := quoted_value("targetSdkVersion")) else None
        ),
        "native_codes": native_codes,
    }


def _parse_signer(output: str) -> str:
    signer_values = {
        match.replace(":", "").lower()
        for match in re.findall(
            r"Signer #\d+ certificate SHA-256 digest:\s*([0-9A-Fa-f:]{64,95})",
            output,
        )
    }
    if len(signer_values) != 1:
        raise VerificationError("APK must have exactly one SHA-256 signer identity")
    if not re.search(
        r"Verified using v(?:2|3)(?:\.\d+)? scheme .*:\s*true",
        output,
    ):
        raise VerificationError("APK must verify with Android signature scheme v2 or v3")
    return signer_values.pop()


def _normalized_release_version(tag: str) -> str:
    return tag[1:] if tag.startswith(("v", "V")) else tag


def verify_release(args: argparse.Namespace) -> dict[str, Any]:
    manifest_path = Path(args.manifest).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("publish") is not True:
        raise VerificationError("release manifest is not a publishable candidate")
    release = manifest.get("release")
    assets = manifest.get("assets")
    if not isinstance(release, dict) or not isinstance(assets, list):
        raise VerificationError("release manifest is incomplete")
    tag = release.get("tag")
    if not isinstance(tag, str) or not tag:
        raise VerificationError("release tag is missing")

    assets_by_abi = {
        asset.get("abi"): asset
        for asset in assets
        if isinstance(asset, dict) and isinstance(asset.get("abi"), str)
    }
    if set(assets_by_abi) != EXPECTED_ABIS or len(assets) != len(EXPECTED_ABIS):
        raise VerificationError("candidate must contain exactly the three expected ABIs")

    verified_apks = []
    source_paths: dict[int, Path] = {}
    for abi in sorted(EXPECTED_ABIS):
        asset = assets_by_abi[abi]
        relative_apk_path = asset.get("apk_path")
        expected_apk_hash = asset.get("apk_sha256")
        if not isinstance(relative_apk_path, str) or not isinstance(expected_apk_hash, str):
            raise VerificationError(f"{abi} asset has no extracted APK identity")
        apk_path = (manifest_path.parent / relative_apk_path).resolve()
        try:
            apk_path.relative_to(manifest_path.parent)
        except ValueError as error:
            raise VerificationError(f"{abi} APK path escapes the release workspace") from error
        if not apk_path.is_file():
            raise VerificationError(f"{abi} APK is missing")
        actual_apk_hash = _sha256(apk_path)
        if actual_apk_hash != expected_apk_hash.lower():
            raise VerificationError(f"{abi} APK hash changed after extraction")

        badging = _parse_badging(
            _run_tool(args.aapt2, ["dump", "badging", str(apk_path)])
        )
        if badging["package_id"] != PACKAGE_ID:
            raise VerificationError(
                f"{abi} package is {badging['package_id']!r}, expected {PACKAGE_ID!r}"
            )
        if badging["version_name"] != _normalized_release_version(tag):
            raise VerificationError(
                f"{abi} version name {badging['version_name']!r} does not match tag {tag!r}"
            )
        if badging["native_codes"] != [abi]:
            raise VerificationError(
                f"{abi} archive contains native code for {badging['native_codes']!r}"
            )

        signer = _parse_signer(
            _run_tool(
                args.apksigner,
                ["verify", "--verbose", "--print-certs", str(apk_path)],
            )
        )
        if signer != EXPECTED_SIGNER_SHA256:
            raise VerificationError(
                f"{abi} signer {signer} does not match the pinned upstream signer"
            )

        version_code = badging["version_code"]
        if version_code <= 0:
            raise VerificationError(f"{abi} version code must be positive")
        if version_code in source_paths:
            raise VerificationError(f"duplicate version code {version_code} across ABI APKs")
        source_paths[version_code] = apk_path
        verified_apks.append(
            {
                "abi": abi,
                "package_id": PACKAGE_ID,
                "version_name": badging["version_name"],
                "version_code": version_code,
                "min_sdk": badging["min_sdk"],
                "target_sdk": badging["target_sdk"],
                "sha256": actual_apk_hash,
                "signer_sha256": signer,
                "repo_filename": f"{PACKAGE_ID}_{version_code}.apk",
            }
        )

    previous_publication = manifest.get("previous_publication")
    if previous_publication is not None:
        if not isinstance(previous_publication, dict):
            raise VerificationError("previous publication state is invalid")
        previous_apks = previous_publication.get("apks")
        if not isinstance(previous_apks, list):
            raise VerificationError("previous publication has no APK state")
        previous_by_abi = {
            item.get("abi"): item
            for item in previous_apks
            if isinstance(item, dict) and isinstance(item.get("abi"), str)
        }
        if set(previous_by_abi) != EXPECTED_ABIS or len(previous_apks) != len(
            EXPECTED_ABIS
        ):
            raise VerificationError(
                "previous publication must describe exactly the three expected ABIs"
            )

        same_release_id = previous_publication.get("release_id") == release.get("id")
        same_release_tag = previous_publication.get("tag") == release.get("tag")
        if same_release_id != same_release_tag:
            raise VerificationError("previous publication release identity is inconsistent")
        same_release = same_release_id and same_release_tag

        for apk in verified_apks:
            previous = previous_by_abi[apk["abi"]]
            previous_version_code = previous.get("version_code")
            if not isinstance(previous_version_code, int):
                raise VerificationError(
                    f"previous {apk['abi']} version code is missing or invalid"
                )
            if same_release:
                if previous_version_code != apk["version_code"]:
                    raise VerificationError(
                        f"{apk['abi']} version code changed beneath the published release"
                    )
                if previous.get("sha256") != apk["sha256"]:
                    raise VerificationError(
                        f"{apk['abi']} APK changed beneath the published release"
                    )
            elif apk["version_code"] <= previous_version_code:
                raise VerificationError(
                    f"{apk['abi']} version code {apk['version_code']} did not advance "
                    f"past {previous_version_code}"
                )

    repo_dir = Path(args.repo_dir)
    if repo_dir.exists() and any(repo_dir.glob("*.apk")):
        raise VerificationError("repository workspace already contains APKs")
    repo_dir.mkdir(parents=True, exist_ok=True)
    for apk in verified_apks:
        shutil.copy2(
            source_paths[apk["version_code"]],
            repo_dir / apk["repo_filename"],
        )

    upstream_assets = [
        {
            "abi": asset["abi"],
            "id": asset.get("id", asset.get("asset_id")),
            "name": asset["name"],
            "size": asset["size"],
            "sha256": asset["sha256"],
        }
        for asset in assets
    ]
    return {
        "schema_version": 1,
        "release": release,
        "upstream_assets": sorted(upstream_assets, key=lambda item: item["abi"]),
        "apks": sorted(verified_apks, key=lambda item: item["abi"]),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-manifest", required=True)
    parser.add_argument("--repo-dir", required=True)
    parser.add_argument("--aapt2", required=True)
    parser.add_argument("--apksigner", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        verified = verify_release(args)
        output_path = Path(args.output_manifest)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = output_path.with_suffix(output_path.suffix + ".tmp")
        temporary_path.write_text(
            json.dumps(verified, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary_path, output_path)
    except (OSError, ValueError, VerificationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
