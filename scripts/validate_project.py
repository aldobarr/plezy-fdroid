#!/usr/bin/env python3
"""Validate the repository's static security and publication contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

PACKAGE_ID = "com.edde746.plezy"
APK_SIGNER_SHA256 = (
    "903b862cf5e3a0bfbad9b5e049ec3de703f83422bba9c5559a7b019716316e72"
)
REPOSITORY_URL = "https://aldobarr.github.io/plezy-fdroid/fdroid/repo"
TRACKING_DISCLOSURE = (
    "Official GitHub builds enable crash reporting by default and perform "
    "automatic update checks. Both can be disabled in Plezy settings."
)
ACTION_PIN = re.compile(r"^\s*uses:\s*[^@\s]+@([0-9a-f]{40})(?:\s+#.*)?$")


class ContractError(RuntimeError):
    """Raised when repository files diverge from the approved contract."""


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContractError(f"{path} must contain a YAML mapping")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _env_reference(config: dict[str, Any], key: str, variable: str) -> None:
    _require(
        config.get(key) == {"env": variable},
        f"config.yml {key} must reference only {variable}",
    )


def _validate_config(root: Path) -> None:
    config = _load_yaml(root / "config.yml")
    _require(config.get("repo_url") == REPOSITORY_URL, "unexpected repository URL")
    _require(config.get("repo_maxage") == 14, "repo_maxage must be 14 days")
    _require(config.get("archive_older") == 0, "only the latest release may be retained")
    _require(
        config.get("make_current_version_link") is False,
        "current-version convenience APK links must stay disabled",
    )
    _env_reference(config, "keystore", "FDROID_KEYSTORE_PATH")
    _env_reference(config, "keystorepass", "FDROID_KEYSTORE_PASSWORD")
    _env_reference(config, "keypass", "FDROID_KEY_PASSWORD")
    _env_reference(config, "repo_keyalias", "FDROID_KEY_ALIAS")
    _env_reference(config, "apksigner", "FDROID_APKSIGNER_PATH")
    serialized = json.dumps(config).lower()
    for marker in ("password1", "password2", "secret", "github_pat_"):
        _require(marker not in serialized, f"config.yml appears to contain {marker!r}")

    anti_features = _load_yaml(root / "config" / "antiFeatures.yml")
    tracking = anti_features.get("Tracking")
    _require(
        isinstance(tracking, dict)
        and tracking.get("name") == "Tracking"
        and bool(tracking.get("description")),
        "standalone repository must define the Tracking anti-feature",
    )
    categories = _load_yaml(root / "config" / "categories.yml")
    multimedia = categories.get("Multimedia")
    _require(
        isinstance(multimedia, dict)
        and multimedia.get("name") == "Multimedia"
        and bool(multimedia.get("description")),
        "standalone repository must define the Multimedia category",
    )


def _validate_metadata(root: Path) -> None:
    metadata_path = root / "metadata" / f"{PACKAGE_ID}.yml"
    metadata = _load_yaml(metadata_path)
    _require(metadata.get("License") == "GPL-3.0-only", "unexpected app license")
    _require(
        metadata.get("SourceCode") == "https://github.com/edde746/plezy",
        "metadata must link to canonical upstream source",
    )
    _require(
        metadata.get("AllowedAPKSigningKeys") == APK_SIGNER_SHA256,
        "metadata must pin the verified upstream APK signer",
    )
    anti_features = metadata.get("AntiFeatures")
    if not isinstance(anti_features, dict) or "Tracking" not in anti_features:
        raise ContractError("metadata must include the Tracking anti-feature")
    tracking = anti_features["Tracking"]
    _require(
        isinstance(tracking, dict)
        and " ".join(str(tracking.get("en-US", "")).split()) == TRACKING_DISCLOSURE,
        "metadata must contain the approved Tracking disclosure",
    )
    template = " ".join(
        (root / "site" / "index.html.tmpl").read_text(encoding="utf-8").split()
    )
    _require(
        TRACKING_DISCLOSURE in template,
        "landing page must contain the same Tracking disclosure as metadata",
    )
    for forbidden in ("Builds", "CurrentVersion", "CurrentVersionCode", "Repo", "RepoType"):
        _require(forbidden not in metadata, f"binary metadata must omit {forbidden}")

    locale = root / "metadata" / PACKAGE_ID / "en-US"
    for filename in ("title.txt", "summary.txt", "description.txt"):
        value = (locale / filename).read_text(encoding="utf-8").strip()
        _require(bool(value), f"{filename} must not be empty")
    summary = (locale / "summary.txt").read_text(encoding="utf-8").strip()
    _require(len(summary) <= 80, "localized summary exceeds 80 characters")


def _permissions(workflow: dict[str, Any], job_name: str) -> dict[str, Any]:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        raise ContractError("workflow has no jobs mapping")
    job = jobs.get(job_name)
    if not isinstance(job, dict):
        raise ContractError(f"workflow has no {job_name!r} job")
    permissions = job.get("permissions")
    if not isinstance(permissions, dict):
        raise ContractError(f"{job_name} has no explicit permissions")
    return permissions


def _validate_action_pins(path: Path) -> None:
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if re.match(r"^\s*uses:", line):
            _require(
                ACTION_PIN.match(line) is not None,
                f"{path}:{line_number} action is not pinned to a 40-character SHA",
            )


def _validate_workflows(root: Path) -> None:
    workflow_dir = root / ".github" / "workflows"
    ci_path = workflow_dir / "ci.yml"
    heartbeat_path = workflow_dir / "heartbeat.yml"
    publish_path = workflow_dir / "publish.yml"
    workflows = {
        "ci": _load_yaml(ci_path),
        "heartbeat": _load_yaml(heartbeat_path),
        "publish": _load_yaml(publish_path),
    }
    for name, workflow in workflows.items():
        _require(workflow.get("permissions") == {}, f"{name} top-level permissions must be empty")
    for path in (ci_path, heartbeat_path, publish_path):
        _validate_action_pins(path)
        _require(
            "pull_request_target:" not in path.read_text(encoding="utf-8"),
            f"{path} must not use pull_request_target",
        )

    _require(_permissions(workflows["ci"], "test") == {"contents": "read"}, "CI is overprivileged")
    _require(
        _permissions(workflows["heartbeat"], "heartbeat") == {"contents": "write"},
        "heartbeat must have only contents: write",
    )
    _require(
        _permissions(workflows["publish"], "build") == {"contents": "read"},
        "publisher build must have only contents: read",
    )
    _require(
        _permissions(workflows["publish"], "deploy")
        == {"pages": "write", "id-token": "write"},
        "deploy job permissions are incorrect",
    )
    _require(
        _permissions(workflows["publish"], "report") == {"issues": "write"},
        "failure reporter must have only issues: write",
    )

    publish_jobs = workflows["publish"]["jobs"]
    publish_build = publish_jobs["build"]
    heartbeat_job = workflows["heartbeat"]["jobs"]["heartbeat"]
    _require(
        publish_build.get("environment") == "fdroid-signing",
        "signing secrets must come from the protected fdroid-signing environment",
    )
    _require(
        publish_build.get("if")
        == "github.ref_name == github.event.repository.default_branch",
        "publisher build must reject non-default refs",
    )
    for job_name in ("deploy", "report"):
        _require(
            "secrets." not in json.dumps(publish_jobs[job_name]),
            f"{job_name} must not receive repository secrets",
        )
    _require(
        "secrets." not in json.dumps(heartbeat_job),
        "heartbeat must remain secretless",
    )
    _require(
        "secrets." in json.dumps(publish_build),
        "only the publisher build should reference signing secrets",
    )
    _require(
        "vars.FDROID_REPOSITORY_FINGERPRINT" in json.dumps(publish_build),
        "publisher must use an independently configured repository fingerprint",
    )

    publish_text = publish_path.read_text(encoding="utf-8")
    heartbeat_text = heartbeat_path.read_text(encoding="utf-8")
    _require(
        'cron: "17 1,7,13,19 * * *"' in publish_text,
        "publisher must poll four times daily at an off-peak minute",
    )
    _require(
        'cp config/*.yml "$RUNNER_TEMP/fdroid/config/"' in publish_text,
        "publisher must copy standalone category and anti-feature definitions",
    )
    _require(
        'FDROID_APKSIGNER_PATH="$ANDROID_HOME/build-tools/'
        '$ANDROID_BUILD_TOOLS_VERSION/apksigner"' in publish_text,
        "publisher must force fdroidserver to use the pinned Android build tools",
    )
    _require(
        '"$actual" != "$expected"' in publish_text,
        "publisher must compare the restored key with the configured fingerprint",
    )
    _require(
        "include-hidden-files: true" in publish_text,
        "Pages artifact must include the generated .nojekyll marker",
    )
    _require(
        "uses: actions/upload-pages-artifact@"
        "fc324d3547104276b827a68afc52ff2a11cc49c9 # v5" in publish_text,
        "Pages upload must use the pinned action version that supports hidden files",
    )
    _require(
        'cron: "41 5 * * 1"' in heartbeat_text and "inactive_days < 30" in heartbeat_text,
        "weekly heartbeat must use the 30-day inactivity threshold",
    )
    _require(
        "workflow_dispatch:" not in heartbeat_text,
        "write-enabled heartbeat must not permit manual dispatch",
    )


def _validate_assets_and_dependencies(root: Path) -> None:
    png_signature = b"\x89PNG\r\n\x1a\n"
    for filename in ("icon.png", "screenshot.png"):
        path = root / "assets" / filename
        _require(path.read_bytes().startswith(png_signature), f"{path} is not a PNG")

    requirements = [
        line.strip()
        for line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    _require(
        requirements == ["fdroidserver==2.4.5", "segno==1.6.6"],
        "runtime dependencies must stay exactly pinned",
    )
    ignore = (root / ".gitignore").read_text(encoding="utf-8")
    for pattern in ("*.apk", "*.p12", "*.jks", "*.tar.gz", "public/", "repo/"):
        _require(pattern in ignore, f".gitignore must exclude {pattern}")


def validate_project(root: Path) -> None:
    _validate_config(root)
    _validate_metadata(root)
    _validate_assets_and_dependencies(root)
    _validate_workflows(root)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        validate_project(args.root.resolve())
    except (ContractError, OSError, UnicodeError, yaml.YAMLError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("project contract is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
