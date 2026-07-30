#!/usr/bin/env python3
"""Fail closed when release version surfaces disagree."""

from __future__ import annotations

import argparse
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require_match(path: str, pattern: str, label: str) -> str:
    match = re.search(pattern, text(path), flags=re.MULTILINE)
    if match is None:
        raise SystemExit(f"missing {label} in {path}")
    return match.group(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected", help="version required by the release tag")
    args = parser.parse_args()

    cargo = tomllib.loads(text("Cargo.toml"))
    workspace_version = cargo["workspace"]["package"]["version"]
    expected = args.expected or workspace_version
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected) is None:
        raise SystemExit(f"invalid release version: {expected!r}")

    observed = {
        "Cargo.toml workspace": workspace_version,
        "nFPM default": require_match(
            "packaging/nfpm.yaml",
            r"^version:\s+\$\{SKYNET_EDR_VERSION:-([^}]+)\}$",
            "nFPM default version",
        ),
        "Hermes plugin Python": require_match(
            "integrations/hermes/skynet-edr/__init__.py",
            r'^PLUGIN_VERSION\s*=\s*"([^"]+)"$',
            "Hermes plugin version",
        ),
        "Hermes plugin manifest": require_match(
            "integrations/hermes/skynet-edr/plugin.yaml",
            r'^version:\s+"([^"]+)"$',
            "Hermes plugin manifest version",
        ),
        "dashboard manifest": json.loads(
            text("integrations/hermes/skynet-edr/dashboard/manifest.json")
        )["version"],
    }

    for crate in ("skynet-edr-cli", "skynet-edr-daemon", "skynet-edr-mcp"):
        manifest = text(f"crates/{crate}/Cargo.toml")
        for dependency in re.finditer(
            r'^skynet-edr-[a-z-]+\s*=\s*\{\s*version\s*=\s*"([^"]+)"',
            manifest,
            flags=re.MULTILINE,
        ):
            observed[f"{crate} internal dependency"] = dependency.group(1)

    lock = tomllib.loads(text("Cargo.lock"))
    for package in lock["package"]:
        if package["name"].startswith("skynet-edr-"):
            observed[f"Cargo.lock {package['name']}"] = package["version"]

    mismatches = {
        label: version for label, version in observed.items() if version != expected
    }
    if mismatches:
        details = ", ".join(
            f"{label}={version}" for label, version in sorted(mismatches.items())
        )
        raise SystemExit(f"release version mismatch; expected {expected}: {details}")

    release_note = ROOT / "docs" / "releases" / f"v{expected}.md"
    if not release_note.is_file():
        raise SystemExit(f"missing reviewed release notes: {release_note.relative_to(ROOT)}")

    required_docs = {
        "README.md": f"docs/releases/v{expected}.md",
        "docs/ROADMAP.md": f"Current milestone: v{expected}",
        "docs/INSTALL.md": f"skynet-edr_{expected}_amd64.deb",
        "CHANGELOG.md": f"## {expected} -",
    }
    for path, marker in required_docs.items():
        if marker not in text(path):
            raise SystemExit(f"{path} does not reference current release {expected}")

    print(f"release version consistency passed: {expected}")


if __name__ == "__main__":
    main()
