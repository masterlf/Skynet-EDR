#!/usr/bin/env python3
"""Fail-closed policy for listing a DEB payload without extracting it."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import PurePosixPath

ALLOWED_ROOTS = (
    "etc/skynet-edr",
    "usr/bin",
    "usr/lib/systemd/system",
    "usr/lib/sysusers.d",
    "usr/lib/tmpfiles.d",
    "usr/libexec/skynet-edr",
    "usr/share/doc/skynet-edr",
    "usr/share/licenses/skynet-edr",
    "usr/share/skynet-edr",
    "var/cache/skynet-edr",
    "var/lib/skynet-edr",
    "var/lib/skynet-edr-hermes-enrollment",
    "var/log/skynet-edr",
)
ALLOWED_ANCESTORS = {
    "etc",
    "usr",
    "usr/lib",
    "usr/lib/systemd",
    "usr/libexec",
    "usr/share",
    "usr/share/doc",
    "usr/share/licenses",
    "var",
    "var/cache",
    "var/lib",
    "var/log",
}
RECORD = re.compile(
    r"^(?P<mode>[bcdlps-][rwxStTs-]{9})\s+"
    r"(?P<owner>[^\s/]+)/(?P<group>\S+)\s+"
    r"(?P<size>\d+)\s+(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2})\s+(?P<path>.+)$"
)


def _is_allowed(path: str) -> bool:
    if path in (".", ""):
        return True
    return path in ALLOWED_ANCESTORS or any(
        path == root or path.startswith(root + "/") for root in ALLOWED_ROOTS
    )


def _expected_identity(path: str) -> tuple[str, str]:
    if path == "etc/skynet-edr" or path.startswith("etc/skynet-edr/"):
        return "root", "skynet-edr"
    for state_root in ("var/cache/skynet-edr", "var/lib/skynet-edr", "var/log/skynet-edr"):
        if path == state_root or path.startswith(state_root + "/"):
            return "skynet-edr", "skynet-edr"
    return "root", "root"


def validate_deb_listing(text: str) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    lines = text.splitlines()
    if not lines:
        return ["listing is empty"]
    for number, line in enumerate(lines, 1):
        match = RECORD.fullmatch(line)
        if match is None:
            errors.append(f"line {number}: ambiguous listing record")
            continue
        mode = match.group("mode")
        owner = match.group("owner")
        group = match.group("group")
        raw_path = match.group("path")
        if " -> " in raw_path or mode[0] == "l":
            errors.append(f"line {number}: links are not permitted")
            continue
        if mode[0] not in ("-", "d"):
            errors.append(f"line {number}: special file type {mode[0]!r} is not permitted")

        if any(bit in mode for bit in "sStT"):
            errors.append(f"line {number}: setuid/setgid/sticky mode is not permitted")
        if mode[8] == "w":
            errors.append(f"line {number}: world-writable payload is not permitted")
        if raw_path.startswith("/") or not raw_path.startswith("./"):
            errors.append(f"line {number}: path must be relative and start with ./")
            continue
        relative = raw_path[2:].rstrip("/")
        parts = PurePosixPath(relative).parts
        if any(part in ("", ".", "..") for part in parts):
            errors.append(f"line {number}: path contains an unsafe component")
            continue
        normalized = "/".join(parts)
        if not _is_allowed(normalized):
            errors.append(f"line {number}: unexpected payload path {raw_path!r}")
        expected_owner, expected_group = _expected_identity(normalized)
        if owner != expected_owner or group != expected_group:
            errors.append(
                f"line {number}: expected payload owner "
                f"{expected_owner}:{expected_group}, observed {owner}:{group}"
            )
        if normalized in seen:
            errors.append(f"line {number}: duplicate normalized path {normalized!r}")
        seen.add(normalized)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("deb",), required=True)
    parser.add_argument("listing")
    args = parser.parse_args()
    try:
        text = open(args.listing, encoding="utf-8", errors="strict").read()
    except (OSError, UnicodeError) as error:
        print(f"could not read listing: {error}", file=sys.stderr)
        return 2
    errors = validate_deb_listing(text)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print("DEB listing policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
