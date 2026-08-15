#!/usr/bin/env python3
"""Classify a canonical release SemVer for GitHub publication."""

from __future__ import annotations

import re
import sys


NUMERIC_IDENTIFIER = r"(?:0|[1-9][0-9]*)"
PRERELEASE_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
VERSION_PATTERN = re.compile(
    rf"{NUMERIC_IDENTIFIER}\."
    rf"{NUMERIC_IDENTIFIER}\."
    rf"{NUMERIC_IDENTIFIER}"
    rf"(?P<prerelease>-{PRERELEASE_IDENTIFIER}(?:\.{PRERELEASE_IDENTIFIER})*)?"
)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: release-publication-mode.py PRODUCT_VERSION")
    match = VERSION_PATTERN.fullmatch(sys.argv[1])
    if match is None:
        raise SystemExit("invalid canonical product version")
    print("prerelease" if match.group("prerelease") else "stable")


if __name__ == "__main__":
    main()
