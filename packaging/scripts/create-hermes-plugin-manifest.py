#!/usr/bin/env python3
"""Create the deterministic package-owned Hermes payload manifest."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

ALLOWED_FILES = (
    "plugin.yaml",
    "__init__.py",
    "README.md",
    "dashboard/manifest.json",
    "dashboard/plugin.js",
    "dashboard/plugin_api.py",
    "desktop/plugin.js",
)


def main() -> int:
    if len(sys.argv) != 3:
        return 2
    source = Path(sys.argv[1])
    destination = Path(sys.argv[2])
    files: dict[str, dict[str, int | str]] = {}
    for relative in ALLOWED_FILES:
        path = source / relative
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o644:
            return 1
        data = path.read_bytes()
        files[relative] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "mode": 0o644,
            "owner": 0,
        }
    generation = hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    document = {
        "schema": 1,
        "payload_version": "0.4.1",
        "generation": generation,
        "files": files,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".manifest.", dir=destination.parent)
    try:
        os.fchmod(fd, 0o644)
        os.write(fd, json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, destination)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
