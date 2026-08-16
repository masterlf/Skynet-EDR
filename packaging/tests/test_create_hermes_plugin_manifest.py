#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "packaging/scripts/create-hermes-plugin-manifest.py"
FILES = (
    "plugin.yaml",
    "__init__.py",
    "README.md",
    "dashboard/manifest.json",
    "dashboard/plugin.js",
    "dashboard/plugin_api.py",
    "desktop/plugin.js",
)


class HermesPluginManifestTests(unittest.TestCase):
    def test_manifest_uses_explicit_release_payload_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            destination = base / "manifest.json"
            for relative in FILES:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"safe\n")
                path.chmod(0o644)

            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(source), str(destination), "0.7.0-alpha.2"],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(destination.read_text(encoding="ascii"))["payload_version"],
                "0.7.0-alpha.2",
            )

    def test_manifest_rejects_missing_or_malformed_payload_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            destination = base / "manifest.json"
            for relative in FILES:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"safe\n")
                path.chmod(0o644)

            for arguments in (
                [str(source), str(destination)],
                [str(source), str(destination), "0.7.0-alpha.2\nINJECTED"],
            ):
                with self.subTest(arguments=arguments):
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT), *arguments],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
