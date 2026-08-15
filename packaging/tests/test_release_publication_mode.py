from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODE_SCRIPT = ROOT / "packaging" / "scripts" / "release-publication-mode.py"
WORKFLOW = ROOT / ".github" / "workflows" / "packaging-release.yml"


class ReleasePublicationModeTests(unittest.TestCase):
    def publication_mode(self, version: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(MODE_SCRIPT), version],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_stable_version_omits_prerelease_flag(self) -> None:
        result = self.publication_mode("0.6.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "stable\n")

    def test_prerelease_version_requires_prerelease_flag(self) -> None:
        result = self.publication_mode("0.6.0-rc.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "prerelease\n")

    def test_noncanonical_version_fails_closed(self) -> None:
        result = self.publication_mode("v0.6.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_workflow_binds_publication_flag_to_checked_product_identity(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            'publication_mode=$(python3 packaging/scripts/release-publication-mode.py "${SKYNET_EDR_PRODUCT_VERSION}")',
            workflow,
        )
        self.assertIn('if [ "$publication_mode" = "prerelease" ]; then', workflow)
        self.assertIn('release_flags+=(--prerelease)', workflow)
        self.assertIn('"${release_flags[@]}"', workflow)
        self.assertNotIn("            --prerelease \\\n", workflow)


if __name__ == "__main__":
    unittest.main()