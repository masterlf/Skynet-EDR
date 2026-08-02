import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "packaging/scripts/validate-s2.sh"


class ValidateS2Tests(unittest.TestCase):
    def run_script(self, *args):
        return subprocess.run([str(SCRIPT), *args], cwd=ROOT, text=True, capture_output=True, check=False)

    def test_validator_is_executable_and_declares_all_required_gates(self):
        self.assertTrue(SCRIPT.is_file())
        self.assertTrue(SCRIPT.stat().st_mode & stat.S_IXUSR)
        text = SCRIPT.read_text(encoding="utf-8")
        for gate in (
            "check-docs.py",
            "validate-packaging.sh",
            "cargo fmt --all -- --check",
            "cargo clippy --workspace --all-targets --all-features --offline -- -D warnings",
            "cargo test --workspace --all-features --offline",
            "test_detection_corpus.py",
            "s2_runtime_canary",
            "dashboard/plugin.test.mjs",
            "desktop/plugin.test.mjs",
        ):
            self.assertIn(gate, text)
        self.assertIn("umask 077", text)
        self.assertIn("CARGO_NET_OFFLINE=true", text)

    def test_rejects_symlink_output_without_running_gates(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "target"
            target.mkdir()
            link = Path(temp) / "link"
            link.symlink_to(target, target_is_directory=True)
            result = self.run_script("--output", str(link))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe output", result.stderr)
            self.assertEqual(list(target.iterdir()), [])

    def test_rejects_sensitive_or_relative_output_paths(self):
        for path in ("relative-report", "/etc/skynet-s2", "/root/.ssh/skynet-s2"):
            with self.subTest(path=path):
                result = self.run_script("--output", path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unsafe output", result.stderr)


if __name__ == "__main__":
    unittest.main()
