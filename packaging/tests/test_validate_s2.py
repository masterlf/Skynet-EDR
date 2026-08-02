import os
import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "packaging/scripts/validate-s2.sh"
REPORT_HELPER = ROOT / "packaging/scripts/s2-report-dir.py"


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

    def private_temp(self):
        return tempfile.TemporaryDirectory(prefix="skynet-s2-test-", dir=Path.home())

    def helper(self, *args, env=None):
        return subprocess.run(
            ["python3", str(REPORT_HELPER), *map(str, args)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )

    def test_report_helper_rejects_existing_symlink_and_writable_parent(self):
        with self.private_temp() as temp:
            root = Path(temp)
            target = root / "target"
            target.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            self.assertNotEqual(self.helper("prepare", link).returncode, 0)
            writable = root / "writable"
            writable.mkdir(mode=0o777)
            writable.chmod(0o777)
            self.assertNotEqual(self.helper("prepare", writable / "report").returncode, 0)

    def test_timing_parser_uses_numeric_record_after_failed_command(self):
        with self.private_temp() as temp:
            timing = Path(temp) / "failed-gate.time"
            timing.write_text(
                "Command exited with non-zero status 7\n0.03\t0.01\t0.02\t1234\n",
                encoding="utf-8",
            )
            parsed = self.helper("parse-timing", timing)
            self.assertEqual(parsed.returncode, 0, parsed.stderr)
            self.assertEqual(parsed.stdout, "0.03\t0.01\t0.02\t1234\n")
            self.assertIn('rc=$?', SCRIPT.read_text(encoding="utf-8"))
            self.assertIn('"$HELPER" parse-timing "$timing"', SCRIPT.read_text(encoding="utf-8"))

    def test_report_helper_detects_stage_identity_swap_without_touching_substitute(self):
        with self.private_temp() as temp:
            output = Path(temp) / "report"
            prepared = self.helper("prepare", output)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            token = json.loads(prepared.stdout)
            stage = Path(token["stage"])
            stage.rmdir()
            stage.mkdir(mode=0o700)
            sentinel = stage / "substitute"
            sentinel.write_text("untouched", encoding="utf-8")
            published = self.helper("publish", output, json.dumps(token))
            self.assertNotEqual(published.returncode, 0)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")
            self.assertFalse(output.exists())

    def run_retained_fd_race(self, swap_after_first_write):
        with self.private_temp() as temp:
            root = Path(temp)
            output = root / "report"
            probe = root / "probe.py"
            probe.write_text(
                "import json, os, pathlib, subprocess, sys\n"
                "root=pathlib.Path(sys.argv[1]); helper=sys.argv[2]\n"
                "token=json.loads(os.environ['S2_REPORT_TOKEN'])\n"
                "stage=pathlib.Path(token['stage']); retained=pathlib.Path(os.environ['S2_REPORT_STAGE'])\n"
                "if sys.argv[3]=='mid': (retained/'before').write_text('original')\n"
                "stage.rename(root/'detached'); substitute=root/'substitute'; substitute.mkdir(mode=0o700); (substitute/'sentinel').write_text('untouched'); stage.symlink_to(substitute, target_is_directory=True)\n"
                "(retained/'after').write_text('original')\n"
                "result=subprocess.run(['python3',helper,'publish-fd',str(root/'report'),os.environ['S2_REPORT_TOKEN']],text=True,capture_output=True)\n"
                "assert result.returncode != 0\n"
                "assert (substitute/'sentinel').read_text() == 'untouched'\n"
                "assert sorted(p.name for p in substitute.iterdir()) == ['sentinel']\n",
                encoding="utf-8",
            )
            phase = "mid" if swap_after_first_write else "before"
            result = self.helper("exec", output, "python3", probe, root, REPORT_HELPER, phase)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(output.exists())

    def test_retained_stage_descriptor_blocks_swap_before_first_write(self):
        self.run_retained_fd_race(False)

    def test_retained_stage_descriptor_blocks_swap_mid_run(self):
        self.run_retained_fd_race(True)

    def run_retained_parent_race(self, swap_after_first_write):
        with self.private_temp() as temp:
            base = Path(temp)
            parent = base / "parent"
            parent.mkdir(mode=0o700)
            output = parent / "report"
            probe = base / "parent_probe.py"
            probe.write_text(
                "import json, os, pathlib, subprocess, sys\n"
                "parent=pathlib.Path(sys.argv[1]); helper=sys.argv[2]\n"
                "retained=pathlib.Path(os.environ['S2_REPORT_STAGE'])\n"
                "if sys.argv[3]=='mid': (retained/'before').write_text('original')\n"
                "parent.rename(parent.with_name('detached-parent')); parent.mkdir(mode=0o700); (parent/'sentinel').write_text('untouched')\n"
                "(retained/'after').write_text('original')\n"
                "result=subprocess.run(['python3',helper,'publish-fd',str(parent/'report'),os.environ['S2_REPORT_TOKEN']],text=True,capture_output=True)\n"
                "assert result.returncode != 0 or (parent.with_name('detached-parent')/'report').is_dir()\n"
                "assert sorted(p.name for p in parent.iterdir()) == ['sentinel']\n",
                encoding="utf-8",
            )
            phase = "mid" if swap_after_first_write else "before"
            result = self.helper("exec", output, "python3", probe, parent, REPORT_HELPER, phase)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((parent / "sentinel").read_text(encoding="utf-8"), "untouched")
            self.assertFalse(output.exists())

    def test_retained_descriptors_do_not_touch_swapped_ancestor_before_first_write(self):
        self.run_retained_parent_race(False)

    def test_retained_descriptors_do_not_touch_swapped_ancestor_mid_run(self):
        self.run_retained_parent_race(True)

    def test_report_seal_fails_closed_on_environment_secret_and_hostile_diagnostic(self):
        with self.private_temp() as temp:
            report = Path(temp) / "stage"
            (report / "logs").mkdir(parents=True, mode=0o700)
            environment_marker = "FAKE_ENV_SECRET_S2_DO_NOT_UPLOAD"
            diagnostic_marker = "HOSTILE_GATE_DIAGNOSTIC_S2_DO_NOT_UPLOAD"
            (report / "manifest.json").write_text("{}\n", encoding="utf-8")
            (report / "summary.json").write_text("{}\n", encoding="utf-8")
            (report / "metrics.tsv").write_text("gate\tstatus\nfixture\tpass\n", encoding="utf-8")
            gates = (
                "docs", "packaging", "fmt", "clippy", "rust-workspace", "hermes-python",
                "producer-corpus", "dashboard-node", "desktop-node", "corpus", "runtime-canary",
            )
            for gate in gates:
                (report / "logs" / f"{gate}.log").write_text(
                    f"gate={gate} status=pass test_count=0\n", encoding="utf-8"
                )
            env = os.environ | {
                "S2_VALIDATION_FAKE_SECRET": environment_marker,
                "S2_VALIDATION_HOSTILE_DIAGNOSTIC": diagnostic_marker,
            }
            sealed = self.helper("seal", report, env=env)
            self.assertEqual(sealed.returncode, 0, sealed.stderr)
            for path in report.rglob("*"):
                if path.is_file():
                    contents = path.read_text(encoding="utf-8")
                    self.assertNotIn(environment_marker, contents)
                    self.assertNotIn(diagnostic_marker, contents)
            self.assertFalse((report / ".completed").exists())

            (report / "SHA256SUMS").unlink()
            forbidden_probe = "".join(("S2_FAKE_", "HONEYTOKEN_EXFIL_7Q9X"))
            (report / "metrics.tsv").write_text(
                f"gate\tstatus\n{forbidden_probe}\tfail\n", encoding="utf-8"
            )
            rejected = self.helper("seal", report, env=env)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse((report / "SHA256SUMS").exists())


if __name__ == "__main__":
    unittest.main()
