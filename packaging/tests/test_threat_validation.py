import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "packaging/scripts/threat-validation.py"
MANIFEST = ROOT / "crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json"
MATRIX = ROOT / "docs/coverage/v0.6.0.json"
PUBLIC_MATRIX = ROOT / "docs/PROTECTION_MATRIX_v0.6.0.md"
NFPM = ROOT / "packaging/nfpm.yaml"
ARCHITECTURE = ROOT / "docs/ARCHITECTURE.md"
DEPLOYMENT = ROOT / "docs/DEPLOYMENT.md"
THREAT_VALIDATION_DOC = ROOT / "docs/THREAT_VALIDATION.md"


class ThreatValidationTests(unittest.TestCase):
    def run_runner(self, *args):
        return subprocess.run(
            ["python3", str(RUNNER), *map(str, args)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_validate_only_writes_deterministic_versioned_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            first = Path(temp) / "first.json"
            second = Path(temp) / "second.json"
            first_run = self.run_runner("--validate-only", "--output", first)
            second_run = self.run_runner("--validate-only", "--output", second)
            self.assertEqual(first_run.returncode, 0, first_run.stderr)
            self.assertEqual(second_run.returncode, 0, second_run.stderr)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            evidence = json.loads(first.read_text(encoding="utf-8"))
            self.assertEqual(evidence["schema_version"], "skynet.threat-validation-evidence.v1")
            self.assertEqual(evidence["suite_version"], "0.6.0")
            self.assertEqual(evidence["mode"], "validate-only")
            self.assertEqual(evidence["status"], "not_tested")
            self.assertEqual(
                evidence["manifest_sha256"], hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
            )
            self.assertEqual(
                evidence["matrix_sha256"], hashlib.sha256(MATRIX.read_bytes()).hexdigest()
            )
            self.assertEqual(
                evidence["public_matrix_sha256"],
                hashlib.sha256(PUBLIC_MATRIX.read_bytes()).hexdigest(),
            )
            self.assertEqual(
                [result["scenario_id"] for result in evidence["results"]],
                sorted(result["scenario_id"] for result in evidence["results"]),
            )
            self.assertTrue(all(result["status"] == "not_tested" for result in evidence["results"]))
            self.assertIn("NOT_TESTED", first_run.stdout)

    def test_manifest_rejects_duplicate_ids_unknown_fields_and_unknown_categories(self):
        source = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutations = []
        duplicate = json.loads(json.dumps(source))
        duplicate["cases"].append(duplicate["cases"][0])
        mutations.append(duplicate)
        unknown = json.loads(json.dumps(source))
        unknown["cases"][0]["unexpected"] = True
        mutations.append(unknown)
        category = json.loads(json.dumps(source))
        category["cases"][0]["category"] = "mystery"
        mutations.append(category)
        with tempfile.TemporaryDirectory() as temp:
            for index, manifest in enumerate(mutations):
                path = Path(temp) / f"invalid-{index}.json"
                path.write_text(json.dumps(manifest), encoding="utf-8")
                result = self.run_runner(
                    "--validate-only", "--manifest", path, "--matrix", MATRIX
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_custom_manifest_cannot_claim_executed_pass(self):
        source = json.loads(MANIFEST.read_text(encoding="utf-8"))
        malicious = next(case for case in source["cases"] if case["case_id"] == "malicious_mcp")
        malicious.update({
            "category": "benign",
            "events": [],
            "expected_incident_count": 0,
            "expected_match": False,
            "expected_outcome": "not_detected",
            "producer_calls": [],
        })
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "mutated.json"
            output = Path(temp) / "evidence.json"
            manifest.write_text(json.dumps(source), encoding="utf-8")

            result = self.run_runner("--manifest", manifest, "--output", output)

            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("custom manifest", result.stderr.lower())
            self.assertFalse(output.exists())

    def test_manifest_rejects_incoherent_expected_outcome_tuples(self):
        source = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutations = [
            ("malicious_mcp", {"expected_outcome": "not_detected"}),
            ("malicious_mcp", {"expected_match": 1}),
            ("malicious_mcp", {"expected_incident_count": True}),
            ("malicious_mcp", {"expected_severity": None}),
            ("near_miss_mcp", {"expected_match": True}),
            ("near_miss_mcp", {"expected_match": []}),
            ("near_miss_mcp", {"expected_severity": "high"}),
            ("hostile_malformed_json", {"expected_incident_count": 1}),
            ("dark_edr_config_001", {"expected_outcome": "not_detected"}),
        ]
        with tempfile.TemporaryDirectory() as temp:
            for index, (case_id, changes) in enumerate(mutations):
                manifest = json.loads(json.dumps(source))
                case = next(item for item in manifest["cases"] if item["case_id"] == case_id)
                case.update(changes)
                path = Path(temp) / f"incoherent-{index}.json"
                path.write_text(json.dumps(manifest), encoding="utf-8")

                result = self.run_runner("--validate-only", "--manifest", path)

                self.assertNotEqual(result.returncode, 0, case_id)
                self.assertIn("contract error", result.stderr.lower())

    def test_output_symlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "protected"
            target.write_text("unchanged", encoding="utf-8")
            output = Path(temp) / "evidence.json"
            output.symlink_to(target)

            result = self.run_runner("--validate-only", "--output", output)

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")

    @unittest.skipUnless(os.name == "posix", "special files require POSIX")
    def test_output_special_file_is_rejected_without_replacing_it(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "evidence.fifo"
            os.mkfifo(output, 0o600)
            before = output.stat()

            result = self.run_runner("--validate-only", "--output", output)

            after = output.stat()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("regular file", result.stderr.lower())
            self.assertTrue(stat.S_ISFIFO(after.st_mode))
            self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))

    def test_matrix_drift_and_unknown_scenario_selection_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
            matrix["rules"][0]["scenario_ids"] = ["TVS-UNKNOWN-999"]
            matrix_path = Path(temp) / "matrix.json"
            matrix_path.write_text(json.dumps(matrix), encoding="utf-8")
            drift = self.run_runner(
                "--validate-only", "--matrix", matrix_path, "--output", Path(temp) / "out.json"
            )
            self.assertNotEqual(drift.returncode, 0)
            selected = self.run_runner("--scenario", "TVS-UNKNOWN-999")
            self.assertNotEqual(selected.returncode, 0)
            self.assertIn("unknown scenario", selected.stderr.lower())

    def test_matrix_rejects_scenarios_attributed_to_the_wrong_rule(self):
        with tempfile.TemporaryDirectory() as temp:
            matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
            first = matrix["rules"][0]["scenario_ids"]
            second = matrix["rules"][1]["scenario_ids"]
            matrix["rules"][0]["scenario_ids"], matrix["rules"][1]["scenario_ids"] = second, first
            matrix_path = Path(temp) / "matrix.json"
            matrix_path.write_text(json.dumps(matrix), encoding="utf-8")

            result = self.run_runner(
                "--validate-only", "--matrix", matrix_path, "--output", Path(temp) / "out.json"
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("scenario attribution", result.stderr.lower())

    def test_matrix_rejects_detected_and_tested_without_executed_scenario_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
            promoted = next(rule for rule in matrix["rules"] if rule["id"] == "EDR-SECRET-001")
            promoted["status"] = "DETECTED_AND_TESTED"
            matrix_path = Path(temp) / "matrix.json"
            matrix_path.write_text(json.dumps(matrix), encoding="utf-8")

            result = self.run_runner(
                "--validate-only", "--matrix", matrix_path,
                "--output", Path(temp) / "out.json",
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("executed scenario evidence", result.stderr.lower())

    def test_executed_mode_rejects_custom_matrix_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            matrix = Path(temp) / "matrix.json"
            public_matrix = Path(temp) / "matrix.md"
            matrix.write_bytes(MATRIX.read_bytes())
            public_matrix.write_bytes(PUBLIC_MATRIX.read_bytes())
            cases = (
                ("--matrix", matrix, "custom matrix"),
                ("--public-matrix", public_matrix, "custom public matrix"),
            )
            for option, path, diagnostic in cases:
                with self.subTest(option=option):
                    result = self.run_runner(option, path, "--output", Path(temp) / f"{option[2:]}.json")
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(diagnostic, result.stderr.lower())

    def test_public_matrix_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            public_matrix = Path(temp) / "matrix.md"
            public_matrix.write_text(
                PUBLIC_MATRIX.read_text(encoding="utf-8") + "manual drift\n", encoding="utf-8"
            )

            result = self.run_runner(
                "--validate-only", "--public-matrix", public_matrix,
                "--output", Path(temp) / "out.json"
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("public protection matrix drift", result.stderr.lower())

    def test_package_description_does_not_claim_unsupported_runtime_protection(self):
        nfpm = NFPM.read_text(encoding="utf-8")
        description = nfpm.split("description: |", 1)[1].split("\nvendor:", 1)[0].lower()

        self.assertNotIn("protects", description)
        for unsupported_runtime in ("openclaw", "codex", "claude code", "similar local agents"):
            with self.subTest(runtime=unsupported_runtime):
                self.assertNotIn(unsupported_runtime, description)

    def test_public_docs_do_not_retain_stale_release_positioning(self):
        architecture = ARCHITECTURE.read_text(encoding="utf-8")
        deployment = DEPLOYMENT.read_text(encoding="utf-8")
        threat_validation = THREAT_VALIDATION_DOC.read_text(encoding="utf-8")

        self.assertNotIn("v0.5.0 plans durable local alerting", architecture)
        self.assertIn("current v0.7.0-alpha.1", architecture.lower())
        self.assertNotIn("This v0.5.1 hotfix", deployment)
        self.assertIn("This v0.6.0 stable SemVer evaluation release", deployment)
        self.assertIn("manifest, matrix, and public-matrix SHA-256", threat_validation)
        self.assertIn("custom manifests, matrices, and public matrices", threat_validation)


if __name__ == "__main__":
    unittest.main()
