from __future__ import annotations

import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest import mock

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPOSITORY_ROOT / "packaging" / "scripts" / "deploy-verify.py"


def load_verifier():
    spec = importlib.util.spec_from_file_location("deploy_verify", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load deployment verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DeploymentVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = load_verifier()

    def valid_records(self):
        return {
            path: {"owner": owner, "group": group, "mode": mode}
            for path, owner, group, mode in self.verifier.PATH_CONTRACT
        }

    def test_exact_path_contract_accepts_only_expected_tuples(self) -> None:
        self.assertEqual(self.verifier.verify_path_records(self.valid_records()), [])

    def test_root_owned_state_directory_fails_without_mutation(self) -> None:
        records = self.valid_records()
        records["/var/lib/skynet-edr"] = {"owner": "root", "group": "root", "mode": "0750"}
        before = {path: dict(record) for path, record in records.items()}
        errors = self.verifier.verify_path_records(records)
        self.assertIn("/var/lib/skynet-edr: expected skynet-edr:skynet-edr 0750, observed root:root 0750", errors)
        self.assertEqual(records, before)

    def test_missing_path_fails_closed(self) -> None:
        records = self.valid_records()
        del records["/var/log/skynet-edr"]
        self.assertIn("/var/log/skynet-edr: missing", self.verifier.verify_path_records(records))

    def test_service_access_requires_every_named_permission(self) -> None:
        observations = {
            (path, permission): True
            for path, permissions in self.verifier.ACCESS_CONTRACT
            for permission in permissions
        }
        self.assertEqual(self.verifier.verify_access_observations(observations), [])
        observations[("/var/lib/skynet-edr", "w")] = False
        self.assertEqual(
            self.verifier.verify_access_observations(observations),
            ["skynet-edr lacks w access to /var/lib/skynet-edr"],
        )

    def test_service_access_probe_timeout_is_structured_and_non_authorizing(self) -> None:
        with (
            mock.patch.object(self.verifier.os, "geteuid", return_value=0),
            mock.patch.object(
                self.verifier.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(["runuser"], 5),
            ),
        ):
            observations, errors = self.verifier.collect_access_observations()
        self.assertEqual(observations, {})
        self.assertIn("access probe failed", errors[0])

    def test_api_contract_requires_status_risks_and_rules(self) -> None:
        documents = {
            "/api/status": {"version": "0.5.1", "ingestion": {"state": "disabled"}},
            "/api/v1/risks?limit=1&offset=0": {"schema_version": "skynet.risk.v1", "read_only": True},
            "/api/v1/rules": {"schema_version": "skynet.rules.v1", "read_only": True, "compiled_active": True},
        }
        self.assertEqual(self.verifier.verify_api_documents(documents, "0.5.1"), [])
        del documents["/api/v1/rules"]
        self.assertIn("/api/v1/rules: missing HTTP 200 JSON document", self.verifier.verify_api_documents(documents, "0.5.1"))

    def test_api_contract_rejects_wrong_version_schema_and_degraded_ingestion(self) -> None:
        documents = {
            "/api/status": {"version": "0.5.0", "ingestion": {"state": "degraded"}},
            "/api/v1/risks?limit=1&offset=0": {"schema_version": "wrong", "read_only": False},
            "/api/v1/rules": {"schema_version": "wrong", "read_only": True, "compiled_active": False},
        }
        errors = self.verifier.verify_api_documents(documents, "0.5.1")
        self.assertGreaterEqual(len(errors), 6)


if __name__ == "__main__":
    unittest.main()
