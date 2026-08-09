from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "packaging" / "scripts" / "vm-smoke.sh"


class VmSmokeGateTests(unittest.TestCase):
    def run_gate(self, *arguments: str, environment: dict[str, str] | None = None):
        clean_environment = {"PATH": os.environ["PATH"]}
        if environment:
            clean_environment.update(environment)
        return subprocess.run(
            [str(SCRIPT), *arguments],
            cwd=REPOSITORY_ROOT,
            env=clean_environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_rejects_manual_and_self_hosted_execution_before_mutation(self) -> None:
        cases = (
            ({}, "GITHUB_ACTIONS=true"),
            ({"GITHUB_ACTIONS": "true"}, "github-hosted"),
            (
                {"GITHUB_ACTIONS": "true", "SKYNET_EDR_RUNNER_ENVIRONMENT": "self-hosted"},
                "github-hosted",
            ),
            (
                {"GITHUB_ACTIONS": "true", "SKYNET_EDR_RUNNER_ENVIRONMENT": "github-hosted"},
                "SKYNET_EDR_DISPOSABLE_SMOKE=1",
            ),
        )
        for environment, expected in cases:
            with self.subTest(environment=environment):
                result = self.run_gate(environment=environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_accepts_attested_gate_and_reaches_argument_validation(self) -> None:
        result = self.run_gate(
            environment={
                "GITHUB_ACTIONS": "true",
                "SKYNET_EDR_RUNNER_ENVIRONMENT": "github-hosted",
                "SKYNET_EDR_DISPOSABLE_SMOKE": "1",
            }
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Usage:", result.stderr)

    def test_skip_purge_is_not_an_authoritative_gate_option(self) -> None:
        result = self.run_gate(
            "--skip-purge",
            environment={
                "GITHUB_ACTIONS": "true",
                "SKYNET_EDR_RUNNER_ENVIRONMENT": "github-hosted",
                "SKYNET_EDR_DISPOSABLE_SMOKE": "1",
            },
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown argument: --skip-purge", result.stderr)


if __name__ == "__main__":
    unittest.main()