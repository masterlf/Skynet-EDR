from __future__ import annotations

import importlib.util
import json
import stat
import subprocess
import time
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
            path: {"type": object_type, "owner": owner, "group": group, "mode": mode}
            for path, object_type, owner, group, mode in self.verifier.PATH_CONTRACT
        }

    def test_exact_path_contract_accepts_only_expected_tuples(self) -> None:
        self.assertEqual(self.verifier.verify_path_records(self.valid_records()), [])

    def test_root_owned_state_directory_fails_without_mutation(self) -> None:
        records = self.valid_records()
        records["/var/lib/skynet-edr"] = {
            "type": "directory",
            "owner": "root",
            "group": "root",
            "mode": "0750",
        }
        before = {path: dict(record) for path, record in records.items()}
        errors = self.verifier.verify_path_records(records)
        self.assertIn("/var/lib/skynet-edr: expected skynet-edr:skynet-edr 0750, observed root:root 0750", errors)
        self.assertEqual(records, before)

    def test_missing_path_fails_closed(self) -> None:
        records = self.valid_records()
        del records["/var/log/skynet-edr"]
        self.assertIn("/var/log/skynet-edr: missing", self.verifier.verify_path_records(records))

    def test_exact_path_contract_rejects_wrong_object_types(self) -> None:
        expected_types = {
            path: object_type
            for path, object_type, _, _, _ in self.verifier.PATH_CONTRACT
        }
        substitutions = {
            "/etc/skynet-edr/config.toml": "directory",
            "/usr/bin/skynet-edr": "fifo",
            "/usr/lib/systemd/system/skynet-edr.service": "device",
            "/var/lib/skynet-edr": "regular",
        }
        for path, wrong_type in substitutions.items():
            with self.subTest(path=path, wrong_type=wrong_type):
                records = self.valid_records()
                records[path]["type"] = wrong_type
                errors = self.verifier.verify_path_records(records)
                self.assertIn(
                    f"{path}: expected {expected_types[path]}",
                    errors[0],
                )

    def test_path_collection_rejects_symlinks_and_special_files(self) -> None:
        contract = (("/fixture", "regular", "root", "root", "0644"),)
        for mode, label in (
            (stat.S_IFLNK | 0o777, "symlink is not permitted"),
            (stat.S_IFIFO | 0o644, "unsupported object type: fifo"),
            (stat.S_IFCHR | 0o644, "unsupported object type: device"),
        ):
            with self.subTest(label=label), mock.patch.object(
                self.verifier, "PATH_CONTRACT", contract
            ), mock.patch.object(
                self.verifier.os, "lstat", return_value=mock.Mock(st_mode=mode)
            ):
                records, errors = self.verifier.collect_path_records()
            self.assertEqual(records, {})
            self.assertIn(label, errors[0])

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

    def test_port_accepts_only_strict_bounded_decimal(self) -> None:
        self.assertEqual(self.verifier.parse_port("8787"), 8787)
        for value in (
            "0",
            "65536",
            "+8787",
            " 8787",
            "127.0.0.1:8787",
            "http://127.0.0.1:8787",
            "http://localhost:8787",
            "http://user@127.0.0.1:8787",
            "http://127.0.0.1:8787?target=evil",
            "http://127.0.0.1:8787#fragment",
            "http://127.0.0.1:8787@evil.invalid",
            "[::1]:8787",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.verifier.parse_port(value)

    def test_redirect_handler_denies_redirects(self) -> None:
        handler = self.verifier.NoRedirectHandler()
        self.assertIsNone(
            handler.redirect_request(
                mock.Mock(), mock.Mock(), 302, "Found", {}, "http://evil.invalid/"
            )
        )

    def test_api_opener_disables_environment_proxies(self) -> None:
        with mock.patch.dict(
            self.verifier.os.environ,
            {"http_proxy": "http://evil.invalid:8080"},
        ):
            opener = self.verifier.build_api_opener()
        self.assertFalse(
            any(
                isinstance(handler, self.verifier.urllib.request.ProxyHandler)
                for handler in opener.handlers
            ),
            "an environment-derived proxy handler must not be installed",
        )
        self.assertTrue(
            any(
                isinstance(handler, self.verifier.NoRedirectHandler)
                for handler in opener.handlers
            )
        )

    def test_request_deadline_interrupts_slow_response(self) -> None:
        started = time.monotonic()
        with self.assertRaises(TimeoutError), self.verifier.request_deadline(0.05):
            time.sleep(0.2)
        self.assertLess(time.monotonic() - started, 0.2)

    def test_api_collection_bounds_and_authenticates_http_responses(self) -> None:
        class Headers:
            def __init__(self, content_type: str):
                self.content_type = content_type

            def get_content_type(self) -> str:
                return self.content_type

        class Response:
            status = 200

            def __init__(self, url: str, body: bytes, content_type: str = "application/json"):
                self.url = url
                self.body = body
                self.headers = Headers(content_type)
                self.read_limit = None

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def geturl(self) -> str:
                return self.url

            def read(self, limit: int) -> bytes:
                self.read_limit = limit
                return self.body[:limit]

        valid_documents = {
            "/api/status": {"version": "0.5.1", "ingestion": {"state": "healthy"}},
            "/api/v1/risks?limit=1&offset=0": {"schema_version": "skynet.risk.v1", "read_only": True},
            "/api/v1/rules": {"schema_version": "skynet.rules.v1", "read_only": True, "compiled_active": True},
        }

        def responses(*, override_path=None, override_body=None, content_type="application/json", final_url=None):
            result = {}
            for path, document in valid_documents.items():
                url = f"http://127.0.0.1:8787{path}"
                result[url] = Response(
                    final_url if path == override_path and final_url else url,
                    override_body if path == override_path and override_body is not None else json.dumps(document).encode(),
                    content_type if path == override_path else "application/json",
                )
            return result

        class Opener:
            def __init__(self, mapped):
                self.mapped = mapped

            def open(self, request, timeout):
                self.assert_timeout = timeout
                return self.mapped[request.full_url]

        mapped = responses()
        documents, errors = self.verifier.collect_api_documents(8787, Opener(mapped))
        self.assertEqual(errors, [])
        self.assertEqual(documents, valid_documents)
        self.assertTrue(
            all(response.read_limit == self.verifier.MAX_API_RESPONSE_BYTES + 1 for response in mapped.values())
        )

        cases = (
            ("redirect", responses(override_path="/api/status", final_url="http://evil.invalid/"), "final URL mismatch"),
            ("wrong content type", responses(override_path="/api/status", content_type="text/html"), "Content-Type must be application/json"),
            ("oversized", responses(override_path="/api/status", override_body=b"x" * 65538), "response exceeds"),
        )
        for label, mapped, expected_error in cases:
            with self.subTest(label=label):
                _, errors = self.verifier.collect_api_documents(8787, Opener(mapped))
                self.assertTrue(any(expected_error in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
