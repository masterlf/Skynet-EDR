import contextlib
import hashlib
import importlib.util
import json
import os
import signal
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "scripts" / "skynet-edr-hermes-enrollment-adapter.py"


def load_module():
    spec = importlib.util.spec_from_file_location("hermes_adapter", MODULE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE_CONFIG = """mode = \"passive\"\n\n[ingest]\nenabled = false\nsocket = \"/run/skynet-edr-ingest/ingest.sock\"\nsocket_group = \"skynet-edr-ingest\"\nallowed_uids = []\nallow_root = false\nrequired_reported_roles = []\nmax_frame_bytes = 262144\n"""


class PrivilegedHermesAdapterTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    @staticmethod
    def _path_info(file_type, *, uid=0, nlink=1, mode=0o755):
        return SimpleNamespace(st_mode=file_type | mode, st_uid=uid, st_nlink=nlink)

    def _status_payload(self, ingestion):
        return {
            "product": "Skynet-EDR", "binary": "skynet-edr", "run_mode": "passive",
            "server": "skynet-edr-mcp", "read_only": True, "tool_count": 6,
            "incident_count": 0, "event_count": 1, "version": "0.5.0",
            "ingestion": ingestion,
        }

    def _status_readback(self, status, **kwargs):
        body = json.dumps(status, separators=(",", ":")).encode("ascii")
        response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        client = mock.MagicMock()
        client.__enter__.return_value = client
        client.recv.side_effect = [response, b""]
        with mock.patch.object(self.module.socket, "socket", return_value=client):
            return self.module._status(**kwargs)

    def test_fixed_hermes_launcher_accepts_direct_regular_and_root_symlink_chains(self):
        regular = self._path_info(self.module.stat.S_IFREG)
        symlink = self._path_info(self.module.stat.S_IFLNK)
        directory = self._path_info(self.module.stat.S_IFDIR)
        paths = {
            Path("/usr"): directory,
            Path("/usr/bin"): directory,
            Path("/usr/bin/hermes"): regular,
            Path("/opt"): directory,
            Path("/opt/hermes"): directory,
            Path("/opt/hermes/bin"): directory,
            Path("/opt/hermes/bin/hermes"): regular,
            Path("/srv"): directory,
            Path("/srv/hermes"): directory,
            Path("/srv/hermes/current"): symlink,
        }

        def lstat(path):
            try:
                return paths[Path(path)]
            except KeyError as exc:
                raise FileNotFoundError(path) from exc

        with mock.patch.object(self.module.os, "lstat", side_effect=lstat), \
                mock.patch.object(self.module.os, "readlink") as readlink:
            self.assertEqual(
                self.module._resolve_hermes_launcher(Path("/usr/bin/hermes")),
                Path("/usr/bin/hermes"),
            )
            paths[Path("/usr/bin/hermes")] = symlink
            readlink.side_effect = ["/opt/hermes/bin/hermes"]
            self.assertEqual(
                self.module._resolve_hermes_launcher(Path("/usr/bin/hermes")),
                Path("/opt/hermes/bin/hermes"),
            )
            readlink.side_effect = ["/srv/hermes/current", "/opt/hermes/bin/hermes"]
            self.assertEqual(
                self.module._resolve_hermes_launcher(Path("/usr/bin/hermes")),
                Path("/opt/hermes/bin/hermes"),
            )

    def test_fixed_hermes_launcher_rejects_untrusted_or_ambiguous_chains(self):
        regular = self._path_info(self.module.stat.S_IFREG)
        symlink = self._path_info(self.module.stat.S_IFLNK)
        directory = self._path_info(self.module.stat.S_IFDIR)

        def resolve(paths, links, entry=Path("/usr/bin/hermes")):
            def lstat(path):
                try:
                    return paths[Path(path)]
                except KeyError as exc:
                    raise FileNotFoundError(path) from exc

            with mock.patch.object(self.module.os, "lstat", side_effect=lstat), \
                    mock.patch.object(self.module.os, "readlink", side_effect=lambda path: links[Path(path)]):
                return self.module._resolve_hermes_launcher(entry)

        trusted = {Path("/usr"): directory, Path("/usr/bin"): directory}
        final = Path("/opt/hermes/bin/hermes")
        final_parents = {
            Path("/opt"): directory,
            Path("/opt/hermes"): directory,
            Path("/opt/hermes/bin"): directory,
        }
        cases = {
            "relative_escape": (
                trusted | {Path("/usr/bin/hermes"): symlink},
                {Path("/usr/bin/hermes"): "../lib/hermes"},
            ),
            "cycle": (
                trusted | {Path("/usr/bin/hermes"): symlink, Path("/opt"): directory,
                           Path("/opt/hermes"): symlink},
                {Path("/usr/bin/hermes"): "/opt/hermes", Path("/opt/hermes"): "/usr/bin/hermes"},
            ),
            "non_root_symlink": (
                trusted | {Path("/usr/bin/hermes"): self._path_info(self.module.stat.S_IFLNK, uid=1000)},
                {Path("/usr/bin/hermes"): str(final)},
            ),
            "multiply_linked_symlink": (
                trusted | {Path("/usr/bin/hermes"): self._path_info(self.module.stat.S_IFLNK, nlink=2)},
                {Path("/usr/bin/hermes"): str(final)},
            ),
            "writable_parent": (
                trusted | {Path("/usr/bin/hermes"): symlink, Path("/opt"): directory,
                           Path("/opt/hermes"): self._path_info(self.module.stat.S_IFDIR, mode=0o775),
                           Path("/opt/hermes/bin"): directory, final: regular},
                {Path("/usr/bin/hermes"): str(final)},
            ),
            "writable_final": (
                trusted | final_parents | {Path("/usr/bin/hermes"): symlink,
                                           final: self._path_info(self.module.stat.S_IFREG, mode=0o775)},
                {Path("/usr/bin/hermes"): str(final)},
            ),
            "non_root_final": (
                trusted | final_parents | {Path("/usr/bin/hermes"): symlink,
                                           final: self._path_info(self.module.stat.S_IFREG, uid=1000)},
                {Path("/usr/bin/hermes"): str(final)},
            ),
            "multiply_linked_final": (
                trusted | final_parents | {Path("/usr/bin/hermes"): symlink,
                                           final: self._path_info(self.module.stat.S_IFREG, nlink=2)},
                {Path("/usr/bin/hermes"): str(final)},
            ),
            "non_regular_final": (
                trusted | final_parents | {Path("/usr/bin/hermes"): symlink, final: directory},
                {Path("/usr/bin/hermes"): str(final)},
            ),
            "non_executable_final": (
                trusted | final_parents | {Path("/usr/bin/hermes"): symlink,
                                           final: self._path_info(self.module.stat.S_IFREG, mode=0o644)},
                {Path("/usr/bin/hermes"): str(final)},
            ),
            "missing_target": (
                trusted | final_parents | {Path("/usr/bin/hermes"): symlink},
                {Path("/usr/bin/hermes"): str(final)},
            ),
            "missing_parent": (
                trusted | {Path("/usr/bin/hermes"): symlink, final: regular},
                {Path("/usr/bin/hermes"): str(final)},
            ),
        }
        for name, (paths, links) in cases.items():
            with self.subTest(name=name), self.assertRaises(self.module.AdapterError):
                resolve(paths, links)

        chain = {Path("/usr/bin/hermes"): symlink}
        links = {}
        parents = dict(trusted)
        current = Path("/usr/bin/hermes")
        for index in range(9):
            target = Path(f"/opt/h{index}")
            links[current] = str(target)
            chain[target] = symlink
            parents[Path("/opt")] = directory
            current = target
        with self.assertRaises(self.module.AdapterError):
            resolve(parents | chain, links)

        with self.assertRaises(self.module.AdapterError):
            resolve({}, {}, Path("usr/bin/hermes"))

    def test_execute_uses_resolved_hermes_target_for_mutation_and_readback(self):
        context = {"uid": 1000, "home": Path("/home/alice/.hermes"), "profile": "default",
                   "generation": "b" * 64}
        resolved = Path("/opt/hermes/bin/hermes")
        payloads = [b"", json.dumps([{"name": "skynet-edr", "status": "enabled"}]).encode()]
        with mock.patch.object(self.module, "_resolve_hermes_launcher", return_value=resolved), \
                mock.patch.object(self.module, "_run", side_effect=payloads) as run:
            result = self.module.execute("enable", context)
        self.assertTrue(result["plugin_enabled"])
        self.assertEqual([call.args[0][0] for call in run.call_args_list], [str(resolved), str(resolved)])

    def test_privileged_actions_require_root_and_target_never_allows_uid_zero(self):
        env = {
            "SKYNET_EDR_TARGET_UID": "1000",
            "SKYNET_EDR_NONCE": "a" * 64,
            "SKYNET_EDR_GENERATION": "b" * 64,
            "HERMES_HOME": "/home/alice/.hermes",
            "HERMES_PROFILE": "work",
        }
        with self.assertRaises(self.module.AdapterError):
            self.module.validate_context("prepare", env, effective_uid=1000)
        env["SKYNET_EDR_TARGET_UID"] = "0"
        with self.assertRaises(self.module.AdapterError):
            self.module.validate_context("prepare", env, effective_uid=0)

    def test_typed_ingest_update_adds_only_reviewed_uid_and_gateway_role(self):
        updated = self.module.rewrite_ingest_toml(BASE_CONFIG, 1001, enabled=True)
        self.assertIn("enabled = true", updated)
        self.assertIn('socket_group = "skynet-edr-ingest"', updated)
        self.assertIn("allowed_uids = [1001]", updated)
        self.assertIn('required_reported_roles = ["gateway"]', updated)
        self.assertIn("allow_root = false", updated)
        second = self.module.rewrite_ingest_toml(updated, 1002, enabled=True)
        self.assertIn("allowed_uids = [1001, 1002]", second)
        removed = self.module.rewrite_ingest_toml(second, 1001, enabled=False)
        self.assertIn("allowed_uids = [1002]", removed)
        self.assertIn("enabled = true", removed)

    def test_ambiguous_or_mistyped_toml_fails_closed(self):
        cases = (
            BASE_CONFIG.replace("enabled = false", "enabled = false\nenabled = true"),
            BASE_CONFIG.replace("allowed_uids = []", 'allowed_uids = ["1000"]'),
            BASE_CONFIG.replace("allow_root = false", "allow_root = true"),
            BASE_CONFIG.replace("socket_group = \"skynet-edr-ingest\"", "socket_group = \"other\""),
        )
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(self.module.AdapterError):
                    self.module.rewrite_ingest_toml(value, 1000, enabled=True)

    def test_only_exact_reviewed_unit_and_per_unit_role_are_rendered(self):
        generation = "a" * 64
        self.assertEqual(
            self.module.render_dropin(
                ["hermes-gateway.service"], generation, Path("/home/alice/.hermes"), "default"
            ),
            ("[Service]\nEnvironment=HERMES_RUNTIME_ROLE=gateway\n"
             f"Environment=SKYNET_EDR_PLUGIN_GENERATION={generation}\n"
             "Environment=HERMES_HOME=%h/.hermes\n"
             "Environment=HERMES_PROFILE=default\n"
             "Environment=PYTHONDONTWRITEBYTECODE=1\n"),
        )
        for units in (["hermes-dashboard.service"], ["hermes-gateway@alice.service"], ["hermes-gateway.service", "other.service"]):
            with self.subTest(units=units):
                with self.assertRaises(self.module.AdapterError):
                    self.module.render_dropin(units, generation, Path("/home/alice/.hermes"), "default")
        with self.assertRaises(self.module.AdapterError):
            self.module.render_dropin(
                ["hermes-gateway.service"], generation, Path("/home/alice/.hermes"), "work"
            )
        self.assertEqual(
            self.module.render_dropin(
                ["hermes-gateway.service"], generation, Path("/home/bob/.hermes"), "default"
            ),
            self.module.render_dropin(
                ["hermes-gateway.service"], generation, Path("/home/alice/.hermes"), "default"
            ),
        )

    def test_context_binds_hermes_home_to_account_home(self):
        account_home = self.base / "home" / "alice"
        hermes_home = account_home / ".hermes"
        hermes_home.mkdir(parents=True, mode=0o700)
        home_info = hermes_home.stat()
        env = {
            "SKYNET_EDR_TARGET_UID": "1000",
            "SKYNET_EDR_NONCE": "a" * 64,
            "SKYNET_EDR_GENERATION": "b" * 64,
            "HERMES_HOME": "/srv/attacker-selected/missing",
            "HERMES_PROFILE": "default",
            "SKYNET_EDR_HOME_DEVICE": str(home_info.st_dev),
            "SKYNET_EDR_HOME_INODE": str(home_info.st_ino),
        }
        account = SimpleNamespace(pw_name="alice", pw_dir=str(account_home), pw_gid=os.getgid())
        pinned_info = SimpleNamespace(
            st_dev=home_info.st_dev, st_ino=home_info.st_ino, st_uid=1000, st_mode=home_info.st_mode
        )
        with (mock.patch.object(self.module.pwd, "getpwuid", return_value=account),
              mock.patch.object(self.module.os, "fstat", return_value=pinned_info)):
            with self.assertRaises(self.module.AdapterError):
                self.module.validate_context("prepare", env, effective_uid=0)
            env["HERMES_HOME"] = str(hermes_home)
            context = self.module.validate_context("prepare", env, effective_uid=0)
        self.addCleanup(os.close, context["home_fd"])
        self.assertEqual(context["home"], hermes_home)

    def test_context_rejects_custom_profile_as_unsupported(self):
        account_home = self.base / "home" / "alice"
        hermes_home = account_home / ".hermes"
        hermes_home.mkdir(parents=True, mode=0o700)
        home_info = hermes_home.stat()
        env = {
            "SKYNET_EDR_TARGET_UID": "1000",
            "SKYNET_EDR_NONCE": "a" * 64,
            "SKYNET_EDR_GENERATION": "b" * 64,
            "HERMES_HOME": str(hermes_home),
            "HERMES_PROFILE": "work",
            "SKYNET_EDR_HOME_DEVICE": str(home_info.st_dev),
            "SKYNET_EDR_HOME_INODE": str(home_info.st_ino),
        }
        account = SimpleNamespace(pw_name="alice", pw_dir=str(account_home), pw_gid=os.getgid())
        with mock.patch.object(self.module.pwd, "getpwuid", return_value=account):
            with self.assertRaises(self.module.AdapterError) as error:
                self.module.validate_context("prepare", env, effective_uid=0)
        self.assertEqual(error.exception.category, "unsupported_contract")

    def test_child_environment_keeps_exact_canonical_hermes_home(self):
        context = {
            "uid": 1000,
            "home": Path("/home/alice/.hermes"),
            "profile": "default",
            "home_fd": 42,
        }
        environment = self.module._minimal_env(context)
        self.assertEqual(environment["HERMES_HOME"], "/home/alice/.hermes")
        self.assertEqual(environment["HERMES_PROFILE"], "default")
        self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertNotIn("_SKYNET_EDR_HOME_FD", environment)

    def test_gateway_environment_readback_requires_bytecode_role_and_exact_generation(self):
        context = {
            "uid": 1000,
            "home": Path("/home/alice/.hermes"),
            "profile": "default",
            "generation": "b" * 64,
        }
        required = (
            "HERMES_HOME=/home/alice/.hermes HERMES_PROFILE=default "
            "HERMES_RUNTIME_ROLE=gateway PYTHONDONTWRITEBYTECODE=1 "
            f"SKYNET_EDR_PLUGIN_GENERATION={context['generation']}\n"
        ).encode()
        with mock.patch.object(self.module, "_run", return_value=required):
            self.assertTrue(self.module._gateway_context_matches(context))
        for missing in ("PYTHONDONTWRITEBYTECODE=1", "HERMES_RUNTIME_ROLE=gateway",
                        f"SKYNET_EDR_PLUGIN_GENERATION={context['generation']}"):
            with self.subTest(missing=missing), mock.patch.object(
                self.module, "_run", return_value=required.replace(missing.encode(), b"")
            ):
                self.assertFalse(self.module._gateway_context_matches(context))

    def _v3_source(self, **changes):
        source = {
            "source_id": "uid:1000:gateway:" + "b" * 64 + ":" + "a" * 64,
            "authenticated_uid": 1000, "runtime_role": "gateway", "protocol_version": 3,
            "s3_eligible": True, "plugin_generation": "b" * 64,
            "runtime_instance_nonce": "a" * 64, "kernel_peer_pid": 22,
            "kernel_peer_start_ticks": 202, "producer_report_age_ms": 0,
            "transport_state": "available", "backlog_bytes": 0,
            "instance_id": None, "producer_checkpoint_bytes": 0, "backlog_age_ms": None,
            "commit_sequence": 4, "events_persisted_total": 4,
            "events_duplicate_total": 0, "events_collision_total": 0,
            "events_malformed_total": 0, "events_dropped_total": 0,
            "last_event_received_at_unix_ms": 100, "last_event_committed_at_unix_ms": 100,
            "last_error_category": None, "last_error_at_unix_ms": None,
            "last_error_age_ms": None, "producer_reported_at_unix_ms": 100,
            "last_persisted_canary_event_id": None,
            "last_persisted_canary_receipt_status": None,
            "last_persisted_canary_incidents_opened": None,
        }
        source.update(changes)
        return source

    def test_exact_v3_source_requires_cardinality_freshness_and_kernel_gateway_identity(self):
        context = {"uid": 1000, "generation": "b" * 64}
        gateway = self.module.ProcessIdentity(22, 202, 2002)
        valid = self._v3_source()
        self.assertEqual(self.module._exact_source({"sources": [valid]}, context, gateway), valid)
        for mutation in (
            {"protocol_version": 2}, {"s3_eligible": False}, {"plugin_generation": "c" * 64},
            {"runtime_instance_nonce": "b" * 64}, {"kernel_peer_pid": 23},
            {"kernel_peer_start_ticks": 203}, {"producer_report_age_ms": 30_001},
            {"transport_state": "degraded"}, {"backlog_bytes": 1},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(self.module.AdapterError):
                self.module._exact_source({"sources": [dict(valid, **mutation)]}, context, gateway)
        for sources in ([], [valid, dict(valid)]):
            with self.subTest(cardinality=len(sources)), self.assertRaises(self.module.AdapterError):
                self.module._exact_source({"sources": sources}, context, gateway)
        retained = [
            self._v3_source(plugin_generation="c" * 64),
            self._v3_source(kernel_peer_pid=99),
            {"authenticated_uid": 1000, "runtime_role": "legacy", "protocol_version": 1},
        ]
        self.assertEqual(self.module._exact_source({"sources": retained + [valid]}, context, gateway), valid)

    def test_exact_v3_source_rejects_unknown_missing_and_mistyped_schema(self):
        context = {"uid": 1000, "generation": "b" * 64}
        gateway = self.module.ProcessIdentity(22, 202, 2002)
        valid = self._v3_source()
        invalid = [dict(valid, unknown=True), dict(valid, backlog_age_ms=0),
                   dict(valid, last_error_category="storage", last_error_at_unix_ms=None,
                        last_error_age_ms=None)]
        for key in ("producer_checkpoint_bytes", "backlog_age_ms", "events_persisted_total"):
            row = dict(valid)
            row.pop(key)
            invalid.append(row)
        for key in ("authenticated_uid", "protocol_version", "kernel_peer_pid",
                    "producer_checkpoint_bytes", "backlog_bytes", "commit_sequence",
                    "events_persisted_total", "events_duplicate_total", "events_collision_total",
                    "events_malformed_total", "events_dropped_total", "producer_report_age_ms"):
            invalid.append(dict(valid, **{key: False}))
        for row in invalid:
            with self.subTest(row=row), self.assertRaises(self.module.AdapterError):
                self.module._exact_source({"sources": [row]}, context, gateway)

    def test_status_root_and_ingestion_schema_are_exact_and_typed(self):
        ingestion = {
            "state": "healthy", "role_identity_assurance": "authorized_uid_self_reported",
            "listener_live": True, "transport_heartbeat_state": "fresh",
            "hook_event_state": "fresh", "hook_event_freshness_affects_state": False,
            "last_event_received_at_unix_ms": 1, "last_event_received_age_ms": 0,
            "last_event_committed_at_unix_ms": 1, "last_event_committed_age_ms": 0,
            "required_reported_roles": [{"runtime_role": "gateway", "state": "fresh"}],
            "connections_accepted_total": 1, "connections_unauthorized_total": 0,
            "connections_capacity_rejected_total": 0, "listener_errors_total": 0,
            "peer_credential_errors_total": 0, "frames_received_total": 1,
            "frames_oversize_total": 0, "frames_invalid_total": 0,
            "frames_timeout_total": 0, "events_persisted_total": 1,
            "events_duplicate_total": 0, "events_collision_total": 0,
            "incident_integrity_collision_total": 0, "correlation_truncated_total": 0,
            "storage_errors_total": 0, "sources": [self._v3_source()],
        }
        status = {
            "product": "Skynet-EDR", "binary": "skynet-edr", "run_mode": "passive",
            "server": "skynet-edr-mcp", "read_only": True, "tool_count": 6,
            "incident_count": 0, "event_count": 1, "version": "0.4.1",
            "ingestion": ingestion,
        }
        self.assertIs(self.module._validate_status_schema(status), ingestion)
        invalid = [
            dict(status, unknown=True),
            dict(status, read_only=1),
            dict(status, ingestion=dict(ingestion, unknown=True)),
            dict(status, ingestion=dict(ingestion, listener_live=1)),
            dict(status, ingestion=dict(ingestion, frames_received_total=True)),
            dict(status, ingestion=dict(ingestion, required_reported_roles=[{"runtime_role": "gateway"}])),
        ]
        for candidate in invalid:
            with self.subTest(candidate=candidate), self.assertRaises(self.module.AdapterError):
                self.module._validate_status_schema(candidate)

    def test_status_disabled_schema_is_exact_and_only_accepted_by_explicit_opt_in(self):
        disabled_ingestion = {
            "state": "disabled", "role_identity_assurance": "authorized_uid_self_reported",
            "listener_live": False, "sources": [],
        }
        disabled = self._status_payload(disabled_ingestion)
        with self.assertRaisesRegex(self.module.AdapterError, "readback_failure"):
            self._status_readback(disabled)
        self.assertEqual(
            self._status_readback(disabled, allow_disabled=True),
            disabled,
        )

        full_ingestion = {
            "state": "healthy", "role_identity_assurance": "authorized_uid_self_reported",
            "listener_live": True, "transport_heartbeat_state": "fresh",
            "hook_event_state": "fresh", "hook_event_freshness_affects_state": False,
            "last_event_received_at_unix_ms": 1, "last_event_received_age_ms": 0,
            "last_event_committed_at_unix_ms": 1, "last_event_committed_age_ms": 0,
            "required_reported_roles": [{"runtime_role": "gateway", "state": "fresh"}],
            "connections_accepted_total": 1, "connections_unauthorized_total": 0,
            "connections_capacity_rejected_total": 0, "listener_errors_total": 0,
            "peer_credential_errors_total": 0, "frames_received_total": 1,
            "frames_oversize_total": 0, "frames_invalid_total": 0,
            "frames_timeout_total": 0, "events_persisted_total": 1,
            "events_duplicate_total": 0, "events_collision_total": 0,
            "incident_integrity_collision_total": 0, "correlation_truncated_total": 0,
            "storage_errors_total": 0, "sources": [self._v3_source()],
        }
        full = self._status_payload(full_ingestion)
        self.assertEqual(self._status_readback(full, allow_disabled=True), full)
        with self.assertRaisesRegex(self.module.AdapterError, "readback_failure"):
            self._status_readback(
                dict(full, ingestion={"state": "healthy", "sources": []}),
                allow_disabled=True,
            )

    def test_disabled_status_schema_rejects_every_root_and_ingestion_mutation(self):
        ingestion = {
            "state": "disabled", "role_identity_assurance": "authorized_uid_self_reported",
            "listener_live": False, "sources": [],
        }
        status = self._status_payload(ingestion)
        self.assertIs(self.module._validate_disabled_status_schema(status), ingestion)

        invalid: list[dict] = [dict(status, unknown=True)]
        for key in self.module.STATUS_KEYS:
            candidate = dict(status)
            candidate.pop(key)
            invalid.append(candidate)
        for key, values in {
            "product": ("Other", False), "binary": ("other", False),
            "run_mode": ("active", False), "server": ("other", False),
            "read_only": (False, 1), "version": ("", False),
        }.items():
            invalid.extend(dict(status, **{key: value}) for value in values)
        for key in ("tool_count", "incident_count", "event_count"):
            invalid.extend(dict(status, **{key: value}) for value in (True, -1, 1.5))
        invalid.extend([
            dict(status, ingestion=[]),
            dict(status, ingestion=dict(ingestion, unknown=True)),
        ])
        for missing in ingestion:
            invalid.append(dict(
                status,
                ingestion={key: value for key, value in ingestion.items() if key != missing},
            ))
        invalid.extend(
            dict(status, ingestion=dict(ingestion, **mutation))
            for mutation in (
                {"state": "degraded"}, {"state": False},
                {"role_identity_assurance": "unknown"},
                {"role_identity_assurance": False},
                {"listener_live": 0}, {"listener_live": True},
                {"sources": [self._v3_source()]}, {"sources": ()},
            )
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate), self.assertRaisesRegex(
                    self.module.AdapterError, "readback_failure"):
                self.module._validate_disabled_status_schema(candidate)

    def test_generation_and_runtime_nonce_are_independent(self):
        context = {"uid": 1000, "generation": "b" * 64, "attestation_token": "c" * 64}
        gateway = self.module.ProcessIdentity(22, 202, 2002)
        with self.assertRaises(self.module.AdapterError):
            self.module._exact_source(
                {"sources": [self._v3_source(runtime_instance_nonce="b" * 64)]}, context, gateway
            )
        token_nonce = self._v3_source(
            source_id="uid:1000:gateway:" + "b" * 64 + ":" + "c" * 64,
            runtime_instance_nonce="c" * 64,
        )
        with self.assertRaisesRegex(self.module.AdapterError, "producer_health"):
            self.module._exact_source({"sources": [token_nonce]}, context, gateway)

    def test_restart_epoch_requires_a_new_runtime_nonce_when_prior_v3_identity_is_known(self):
        context = {"uid": 1000, "generation": "b" * 64}
        gateway = self.module.ProcessIdentity(21, 201, 2001)
        prior = self._v3_source(
            source_id="uid:1000:gateway:" + "b" * 64 + ":" + "c" * 64,
            runtime_instance_nonce="c" * 64, kernel_peer_pid=21, kernel_peer_start_ticks=201,
        )
        self.assertEqual(
            self.module._previous_runtime_nonce({"ingestion": {"sources": [prior]}}, context, gateway),
            "c" * 64,
        )
        unrelated = [
            dict(prior, plugin_generation="d" * 64),
            dict(prior, kernel_peer_pid=99),
            dict(prior, kernel_peer_start_ticks=999),
            dict(prior, protocol_version=2),
            dict(prior, protocol_version=True),
            dict(prior, authenticated_uid=True),
            {"authenticated_uid": 1000, "runtime_role": "gateway", "protocol_version": 1},
        ]
        self.assertEqual(self.module._previous_runtime_nonce(
            {"ingestion": {"sources": unrelated + [prior]}}, context, gateway
        ), "c" * 64)
        self.assertIsNone(self.module._previous_runtime_nonce(
            {"ingestion": {"sources": unrelated}}, context, gateway
        ))
        with self.assertRaisesRegex(self.module.AdapterError, "source_cardinality"):
            self.module._previous_runtime_nonce(
                {"ingestion": {"sources": unrelated + [prior, dict(prior)]}}, context, gateway
            )

    def test_recorded_attestation_expires_with_original_deadline_and_boot(self):
        context = {"uid": 1000, "profile": "default", "generation": "b" * 64,
                   "deadline_ns": 101}
        scope = self.base / "scope"
        scope.mkdir()
        (scope / "snapshot.json").write_text(
            json.dumps({"generation": "b" * 64}), encoding="ascii"
        )
        observation = {"loaded_generation": "b" * 64}
        boot_id = "00000000-0000-0000-0000-000000000000"
        with (mock.patch.object(self.module, "_scope", return_value=scope),
              mock.patch.object(self.module, "_boot_id", return_value=boot_id),
              mock.patch.object(self.module.time, "monotonic_ns", return_value=100)):
            self.module._record_attestation(context, observation, 101, boot_id)
            self.assertEqual(self.module._attestation(context), observation)
        with (mock.patch.object(self.module, "_scope", return_value=scope),
              mock.patch.object(self.module.time, "monotonic_ns", return_value=101)):
            with self.assertRaises(self.module.AdapterError):
                self.module._attestation(context)

    def test_persisted_advancement_requires_same_source_without_retry_collision_or_error(self):
        baseline = self._v3_source()
        token = "d" * 64
        event_id = "evt_skynet_attest_" + hashlib.sha256(
            b"skynet-edr-attestation-v1\0" + token.encode("ascii")
        ).hexdigest()
        advanced = self._v3_source(
            commit_sequence=5, events_persisted_total=5,
            last_persisted_canary_event_id=event_id,
            last_persisted_canary_receipt_status="persisted",
            last_persisted_canary_incidents_opened=0,
        )
        self.assertTrue(self.module._persisted_advanced(baseline, advanced, event_id))
        for mutation in (
            {}, {"commit_sequence": 5, "events_persisted_total": 4},
            {"commit_sequence": 6, "events_persisted_total": 6},
            {"commit_sequence": 5, "events_persisted_total": 5, "events_duplicate_total": 1},
            {"commit_sequence": 5, "events_persisted_total": 5, "events_collision_total": 1},
            {"commit_sequence": 5, "events_persisted_total": 5, "events_dropped_total": 1},
            {"commit_sequence": 5, "events_persisted_total": 5, "events_malformed_total": 1},
            {"commit_sequence": 5, "events_persisted_total": 5, "last_error_category": "storage"},
            {"commit_sequence": 5, "events_persisted_total": 5, "runtime_instance_nonce": "c" * 64},
        ):
            with self.subTest(mutation=mutation):
                self.assertFalse(self.module._persisted_advanced(baseline, dict(baseline, **mutation), event_id))
        unrelated = dict(advanced, last_persisted_canary_event_id="evt_skynet_attest_" + "0" * 64)
        self.assertFalse(self.module._persisted_advanced(baseline, unrelated, event_id))
        self.assertFalse(self.module._persisted_advanced(
            baseline, dict(advanced, last_persisted_canary_incidents_opened=1), event_id
        ))

    def test_canary_command_requires_exact_event_bound_ack(self):
        token = "d" * 64
        event_id = "evt_skynet_attest_" + hashlib.sha256(
            b"skynet-edr-attestation-v1\0" + token.encode("ascii")
        ).hexdigest()
        context = {"uid": os.getuid(), "account_gid": os.getgid(),
                   "home": self.base / ".hermes", "profile": "default"}
        expected = f"SKYNET_EDR_ATTEST_ACK_V1 {event_id}\n".encode("ascii")
        fake_hermes = self.base / "fake-hermes"
        fake_hermes.write_text(
            "#!/usr/bin/python3\n"
            "import sys\n"
            "assert sys.argv[1:7] == ['chat','--max-turns','1','--toolsets','none','-q']\n"
            "lines = sys.argv[7].splitlines()\n"
            "parts = lines[0].split()\n"
            "assert len(parts) == 3 and parts[0] == 'SKYNET_EDR_ATTEST_V1'\n"
            "event_id = parts[1]\n"
            "assert lines == [lines[0], f'Respond with exactly SKYNET_EDR_ATTEST_ACK_V1 {event_id} and no other text.']\n"
            "print(f'SKYNET_EDR_ATTEST_ACK_V1 {event_id}')\n",
            encoding="ascii",
        )
        fake_hermes.chmod(0o755)
        context["_hermes_launcher"] = fake_hermes
        with mock.patch.object(self.module, "HERMES", fake_hermes):
            self.module._run_canary(
                context, event_id, token, self.module.time.monotonic_ns() + 1_000_000_000
            )

        for output in (b"OK\n", expected.replace(event_id.encode(), b"evt_skynet_attest_" + b"0" * 64),
                       expected.rstrip(b"\n"), expected + b"extra\n"):
            with self.subTest(output=output), mock.patch.object(self.module, "_run", return_value=output):
                with self.assertRaisesRegex(self.module.AdapterError, "hook_failure"):
                    self.module._run_canary(context, event_id, token, 100)

    def test_attest_context_rejects_expired_inherited_deadline_before_nss(self):
        env = {
            "SKYNET_EDR_TARGET_UID": "1000", "SKYNET_EDR_NONCE": "a" * 64,
            "SKYNET_EDR_GENERATION": "b" * 64, "HERMES_HOME": "/home/alice/.hermes",
            "HERMES_PROFILE": "default", "SKYNET_EDR_HOME_DEVICE": "1",
            "SKYNET_EDR_HOME_INODE": "2", "SKYNET_EDR_DEADLINE_NS": "100",
            "SKYNET_EDR_ATTESTATION_TOKEN": "c" * 64,
            "SKYNET_EDR_CANARY_EVENT_ID": "evt_skynet_attest_" + "d" * 64,
        }
        with (mock.patch.object(self.module.time, "monotonic_ns", return_value=100),
              mock.patch.object(self.module.pwd, "getpwuid") as nss):
            with self.assertRaisesRegex(self.module.AdapterError, "deadline"):
                self.module.validate_context("attest", env, effective_uid=0)
        nss.assert_not_called()

    def test_attest_main_uses_fixed_deadline_field_before_context_and_restores_watchdog(self):
        deadline = 10_000_000_000
        environment = {
            "SKYNET_EDR_DEADLINE_NS": str(deadline),
            "SKYNET_EDR_ATTEST_DEADLINE_NS": "not-authoritative",
        }
        with mock.patch.object(self.module.sys, "argv", ["adapter", "attest"]), \
                mock.patch.object(self.module.os, "environ", environment), \
                mock.patch.object(self.module, "_deadline_watchdog") as watchdog, \
                mock.patch.object(self.module, "validate_context", side_effect=self.module.AdapterError("deadline")) as validate, \
                mock.patch.object(self.module, "emit", return_value=1):
            self.assertEqual(self.module.main(), 1)
        watchdog.assert_called_once_with(deadline)
        validate.assert_called_once_with("attest", environment)

    def test_adapter_deadline_watchdog_restores_signal_state_on_success_and_error(self):
        for failure in (False, True):
            previous_handler = mock.Mock()
            current_handler = {"value": previous_handler}
            events = []
            timer_calls = 0

            def install(_signum, handler):
                old = current_handler["value"]
                current_handler["value"] = handler
                events.append(("signal", handler))
                return old

            def set_timer(_which, delay, interval=0.0):
                nonlocal timer_calls
                timer_calls += 1
                events.append(("timer", delay, interval))
                if timer_calls == 1:
                    return (0.5, 0.25)
                if delay > 0:
                    current_handler["value"](signal.SIGALRM, None)
                return (0.0, 0.0)

            monotonic = [0, 600_000_000] if failure else [0, 600_000_000, 600_000_000]
            with self.subTest(failure=failure), \
                    mock.patch.object(self.module.time, "monotonic_ns", side_effect=monotonic), \
                    mock.patch.object(self.module.signal, "signal", side_effect=install), \
                    mock.patch.object(self.module.signal, "setitimer", side_effect=set_timer):
                with self.assertRaises(RuntimeError) if failure else contextlib.nullcontext():
                    with self.module._deadline_watchdog(10_000_000_000):
                        if failure:
                            raise RuntimeError("boom")
            self.assertEqual(events[-2], ("signal", previous_handler))
            self.assertEqual(events[-1][0], "timer")
            self.assertGreater(events[-1][1], 0.0)
            previous_handler.assert_called_once_with(signal.SIGALRM, None)

    def test_record_attestation_does_not_write_when_snapshot_read_reaches_deadline(self):
        context = {"uid": 1000, "profile": "default", "generation": "b" * 64}
        snapshot_path = self.base / "scope" / "snapshot.json"
        snapshot_path.parent.mkdir()
        snapshot_path.write_text(json.dumps({"generation": "b" * 64}), encoding="ascii")
        with mock.patch.object(self.module, "_scope", return_value=snapshot_path.parent), \
                mock.patch.object(self.module.time, "monotonic_ns", side_effect=[0, 100]), \
                mock.patch.object(self.module, "_atomic_write") as write:
            with self.assertRaisesRegex(self.module.AdapterError, "deadline"):
                self.module._record_attestation(context, {}, 100, "00000000-0000-0000-0000-000000000000")
        write.assert_not_called()

    def test_attest_watchdog_interrupts_slow_nss_before_home_or_package_reads(self):
        token = "c" * 64
        event_id = "evt_skynet_attest_" + hashlib.sha256(
            b"skynet-edr-attestation-v1\0" + token.encode("ascii")
        ).hexdigest()
        deadline_ns = self.module.time.monotonic_ns() + 50_000_000
        environment = {
            "SKYNET_EDR_TARGET_UID": "1000", "SKYNET_EDR_NONCE": "a" * 64,
            "SKYNET_EDR_GENERATION": "b" * 64, "HERMES_HOME": "/home/alice/.hermes",
            "HERMES_PROFILE": "default", "SKYNET_EDR_HOME_DEVICE": "1",
            "SKYNET_EDR_HOME_INODE": "2", "SKYNET_EDR_DEADLINE_NS": str(deadline_ns),
            "SKYNET_EDR_ATTESTATION_TOKEN": token, "SKYNET_EDR_CANARY_EVENT_ID": event_id,
        }

        def slow_nss(_uid):
            self.module.time.sleep(5)

        started = self.module.time.monotonic()
        with mock.patch.object(self.module.sys, "argv", ["adapter", "attest"]), \
                mock.patch.object(self.module.os, "environ", environment), \
                mock.patch.object(self.module.pwd, "getpwuid", side_effect=slow_nss) as nss, \
                mock.patch.object(self.module.os, "open") as open_path, \
                mock.patch.object(self.module, "emit", return_value=1):
            self.assertEqual(self.module.main(), 1)
        self.assertLess(self.module.time.monotonic() - started, 1.0)
        nss.assert_called_once_with(1000)
        open_path.assert_not_called()

    def test_deadline_expiry_after_temp_fsync_prevents_atomic_replace(self):
        target = self.base / "deadline-write"
        with mock.patch.object(self.module.time, "monotonic_ns", side_effect=[0, 0, 0, 100]), \
                mock.patch.object(self.module.os, "replace") as replace:
            with self.assertRaisesRegex(self.module.AdapterError, "deadline"):
                self.module._atomic_write(target, b"safe", 0o600, deadline_ns=100)
        replace.assert_not_called()

    def test_deadline_propagates_remaining_timeout_and_forbids_calls_at_expiry(self):
        clock = mock.Mock()
        clock.monotonic_ns.side_effect = [1_000, 2_000, 3_000]
        completed = SimpleNamespace(returncode=0, stdout=b"ok")
        with (mock.patch.object(self.module.time, "monotonic_ns", clock.monotonic_ns),
              mock.patch.object(self.module.subprocess, "run", return_value=completed) as run):
            self.assertEqual(self.module._run(["/bin/true"], env={}, deadline_ns=5_000), b"ok")
        self.assertEqual(run.call_args.kwargs["timeout"], 0.000004)
        with mock.patch.object(self.module.time, "monotonic_ns", return_value=5_000):
            with self.assertRaises(self.module.AdapterError):
                self.module._run(["/bin/true"], env={}, deadline_ns=5_000)

    def test_deadline_rejects_subprocess_returning_at_expiry_and_caps_sleep(self):
        completed = SimpleNamespace(returncode=0, stdout=b"ok")
        with (mock.patch.object(self.module.time, "monotonic_ns", side_effect=[0, 15_000_000_000]),
              mock.patch.object(self.module.subprocess, "run", return_value=completed)):
            with self.assertRaises(self.module.AdapterError):
                self.module._run(["/bin/true"], env={}, deadline_ns=15_000_000_000)
        with (mock.patch.object(self.module.time, "monotonic_ns", side_effect=[14_900_000_000, 15_000_000_000]),
              mock.patch.object(self.module.time, "sleep") as sleep):
            with self.assertRaises(self.module.AdapterError):
                self.module._bounded_sleep(15_000_000_000, 0.5)
        sleep.assert_called_once_with(0.1)

    def test_wait_for_socket_ready_retries_missing_with_inherited_deadline(self):
        ready = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_gid=987)
        with mock.patch.object(self.module.time, "monotonic_ns", return_value=0), mock.patch.object(
            self.module.os, "lstat", side_effect=[FileNotFoundError(), FileNotFoundError(), ready]
        ) as lstat, mock.patch.object(self.module, "_bounded_sleep") as sleep:
            self.assertIs(self.module._wait_for_socket_ready(Path("/run/ingest.sock"), 987, 1234), True)
        self.assertEqual(lstat.call_count, 3)
        self.assertEqual(sleep.call_args_list, [mock.call(1234), mock.call(1234)])

    def test_wait_for_socket_ready_accepts_exact_socket_without_sleep(self):
        ready = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_gid=987)
        with mock.patch.object(self.module.time, "monotonic_ns", return_value=0), \
                mock.patch.object(self.module.os, "lstat", return_value=ready), \
                mock.patch.object(self.module, "_bounded_sleep") as sleep:
            self.assertIs(self.module._wait_for_socket_ready(Path("/run/ingest.sock"), 987, 1234), True)
        sleep.assert_not_called()

    def test_wait_for_socket_ready_retries_socket_until_exact_dac_and_gid(self):
        candidates = [
            SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_gid=987),
            SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_gid=986),
            SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_gid=987),
        ]
        with mock.patch.object(self.module.time, "monotonic_ns", return_value=0), \
                mock.patch.object(self.module.os, "lstat", side_effect=candidates), \
                mock.patch.object(self.module, "_bounded_sleep") as sleep:
            self.assertIs(self.module._wait_for_socket_ready(Path("/run/ingest.sock"), 987, 1234), True)
        self.assertEqual(sleep.call_args_list, [mock.call(1234), mock.call(1234)])

    def test_wait_for_socket_ready_persistent_missing_raises_deadline(self):
        with mock.patch.object(self.module.time, "monotonic_ns", side_effect=[0, 0, 1234]), \
                mock.patch.object(self.module.os, "lstat", side_effect=FileNotFoundError()), \
                mock.patch.object(self.module.time, "sleep") as sleep:
            with self.assertRaisesRegex(self.module.AdapterError, "deadline"):
                self.module._wait_for_socket_ready(Path("/run/ingest.sock"), 987, 1234)
        sleep.assert_called_once_with(0.000001234)

    def test_wait_for_socket_ready_rejects_non_socket_objects_without_sleep(self):
        candidates = (
            SimpleNamespace(st_mode=stat.S_IFREG | 0o660, st_gid=987),
            SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_gid=987),
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o660, st_gid=987),
        )
        for candidate in candidates:
            with self.subTest(mode=candidate.st_mode), \
                    mock.patch.object(self.module.time, "monotonic_ns", return_value=0), \
                    mock.patch.object(self.module.os, "lstat", return_value=candidate), \
                    mock.patch.object(self.module, "_bounded_sleep") as sleep:
                with self.assertRaisesRegex(self.module.AdapterError, "readback_failure"):
                    self.module._wait_for_socket_ready(Path("/run/ingest.sock"), 987, 1234)
            sleep.assert_not_called()

    def test_wait_for_socket_ready_rejects_permission_and_other_os_errors_without_sleep(self):
        for failure in (PermissionError(), OSError("io")):
            with self.subTest(failure=type(failure)), \
                    mock.patch.object(self.module.time, "monotonic_ns", return_value=0), \
                    mock.patch.object(self.module.os, "lstat", side_effect=failure), \
                    mock.patch.object(self.module, "_bounded_sleep") as sleep:
                with self.assertRaisesRegex(self.module.AdapterError, "readback_failure"):
                    self.module._wait_for_socket_ready(Path("/run/ingest.sock"), 987, 1234)
            sleep.assert_not_called()

    def test_proc_reads_do_not_start_after_deadline_expires_during_open(self):
        for function in (self.module._proc_start_ticks, self.module._process_groups):
            with (self.subTest(function=function.__name__),
                  mock.patch.object(self.module.time, "monotonic_ns", side_effect=[0, 1]),
                  mock.patch.object(self.module.os, "open", return_value=99),
                  mock.patch.object(self.module.os, "read") as read,
                  mock.patch.object(self.module.os, "fstat") as fstat,
                  mock.patch.object(self.module.os, "close")):
                with self.assertRaisesRegex(self.module.AdapterError, "deadline"):
                    function(22, 1)
            read.assert_not_called()
            fstat.assert_not_called()

        with (mock.patch.object(self.module.time, "monotonic_ns", side_effect=[0, 1]),
              mock.patch.object(self.module.os, "open", return_value=99),
              mock.patch.object(self.module.os, "read") as read,
              mock.patch.object(self.module.os, "close")):
            with self.assertRaisesRegex(self.module.AdapterError, "deadline"):
                self.module._boot_id(1)
        read.assert_not_called()

    def test_authorized_attest_attests_all_epochs_and_discloses_account_wide_blast_radius(self):
        token = "d" * 64
        event_id = "evt_skynet_attest_" + hashlib.sha256(
            b"skynet-edr-attestation-v1\0" + token.encode("ascii")
        ).hexdigest()
        context = {"uid": 1000, "home": Path("/home/alice/.hermes"), "profile": "default",
                   "generation": "b" * 64, "ingest_gid": 987,
                   "deadline_ns": 15_000_001_000, "attestation_token": token,
                   "canary_event_id": event_id, "_hermes_launcher": self.module.HERMES}
        identities = [
            self.module.ProcessIdentity(11, 101, 1001), self.module.ProcessIdentity(21, 201, 2001),
            self.module.ProcessIdentity(31, 301, 3001), self.module.ProcessIdentity(12, 102, 1002),
            self.module.ProcessIdentity(22, 202, 2002), self.module.ProcessIdentity(32, 302, 3002),
            self.module.ProcessIdentity(12, 102, 1002), self.module.ProcessIdentity(22, 202, 2002),
            self.module.ProcessIdentity(32, 302, 3002),
            self.module.ProcessIdentity(12, 102, 1002), self.module.ProcessIdentity(22, 202, 2002),
            self.module.ProcessIdentity(32, 302, 3002),
        ]
        baseline = self._v3_source()
        advanced = self._v3_source(
            commit_sequence=5, events_persisted_total=5,
            last_persisted_canary_event_id=event_id,
            last_persisted_canary_receipt_status="persisted",
            last_persisted_canary_incidents_opened=0,
        )
        status = {"ingestion": {"state": "healthy", "listener_live": True, "sources": [advanced]}}
        prior_status = {"ingestion": {"sources": [self._v3_source(
            source_id="uid:1000:gateway:" + "b" * 64 + ":" + "c" * 64,
            runtime_instance_nonce="c" * 64, kernel_peer_pid=21, kernel_peer_start_ticks=201)]}}
        deadlines = []
        config = self.base / "config.toml"
        config.write_text(BASE_CONFIG.replace(
            "enabled = false", "enabled = true").replace(
                "allowed_uids = []", "allowed_uids = [1000]").replace(
                    "required_reported_roles = []", 'required_reported_roles = ["gateway"]'), encoding="utf-8")

        def identity(_context, _unit, deadline_ns):
            deadlines.append(deadline_ns)
            return identities.pop(0)

        def command(argv, **_kwargs):
            if argv[0] == str(self.module.HERMES):
                prompt = argv[-1]
                self.assertIn(f"SKYNET_EDR_ATTEST_V1 {event_id} {token}", prompt)
                return f"SKYNET_EDR_ATTEST_ACK_V1 {event_id}\n".encode("ascii")
            return b""

        with (mock.patch.object(self.module.time, "monotonic_ns", return_value=1_000),
              mock.patch.object(self.module, "_service_identity", side_effect=identity),
              mock.patch.object(self.module, "_old_identity_gone", return_value=True),
              mock.patch.object(self.module, "_wait_for_socket_ready", return_value=True) as socket_ready,
              mock.patch.object(self.module, "CONFIG", config),
              mock.patch.object(self.module, "_process_groups", return_value={987}),
              mock.patch.object(self.module, "_gateway_context_matches", return_value=True),
              mock.patch.object(self.module, "_wait_for_source", side_effect=[(status, baseline), (status, advanced)]),
              mock.patch.object(self.module, "_status", side_effect=[prior_status, status]) as status_readback,
              mock.patch.object(self.module, "_run", side_effect=command) as run,
              mock.patch.object(self.module, "_atomic_write") as atomic_write,
              mock.patch.object(self.module, "_plugin_enabled", return_value=True),
              mock.patch.object(self.module, "_boot_id", return_value="00000000-0000-0000-0000-000000000000"),
              mock.patch.object(self.module, "_record_attestation") as record):
            observation = self.module._restart(context)
        self.assertEqual(observation["restart_blast_radius"], "complete_user_manager")
        self.assertEqual(len(set(deadlines)), 1)
        self.assertEqual(len(deadlines), 12)
        self.assertIn([str(self.module.SYSTEMCTL), "restart", "user@1000.service"],
                      [call.args[0] for call in run.call_args_list])
        self.assertIn([str(self.module.SYSTEMCTL), "restart", self.module.DAEMON_UNIT],
                      [call.args[0] for call in run.call_args_list])
        record.assert_called_once_with(
            context, observation, 15_000_001_000, "00000000-0000-0000-0000-000000000000"
        )
        expected_dropin = self.module.render_dropin(
            [self.module.UNIT], context["generation"], context["home"], context["profile"]
        ).encode("ascii")
        self.assertEqual(atomic_write.call_args_list[-1].args[:3],
                         (self.module.DROPIN, expected_dropin, 0o644))
        self.assertEqual(
            status_readback.call_args_list,
            [mock.call(15_000_001_000, allow_disabled=True), mock.call(15_000_001_000)],
        )
        socket_ready.assert_called_once_with(self.module.SOCKET, 987, 15_000_001_000)

    def test_attestation_dropin_is_restored_when_restart_fails(self):
        token = "d" * 64
        context = {"uid": 1000, "home": Path("/home/alice/.hermes"), "profile": "default",
                   "generation": "b" * 64, "deadline_ns": 15_000_000_000,
                   "attestation_token": token,
                   "canary_event_id": "evt_skynet_attest_" + hashlib.sha256(
                       b"skynet-edr-attestation-v1\0" + token.encode("ascii")
                   ).hexdigest()}
        with (mock.patch.object(self.module, "_restart_attestation",
                                side_effect=self.module.AdapterError("deadline")),
              mock.patch.object(self.module, "_atomic_write") as atomic_write):
            with self.assertRaisesRegex(self.module.AdapterError, "deadline"):
                self.module._restart(context)
        expected_dropin = self.module.render_dropin(
            [self.module.UNIT], context["generation"], context["home"], context["profile"]
        ).encode("ascii")
        atomic_write.assert_called_once_with(self.module.DROPIN, expected_dropin, 0o644)

    def test_expired_inner_dropin_cleanup_relies_on_outer_snapshot_rollback_evidence(self):
        dropin = self.base / "50-skynet-edr.conf"
        dropin.write_text("prior-dropin\n", encoding="ascii")
        snapshot = self.module.snapshot_files({"dropin": dropin})
        token = "d" * 64
        tokenized = f"Environment=SKYNET_EDR_ATTESTATION_TOKEN={token}\n"
        dropin.write_text(tokenized, encoding="ascii")
        context = {"uid": 1000, "home": Path("/home/alice/.hermes"), "profile": "default",
                   "generation": "b" * 64, "deadline_ns": 100,
                   "attestation_token": token,
                   "canary_event_id": "evt_skynet_attest_" + "e" * 64}
        with mock.patch.object(self.module, "DROPIN", dropin), \
                mock.patch.object(self.module, "_restart_attestation",
                                  side_effect=self.module.AdapterError("hook_failure")), \
                mock.patch.object(self.module, "_atomic_write",
                                  side_effect=self.module.AdapterError("deadline")):
            with self.assertRaisesRegex(self.module.AdapterError, "deadline"):
                self.module._restart(context)
        self.assertEqual(dropin.read_text(encoding="ascii"), tokenized)

        self.module.restore_files(snapshot, {"dropin": dropin})
        self.assertEqual(dropin.read_text(encoding="ascii"), "prior-dropin\n")
        self.assertNotIn(token, dropin.read_text(encoding="ascii"))

    def test_restart_fails_closed_when_any_required_epoch_is_unchanged(self):
        token = "d" * 64
        context = {"uid": 1000, "home": Path("/home/alice/.hermes"), "profile": "default",
                   "generation": "b" * 64, "deadline_ns": 15_000_000_000,
                   "attestation_token": token,
                   "canary_event_id": "evt_skynet_attest_" + hashlib.sha256(
                       b"skynet-edr-attestation-v1\0" + token.encode("ascii")
                   ).hexdigest()}
        before = [self.module.ProcessIdentity(11, 101, 1001), self.module.ProcessIdentity(21, 201, 2001),
                  self.module.ProcessIdentity(31, 301, 3001)]
        for unchanged in range(3):
            after = [self.module.ProcessIdentity(12, 102, 1002), self.module.ProcessIdentity(22, 202, 2002),
                     self.module.ProcessIdentity(32, 302, 3002)]
            after[unchanged] = before[unchanged]
            with self.subTest(unchanged=unchanged), mock.patch.object(
                self.module.time, "monotonic_ns", return_value=0
            ), mock.patch.object(
                self.module, "_service_identity", side_effect=before + after
            ), mock.patch.object(self.module, "_status", return_value={"ingestion": {"sources": []}}), \
                    mock.patch.object(self.module, "_run", return_value=b""), \
                    mock.patch.object(self.module, "_atomic_write"):
                with self.assertRaises(self.module.AdapterError) as error:
                    self.module._restart(context)
            self.assertEqual(error.exception.category, "identity_epoch")

    def test_real_hermes_019_plugin_status_is_parsed_strictly(self):
        context = {"uid": 1000, "home": Path("/home/alice/.hermes"), "profile": "work",
                   "_hermes_launcher": self.module.HERMES}
        cases = (("enabled", True), ("not enabled", False))
        for status, expected in cases:
            payload = json.dumps([{"name": "skynet-edr", "status": status, "version": "0.4.1"}]).encode()
            with self.subTest(status=status), mock.patch.object(self.module, "_run", return_value=payload):
                self.assertIs(self.module._plugin_enabled(context), expected)
        for invalid in ("unknown", True, None):
            payload = json.dumps([{"name": "skynet-edr", "status": invalid, "version": "0.4.1"}]).encode()
            with self.subTest(invalid=invalid), mock.patch.object(self.module, "_run", return_value=payload):
                with self.assertRaises(self.module.AdapterError):
                    self.module._plugin_enabled(context)

    def test_socket_requires_both_exact_dac_and_peer_uid_authorization(self):
        path = self.base / "ingest.sock"
        server = socket.socket(socket.AF_UNIX)
        self.addCleanup(server.close)
        server.bind(str(path))
        os.chmod(path, 0o660)
        self.assertTrue(self.module.socket_dac_ok(path, os.getgid()))
        os.chmod(path, 0o600)
        self.assertFalse(self.module.socket_dac_ok(path, os.getgid()))
        self.assertFalse(self.module.authorization_ok(dac=True, configured_uids=[1001], target_uid=1002))
        self.assertFalse(self.module.authorization_ok(dac=False, configured_uids=[1002], target_uid=1002))
        self.assertTrue(self.module.authorization_ok(dac=True, configured_uids=[1002], target_uid=1002))

    def test_snapshot_restore_is_byte_exact_after_each_mutation_stage(self):
        config = self.base / "config.toml"
        dropin = self.base / "50-skynet-edr.conf"
        config.write_text(BASE_CONFIG, encoding="utf-8")
        dropin.parent.mkdir(parents=True, exist_ok=True)
        dropin.write_text("prior-dropin\n", encoding="utf-8")
        snapshot = self.module.snapshot_files({"config": config, "dropin": dropin})
        for stage in ("config", "dropin"):
            config.write_text(f"changed-{stage}\n", encoding="utf-8")
            dropin.write_text(f"changed-{stage}\n", encoding="utf-8")
            self.module.restore_files(snapshot, {"config": config, "dropin": dropin})
            self.assertEqual(config.read_text(encoding="utf-8"), BASE_CONFIG)
            self.assertEqual(dropin.read_text(encoding="utf-8"), "prior-dropin\n")

    def test_failed_initial_prepare_removes_baseline_and_scope_residue(self):
        config = self.base / "config.toml"
        config.write_text(BASE_CONFIG, encoding="utf-8")
        command = self.base / "command"
        command.write_text("safe", encoding="utf-8")
        command.chmod(0o755)
        state = self.base / "adapter-state"
        context = {
            "uid": 1000,
            "account": "alice",
            "home": Path("/home/alice/.hermes"),
            "profile": "work",
            "generation": "b" * 64,
        }
        group = SimpleNamespace(gr_mem=[], gr_gid=1000)
        patches = (
            mock.patch.object(self.module, "CONFIG", config),
            mock.patch.object(self.module, "DROPIN", self.base / "dropin" / "50-skynet-edr.conf"),
            mock.patch.object(self.module, "STATE_ROOT", state),
            mock.patch.object(self.module, "HERMES", command),
            mock.patch.object(self.module, "SYSTEMCTL", command),
            mock.patch.object(self.module, "USERMOD", command),
            mock.patch.object(self.module.grp, "getgrnam", return_value=group),
            mock.patch.object(self.module, "_plugin_enabled", side_effect=self.module.AdapterError("readback_failure")),
        )
        with contextlib.ExitStack() as stack:
            for active in patches:
                stack.enter_context(active)
            with self.assertRaises(self.module.AdapterError):
                self.module.prepare(context)
        self.assertFalse((state / "baseline.json").exists())
        self.assertFalse(self.module._scope(context).exists())
        self.assertFalse(state.exists())

    def test_bounded_json_rejects_hostile_or_oversized_child_output(self):
        marker = "FAKE_SECRET_DO_NOT_STORE_7129"
        with self.assertRaises(self.module.AdapterError) as error:
            self.module.parse_bounded_json((marker * 10000).encode())
        self.assertEqual(error.exception.category, "command_failure")
        with self.assertRaises(self.module.AdapterError):
            self.module.parse_bounded_json(b'{"enabled":true,"enabled":false}')

    def test_privileged_paths_reject_writable_ancestors(self):
        writable = self.base / "writable"
        writable.mkdir()
        writable.chmod(0o777)
        with self.assertRaises(self.module.AdapterError):
            self.module._trusted_parent(writable / "owned" / "config.toml")

    def test_all_package_lifecycles_include_the_root_owned_adapter(self):
        nfpm = (ROOT / "packaging" / "nfpm.yaml").read_text(encoding="utf-8")
        installer = (ROOT / "packaging" / "tarball" / "install.sh").read_text(encoding="utf-8")
        uninstaller = (ROOT / "packaging" / "tarball" / "uninstall.sh").read_text(encoding="utf-8")
        inspector = (ROOT / "packaging" / "scripts" / "inspect-artifacts.sh").read_text(encoding="utf-8")
        package_path = "/usr/libexec/skynet-edr/hermes-enrollment-adapter.py"
        self.assertIn(package_path, nfpm)
        self.assertIn(package_path, installer)
        self.assertIn(package_path, uninstaller)
        self.assertIn("hermes-enrollment-adapter.py", inspector)


if __name__ == "__main__":
    unittest.main()
