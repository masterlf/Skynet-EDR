import contextlib
import importlib.util
import json
import os
import socket
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
            "authenticated_uid": 1000, "runtime_role": "gateway", "protocol_version": 3,
            "s3_eligible": True, "plugin_generation": "b" * 64,
            "runtime_instance_nonce": "a" * 64, "kernel_peer_pid": 22,
            "kernel_peer_start_ticks": 202, "producer_report_age_ms": 0,
            "transport_state": "available", "backlog_bytes": 0,
            "commit_sequence": 4, "events_persisted_total": 4,
            "events_duplicate_total": 0, "events_collision_total": 0,
            "events_malformed_total": 0, "events_dropped_total": 0,
            "last_error_category": None,
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
        for sources in ([], [valid, dict(valid)],
                        [valid, self._v3_source(plugin_generation="c" * 64, kernel_peer_pid=99)]):
            with self.subTest(cardinality=len(sources)), self.assertRaises(self.module.AdapterError):
                self.module._exact_source({"sources": sources}, context, gateway)

    def test_generation_and_runtime_nonce_are_independent(self):
        context = {"uid": 1000, "generation": "b" * 64}
        gateway = self.module.ProcessIdentity(22, 202, 2002)
        with self.assertRaises(self.module.AdapterError):
            self.module._exact_source(
                {"sources": [self._v3_source(runtime_instance_nonce="b" * 64)]}, context, gateway
            )

    def test_restart_epoch_requires_a_new_runtime_nonce_when_prior_v3_identity_is_known(self):
        context = {"uid": 1000, "generation": "b" * 64}
        gateway = self.module.ProcessIdentity(21, 201, 2001)
        prior = self._v3_source(
            runtime_instance_nonce="c" * 64, kernel_peer_pid=21, kernel_peer_start_ticks=201
        )
        self.assertEqual(
            self.module._previous_runtime_nonce({"ingestion": {"sources": [prior]}}, context, gateway),
            "c" * 64,
        )
        self.assertEqual(
            self.module._previous_runtime_nonce(
                {"ingestion": {"sources": [dict(prior, plugin_generation="d" * 64)]}},
                context,
                gateway,
            ),
            "c" * 64,
        )
        with self.assertRaisesRegex(self.module.AdapterError, "source_cardinality"):
            self.module._previous_runtime_nonce(
                {"ingestion": {"sources": [prior, dict(prior)]}}, context, gateway
            )

    def test_recorded_attestation_expires_with_original_deadline_and_boot(self):
        context = {"uid": 1000, "profile": "default", "generation": "b" * 64}
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
        advanced = self._v3_source(commit_sequence=5, events_persisted_total=5)
        self.assertTrue(self.module._persisted_advanced(baseline, advanced))
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
                self.assertFalse(self.module._persisted_advanced(baseline, dict(baseline, **mutation)))

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

    def test_authorized_restart_attests_all_epochs_and_discloses_account_wide_blast_radius(self):
        context = {"uid": 1000, "home": Path("/home/alice/.hermes"), "profile": "default",
                   "generation": "b" * 64, "ingest_gid": 987}
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
        advanced = self._v3_source(commit_sequence=5, events_persisted_total=5)
        status = {"ingestion": {"state": "healthy", "listener_live": True, "sources": [advanced]}}
        prior_status = {"ingestion": {"sources": [self._v3_source(
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

        with (mock.patch.object(self.module.time, "monotonic_ns", return_value=1_000),
              mock.patch.object(self.module, "_service_identity", side_effect=identity),
              mock.patch.object(self.module, "_old_identity_gone", return_value=True),
              mock.patch.object(self.module.os, "lstat", return_value=SimpleNamespace(st_gid=987, st_mode=0o140660)),
              mock.patch.object(self.module, "CONFIG", config),
              mock.patch.object(self.module, "_process_groups", return_value={987}),
              mock.patch.object(self.module, "_gateway_context_matches", return_value=True),
              mock.patch.object(self.module, "_wait_for_source", side_effect=[(status, baseline), (status, advanced)]),
              mock.patch.object(self.module, "_status", side_effect=[prior_status, status]),
              mock.patch.object(self.module, "_run", return_value=b"") as run,
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

    def test_restart_fails_closed_when_any_required_epoch_is_unchanged(self):
        context = {"uid": 1000, "home": Path("/home/alice/.hermes"), "profile": "default",
                   "generation": "b" * 64}
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
                    mock.patch.object(self.module, "_run", return_value=b""):
                with self.assertRaises(self.module.AdapterError) as error:
                    self.module._restart(context)
            self.assertEqual(error.exception.category, "identity_epoch")

    def test_real_hermes_019_plugin_status_is_parsed_strictly(self):
        context = {"uid": 1000, "home": Path("/home/alice/.hermes"), "profile": "work"}
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
