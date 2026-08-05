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
             f"Environment=SKYNET_EDR_RUNTIME_INSTANCE={generation}\n"
             "Environment=HERMES_HOME=%h/.hermes\n"
             "Environment=HERMES_PROFILE=default\n"),
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
        self.assertNotIn("_SKYNET_EDR_HOME_FD", environment)

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
