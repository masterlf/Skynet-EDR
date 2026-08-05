import hashlib
import importlib.util
import io
import json
import os
import pwd
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "scripts" / "skynet-edr-hermes-enroll.py"


def load_module():
    spec = importlib.util.spec_from_file_location("hermes_enroll", MODULE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HermesEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.home = self.base / "home"
        self.home.mkdir(mode=0o700)
        self.source = self.base / "payload"
        self.source.mkdir()
        files = {
            "plugin.yaml": b'name: skynet-edr\nversion: "0.4.1"\n',
            "__init__.py": b'PLUGIN_VERSION = "0.4.1"\n',
            "README.md": b"safe\n",
            "dashboard/manifest.json": b'{"version":"0.4.1"}\n',
            "dashboard/plugin.js": b"safe\n",
            "dashboard/plugin_api.py": b"safe\n",
            "desktop/plugin.js": b"safe\n",
        }
        for relative, data in files.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.manifest = {
            rel: {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "mode": 0o644,
                "owner": os.getuid(),
            }
            for rel, data in files.items()
        }
        self.request = {
            "account": pwd.getpwuid(os.getuid()).pw_name,
            "uid": os.getuid(),
            "allow_root": os.getuid() == 0,
            "hermes_home": str(self.home),
            "profile": "fixture-profile",
            "host": {"id": "ubuntu", "version": "24.04", "arch": "x86_64", "init": "systemd"},
            "hermes_version": "0.19.0",
            "payload_version": "0.4.1",
            "manifest": self.manifest,
            "fixture": True,
            "socket": {"dac": True, "uid_authorized": True},
            "required_role": "gateway",
            "units": ["hermes-gateway.service"],
            "restart_authorized": True,
        }
        self.request["manifest_sha256"] = hashlib.sha256(
            json.dumps(self.manifest, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        self.obs = {
            "plugin_enabled": False,
            "loaded_generation": None,
            "process_fresh": False,
            "daemon": {"healthy": False, "listener": True, "transport": "available", "backlog": 0, "degraded": False},
            "producer": {"uid": os.getuid(), "role": "gateway", "fresh": False},
            "real_hook": {"correlated": False, "committed": False, "incident_opened": False},
        }
        self.request_path = self.base / "request.json"
        self.obs_path = self.base / "observations.json"
        self.state = self.base / "state"
        self._write_inputs()

    def _write_inputs(self):
        self.request_path.write_text(json.dumps(self.request), encoding="utf-8")
        self.obs_path.write_text(json.dumps(self.obs), encoding="utf-8")

    def run_cli(self, verb, *extra):
        harness = (
            "import importlib.util,sys;"
            f"s=importlib.util.spec_from_file_location('hermes_enroll',{str(MODULE)!r});"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            "raise SystemExit(m.main(test_mode=True))"
        )
        result = subprocess.run(
            ["python3", "-c", harness, verb, "--request", str(self.request_path), "--source", str(self.source),
             "--state-root", str(self.state), "--observations", str(self.obs_path), *extra],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        return result, json.loads(result.stdout)

    def test_shipped_entrypoint_rejects_fixture_and_caller_selected_roots(self):
        result = subprocess.run(
            ["python3", str(MODULE), "verify", "--request", str(self.request_path), "--source", str(self.source),
             "--state-root", str(self.state), "--observations", str(self.obs_path)],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        output = json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output["category"], "untrusted_runtime")

    def test_nonfixture_payload_identity_comes_from_package_manifest(self):
        module = load_module()
        package_manifest = self.base / "manifest.json"
        package_manifest.write_text(json.dumps({
            "schema": 1,
            "payload_version": "0.4.1",
            "generation": self.request["manifest_sha256"],
            "files": self.manifest,
        }), encoding="utf-8")
        package_manifest.chmod(0o644)
        setattr(module, "SYSTEM_SOURCE", self.source)
        setattr(module, "SYSTEM_MANIFEST", package_manifest)
        request = dict(self.request)
        request["fixture"] = False
        request["manifest"] = {"attacker": {}}
        request["manifest_sha256"] = "0" * 64
        canonical_home = self.base / ".hermes"
        canonical_home.mkdir(mode=0o700)
        request["hermes_home"] = str(canonical_home)
        request["profile"] = "default"
        account = SimpleNamespace(pw_name=request["account"], pw_dir=str(self.base), pw_gid=os.getgid())
        with mock.patch.object(module.pwd, "getpwuid", return_value=account):
            _, _, _, actual = module.validate_request(request, self.source)
        self.assertEqual(actual, self.manifest)

    def test_nonfixture_custom_profile_is_unsupported(self):
        module = load_module()
        request = dict(self.request)
        request["fixture"] = False
        request["hermes_home"] = str(self.base / ".hermes")
        request["profile"] = "work"
        account = SimpleNamespace(pw_name=request["account"], pw_dir=str(self.base), pw_gid=os.getgid())
        with mock.patch.object(module.pwd, "getpwuid", return_value=account):
            with self.assertRaises(module.EnrollmentError) as error:
                module.validate_request(request, self.source)
        self.assertEqual(error.exception.category, "unsupported_contract")

    def test_missing_canonical_home_fails_with_bounded_json_without_mutation(self):
        module = load_module()
        package_manifest = self.base / "manifest.json"
        package_manifest.write_text(json.dumps({
            "schema": 1,
            "payload_version": "0.4.1",
            "generation": self.request["manifest_sha256"],
            "files": self.manifest,
        }), encoding="utf-8")
        package_manifest.chmod(0o644)
        account_home = self.base / "missing-account-home"
        canonical_home = account_home / ".hermes"
        request = dict(self.request)
        request["fixture"] = False
        request["hermes_home"] = str(canonical_home)
        request["profile"] = "default"
        self.request_path.write_text(json.dumps(request), encoding="utf-8")
        account = SimpleNamespace(pw_name=request["account"], pw_dir=str(account_home), pw_gid=os.getgid())
        arguments = [
            str(MODULE), "check", "--request", str(self.request_path), "--source", str(self.source),
            "--state-root", str(self.state), "--observations", str(self.obs_path),
        ]
        output = io.StringIO()
        errors = io.StringIO()
        with (mock.patch.object(module, "SYSTEM_SOURCE", self.source),
              mock.patch.object(module, "SYSTEM_MANIFEST", package_manifest),
              mock.patch.object(module.pwd, "getpwuid", return_value=account),
              mock.patch.object(module.sys, "argv", arguments),
              mock.patch.object(module.sys, "stdout", output),
              mock.patch.object(module.sys, "stderr", errors)):
            result = module.main(test_mode=True)

        lines = output.getvalue().splitlines()
        self.assertNotEqual(result, 0)
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0]), {
            "schema": 1, "state": "DRIFTED", "category": "invalid_target", "noop": False,
        })
        combined = output.getvalue() + errors.getvalue()
        self.assertNotIn(str(account_home), combined)
        self.assertNotIn(str(canonical_home), combined)
        self.assertNotIn("Traceback", combined)
        self.assertFalse(account_home.exists())
        self.assertFalse(self.state.exists())

    def make_adapter(self, enabled=True, healthy=True, home=None, profile="fixture-profile", fail_action=None,
                     require_payload_before_prepare=False):
        home = self.home if home is None else home
        adapter = self.base / "adapter.py"
        adapter.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            f"if sys.argv[1] == {fail_action!r}: raise SystemExit(9)\n"
            "assert os.environ['HERMES_HOME']==" + repr(str(home)) + "\n"
            "assert os.environ['HERMES_PROFILE']==" + repr(profile) + "\n"
            + ("if sys.argv[1]=='prepare': assert os.path.isfile(os.path.join(os.environ['HERMES_HOME'],'plugins','skynet-edr','plugin.yaml'))\n"
               if require_payload_before_prepare else "") +
            "o={'plugin_enabled':False,'loaded_generation':None,'process_fresh':False,"
            "'daemon':{'healthy':False,'listener':True,'transport':'available','backlog':0,'degraded':False},"
            "'producer':{'uid':int(os.environ['SKYNET_EDR_TARGET_UID']),'role':'gateway','fresh':False},"
            "'real_hook':{'correlated':False,'committed':False,'incident_opened':False}}\n"
            "if sys.argv[1]=='enable':\n"
            f" o['plugin_enabled']={enabled!r}\n"
            " o['loaded_generation']=os.environ['SKYNET_EDR_GENERATION']\n"
            "elif sys.argv[1]=='disable': o['plugin_enabled']=False\n"
            "elif sys.argv[1]=='restart':\n"
            f" o['plugin_enabled']=True; o['loaded_generation']=os.environ['SKYNET_EDR_GENERATION']; o['process_fresh']={healthy!r}; o['producer']['fresh']={healthy!r}; o['daemon']['healthy']={healthy!r}\n"
            "elif sys.argv[1]=='hook':\n"
            f" o['plugin_enabled']=True; o['loaded_generation']=os.environ['SKYNET_EDR_GENERATION']; o['process_fresh']={healthy!r}; o['producer']['fresh']={healthy!r}; o['daemon']['healthy']={healthy!r}; o['real_hook']={{'correlated':True,'committed':True,'incident_opened':False}}\n"
            "o['adapter_euid']=os.geteuid()\n"
            "print(json.dumps(o))\n",
            encoding="utf-8",
        )
        adapter.chmod(0o700)
        return str(adapter)

    def test_prepare_observes_staged_payload_and_no_restart_returns_reload_required(self):
        self.request["restart_authorized"] = False
        self._write_inputs()
        adapter = self.make_adapter(require_payload_before_prepare=True)
        result, output = self.run_cli("apply", "--adapter", adapter)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output["state"], "RELOAD_REQUIRED")

    def test_split_filesystem_is_rejected_before_any_mutation(self):
        module = load_module()
        state = self.base / "new-state-root"
        adapter = Path(self.make_adapter())
        original_stat = module.os.stat

        def split_stat(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            device = 2 if Path(path) == self.home or str(path).startswith("/proc/self/fd/") else 1
            return SimpleNamespace(**{
                name: getattr(info, name)
                for name in ("st_mode", "st_ino", "st_uid", "st_gid", "st_nlink")
            }, st_dev=device)

        with mock.patch.object(module.os, "stat", side_effect=split_stat):
            with self.assertRaises(module.EnrollmentError) as error:
                module.apply(self.request, self.source, state, self.obs_path, adapter)
        self.assertEqual(error.exception.category, "unsupported_layout")
        self.assertFalse(state.exists())
        self.assertFalse((self.home / "plugins").exists())
        self.assertFalse((self.home / "desktop-plugins").exists())

    def test_symlinked_plugin_parents_cannot_pivot_privileged_writes(self):
        outside = self.base / "outside"
        outside.mkdir()
        marker = outside / "keep"
        marker.write_text("unchanged", encoding="utf-8")
        for parent_name in ("plugins", "desktop-plugins"):
            with self.subTest(parent=parent_name):
                candidate = self.home / parent_name
                candidate.symlink_to(outside, target_is_directory=True)
                check_result, check_output = self.run_cli("check")
                self.assertNotEqual(check_result.returncode, 0)
                self.assertEqual(check_output["category"], "invalid_target")
                result, output = self.run_cli("apply", "--adapter", self.make_adapter())
                self.assertNotEqual(result.returncode, 0)
                self.assertNotEqual(output["state"], "ENROLLED")
                self.assertTrue(candidate.is_symlink())
                self.assertEqual(marker.read_text(encoding="utf-8"), "unchanged")
                self.assertFalse((outside / "skynet-edr").exists())
                candidate.unlink()

    def test_special_or_hardlinked_plugin_parents_are_rejected(self):
        source_file = self.base / "linked-parent"
        source_file.write_text("do not follow", encoding="utf-8")
        for parent_name, hardlink in (("plugins", False), ("desktop-plugins", True)):
            with self.subTest(parent=parent_name):
                candidate = self.home / parent_name
                if hardlink:
                    os.link(source_file, candidate)
                else:
                    candidate.write_text("special-like non-directory", encoding="utf-8")
                result, output = self.run_cli("apply", "--adapter", self.make_adapter())
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output["category"], "invalid_target")
                self.assertEqual(source_file.read_text(encoding="utf-8"), "do not follow")
                candidate.unlink()

    def test_check_is_side_effect_free_and_absent_is_nonzero(self):
        before = self.obs_path.read_bytes()
        result, output = self.run_cli("check")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output["state"], "ABSENT")
        self.assertEqual(before, self.obs_path.read_bytes())
        self.assertFalse(self.state.exists())

    def test_apply_then_verify_enrolled_and_second_apply_is_noop(self):
        adapter = self.make_adapter()
        result, output = self.run_cli("apply", "--adapter", adapter)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output["state"], "ENROLLED")
        target = self.home / "plugins" / "skynet-edr"
        before = {p.relative_to(target): (p.stat().st_mtime_ns, p.read_bytes()) for p in target.rglob("*") if p.is_file()}
        result, output = self.run_cli("apply", "--adapter", adapter)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output["noop"])
        after = {p.relative_to(target): (p.stat().st_mtime_ns, p.read_bytes()) for p in target.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_stale_unchanged_observation_cannot_enroll(self):
        generation = hashlib.sha256(
            json.dumps(self.manifest, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        self.obs.update({
            "plugin_enabled": True,
            "loaded_generation": generation,
            "process_fresh": True,
            "daemon": {"healthy": True, "listener": True, "transport": "available", "backlog": 0, "degraded": False},
            "producer": {"uid": os.getuid(), "role": "gateway", "fresh": True},
            "real_hook": {"correlated": True, "committed": True, "incident_opened": False},
        })
        self._write_inputs()
        before = self.obs_path.read_bytes()
        adapter = self.base / "noop.py"
        adapter.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        adapter.chmod(0o700)
        result, output = self.run_cli("apply", "--adapter", str(adapter))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(output["state"], "ENROLLED")
        self.assertEqual(before, self.obs_path.read_bytes())

    def test_failed_reapply_restores_prior_metadata_and_generation(self):
        adapter = self.make_adapter()
        result, _ = self.run_cli("apply", "--adapter", adapter)
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata_before = (self.state / "enrollment.json").read_bytes()
        target = self.home / "plugins" / "skynet-edr"
        bytes_before = {p.relative_to(target): p.read_bytes() for p in target.rglob("*") if p.is_file()}

        self.obs = json.loads(self.obs_path.read_text(encoding="utf-8"))
        self.obs["daemon"]["degraded"] = True
        self._write_inputs()
        result, output = self.run_cli("apply", "--adapter", self.make_adapter(enabled=False))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(output["state"], {"DRIFTED", "ROLLBACK_REQUIRED"})
        self.assertEqual(metadata_before, (self.state / "enrollment.json").read_bytes())
        self.assertEqual(bytes_before, {p.relative_to(target): p.read_bytes() for p in target.rglob("*") if p.is_file()})

    def test_desktop_companion_is_transactional(self):
        adapter = self.make_adapter()
        result, _ = self.run_cli("apply", "--adapter", adapter)
        self.assertEqual(result.returncode, 0, result.stderr)
        desktop = self.home / "desktop-plugins" / "skynet-edr" / "plugin.js"
        self.assertEqual(desktop.read_bytes(), (self.source / "desktop" / "plugin.js").read_bytes())
        result, _ = self.run_cli("unenroll", "--adapter", adapter)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(desktop.exists())

    def test_custom_home_and_profile_are_passed_to_every_adapter_action(self):
        result, output = self.run_cli("apply", "--adapter", self.make_adapter())
        self.assertEqual(result.returncode, 0, (result.stderr, output))

    def test_runtime_state_and_nonce_are_isolated_by_uid_and_profile(self):
        module = load_module()
        first = module.scoped_runtime_state(self.state, 1001, "work")
        second = module.scoped_runtime_state(self.state, 1001, "personal")
        third = module.scoped_runtime_state(self.state, 1002, "work")
        self.assertEqual(len({first, second, third}), 3)
        self.assertEqual(module.enrollment_lock(first), module.enrollment_lock(second))

    def test_metadata_identity_mismatch_fails_closed(self):
        result, _ = self.run_cli("apply", "--adapter", self.make_adapter())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.request["profile"] = "other-profile"
        self._write_inputs()
        result, output = self.run_cli("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output["state"], "DRIFTED")

    @unittest.skipUnless(os.geteuid() == 0, "requires root to prove credential drop")
    def test_target_cli_actions_drop_identity_but_privileged_actions_remain_root(self):
        target = pwd.getpwnam("nobody")
        accessible = Path(tempfile.mkdtemp(prefix="skynet-hermes-target-", dir="/var/tmp"))
        self.addCleanup(shutil.rmtree, accessible, True)
        accessible.chmod(0o755)
        target_home = accessible / "home"
        target_home.mkdir(mode=0o700)
        os.chown(target_home, target.pw_uid, target.pw_gid)
        self.request.update({
            "account": target.pw_name,
            "uid": target.pw_uid,
            "allow_root": False,
            "hermes_home": str(target_home),
            "profile": "target-profile",
        })
        self.obs["producer"]["uid"] = target.pw_uid
        self._write_inputs()
        adapter = accessible / "adapter.py"
        action_log = accessible / "adapter-actions.jsonl"
        action_log.touch(mode=0o666)
        action_log.chmod(0o666)
        adapter.write_text(
            "import json,os,sys\n"
            f"open({str(action_log)!r},'a').write(json.dumps([sys.argv[1],os.geteuid()])+'\\n')\n"
            "healthy=sys.argv[1] in {'restart','hook'}\n"
            "print(json.dumps({'plugin_enabled':sys.argv[1]!='disable','loaded_generation':os.environ['SKYNET_EDR_GENERATION'],"
            "'process_fresh':healthy,'daemon':{'healthy':healthy,'listener':True,'transport':'available','backlog':0,'degraded':False},"
            "'producer':{'uid':int(os.environ['SKYNET_EDR_TARGET_UID']),'role':'gateway','fresh':healthy},"
            "'real_hook':{'correlated':sys.argv[1]=='hook','committed':sys.argv[1]=='hook','incident_opened':False},"
            "'adapter_euid':os.geteuid()}))\n",
            encoding="utf-8",
        )
        adapter.chmod(0o755)
        result, output = self.run_cli("apply", "--adapter", str(adapter))
        self.assertEqual(result.returncode, 0, (result.stderr, output))
        installed = target_home / "plugins" / "skynet-edr"
        self.assertTrue(all(path.stat().st_uid == target.pw_uid for path in installed.rglob("*") if path.is_file()))
        self.assertEqual((target_home / "desktop-plugins" / "skynet-edr" / "plugin.js").stat().st_uid, target.pw_uid)
        observation = json.loads(self.obs_path.read_text(encoding="utf-8"))
        self.assertEqual(observation["adapter_euid"], 0)
        actions = {action: euid for action, euid in map(json.loads, action_log.read_text(encoding="utf-8").splitlines())}
        self.assertEqual(actions["enable"], target.pw_uid)
        self.assertEqual(actions["restart"], 0)
        self.assertEqual(actions["hook"], 0)

    def test_enable_zero_without_readback_fails_closed_and_rolls_back(self):
        result, output = self.run_cli("apply", "--adapter", self.make_adapter(enabled=False))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(output["state"], {"DRIFTED", "ROLLBACK_REQUIRED"})
        self.assertFalse((self.home / "plugins" / "skynet-edr").exists())

    def test_each_adapter_mutation_failure_restores_bytes_and_metadata(self):
        for action in ("prepare", "enable", "restart", "hook"):
            with self.subTest(action=action):
                self.setUp()
                result, output = self.run_cli("apply", "--adapter", self.make_adapter(fail_action=action))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(output["state"], {"DRIFTED", "ROLLBACK_REQUIRED"})
                self.assertFalse((self.home / "plugins" / "skynet-edr").exists())
                self.assertFalse((self.state / "enrollment.json").exists())

    def test_failed_initial_prepare_restores_exact_zero_residue_baseline(self):
        self.obs_path.unlink()
        adapter = self.make_adapter(fail_action="prepare")
        result, output = self.run_cli("apply", "--adapter", adapter)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output["category"], "adapter_failure")
        self.assertFalse(self.state.exists())
        self.assertFalse(self.obs_path.exists())
        self.assertFalse((self.home / "plugins").exists())
        self.assertFalse((self.home / "desktop-plugins").exists())

    def test_failed_prepare_preserves_parent_created_in_check_mkdir_race(self):
        for parent_name in ("plugins", "desktop-plugins"):
            with self.subTest(parent=parent_name):
                self.setUp()
                module = load_module()
                adapter = Path(self.make_adapter(fail_action="prepare"))
                original_mkdir = module.os.mkdir
                raced = False

                def create_before_transaction_mkdir(path, mode=0o777, *, dir_fd=None):
                    nonlocal raced
                    if path == parent_name and dir_fd is not None and not raced:
                        original_mkdir(path, mode=0o700, dir_fd=dir_fd)
                        raced = True
                    return original_mkdir(path, mode=mode, dir_fd=dir_fd)

                output = io.StringIO()
                with (mock.patch.object(module.os, "mkdir", side_effect=create_before_transaction_mkdir),
                      mock.patch.object(module.sys, "stdout", output)):
                    result = module.apply(self.request, self.source, self.state, self.obs_path, adapter)

                self.assertNotEqual(result, 0)
                self.assertTrue(raced)
                self.assertTrue((self.home / parent_name).is_dir())

    def test_failed_prepare_preserves_preexisting_plugin_parents(self):
        parents = [self.home / name for name in ("plugins", "desktop-plugins")]
        for parent in parents:
            parent.mkdir(mode=0o700)

        result, _ = self.run_cli("apply", "--adapter", self.make_adapter(fail_action="prepare"))

        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(all(parent.is_dir() for parent in parents))

    def test_created_parent_inode_mismatch_fails_closed_without_removal(self):
        module = load_module()
        parent = self.home / "plugins"
        parent.mkdir(mode=0o700)
        pinned_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, pinned_fd)
        original = os.fstat(pinned_fd)
        parent.rmdir()
        parent.mkdir(mode=0o700)

        with self.assertRaises(module.EnrollmentError) as error:
            module.remove_empty_user_directory(
                self.home, "plugins", os.getuid(), (original.st_dev, original.st_ino)
            )

        self.assertEqual(error.exception.state, "ROLLBACK_REQUIRED")
        self.assertTrue(parent.is_dir())

    def test_created_parent_replaced_before_open_is_not_booked_or_chowned(self):
        module = load_module()
        parent = self.home / "plugins"
        original_open = module.os.open
        replacement_identity = None
        displaced_fd = None

        def replace_before_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal displaced_fd, replacement_identity
            if path == "plugins" and dir_fd is not None and replacement_identity is None:
                displaced_fd = original_open(
                    path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd
                )
                os.rmdir(path, dir_fd=dir_fd)
                os.mkdir(path, mode=0o700, dir_fd=dir_fd)
                replacement = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
                replacement_identity = replacement.st_dev, replacement.st_ino
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(module.os, "open", side_effect=replace_before_open):
            with self.assertRaises(module.EnrollmentError) as error:
                with module.opened_user_directory(
                    self.home, "plugins", os.getuid(), os.getgid(), create=True
                ):
                    self.fail("replacement must not be yielded as transaction-created")

        self.assertEqual(error.exception.category, "invalid_target")
        self.assertEqual((parent.stat().st_dev, parent.stat().st_ino), replacement_identity)
        assert displaced_fd is not None
        os.close(displaced_fd)

    def test_created_nonempty_parent_fails_closed_without_removal(self):
        module = load_module()
        parent = self.home / "plugins"
        parent.mkdir(mode=0o700)
        identity = parent.stat().st_dev, parent.stat().st_ino
        marker = parent / "target-owned"
        marker.write_text("preserve", encoding="utf-8")

        with self.assertRaises(module.EnrollmentError) as error:
            module.remove_empty_user_directory(self.home, "plugins", os.getuid(), identity)

        self.assertEqual(error.exception.state, "ROLLBACK_REQUIRED")
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_created_parent_mode_drift_fails_closed_without_removal(self):
        module = load_module()
        parent = self.home / "plugins"
        parent.mkdir(mode=0o700)
        identity = parent.stat().st_dev, parent.stat().st_ino
        parent.chmod(0o750)

        with self.assertRaises(module.EnrollmentError) as error:
            module.remove_empty_user_directory(self.home, "plugins", os.getuid(), identity)

        self.assertEqual(error.exception.state, "ROLLBACK_REQUIRED")
        self.assertTrue(parent.is_dir())

    def test_failed_initial_prepare_preserves_preexisting_state_and_observation(self):
        self.state.mkdir()
        evidence = self.state / "evidence.log"
        evidence.write_text("preserve", encoding="utf-8")
        observation = self.obs_path.read_bytes()
        adapter = self.make_adapter(fail_action="prepare")
        result, _ = self.run_cli("apply", "--adapter", adapter)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(evidence.read_text(encoding="utf-8"), "preserve")
        self.assertEqual(self.obs_path.read_bytes(), observation)

    def test_synthetic_canary_is_not_real_hook_proof(self):
        result, _ = self.run_cli("apply", "--adapter", self.make_adapter())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.obs = json.loads(self.obs_path.read_text(encoding="utf-8"))
        self.obs["real_hook"] = {"correlated": False, "committed": False, "incident_opened": False}
        self.obs["synthetic_canary"] = True
        self._write_inputs()
        result, output = self.run_cli("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output["state"], "DEGRADED")

    def test_unsupported_platform_and_hermes_version_fail_closed(self):
        for key, value in (("host", {"id": "debian", "version": "12", "arch": "x86_64", "init": "systemd"}),
                           ("hermes_version", "0.20.0")):
            original = self.request[key]
            self.request[key] = value
            self._write_inputs()
            result, output = self.run_cli("check")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output["category"], "unsupported_contract")
            self.request[key] = original

    def test_hostile_paths_symlinks_and_manifest_drift_are_rejected(self):
        self.request["hermes_home"] = "../relative"
        self._write_inputs()
        result, output = self.run_cli("check")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output["category"], "invalid_input")
        self.request["hermes_home"] = str(self.home)
        (self.source / "plugin.yaml").write_text("tampered", encoding="utf-8")
        self._write_inputs()
        result, output = self.run_cli("check")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output["category"], "payload_identity")

    def test_source_symlink_and_hardlink_ambiguity_are_rejected(self):
        original = self.source / "README.md"
        linked = self.source / "desktop" / "plugin.js"
        linked.unlink()
        os.link(original, linked)
        self.manifest["desktop/plugin.js"]["sha256"] = hashlib.sha256(original.read_bytes()).hexdigest()
        self.manifest["desktop/plugin.js"]["size"] = original.stat().st_size
        self._write_inputs()
        result, output = self.run_cli("check")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output["category"], "payload_identity")

    def test_dac_uid_role_and_health_matrices_fail_closed(self):
        cases = [
            (lambda: self.request["socket"].update(dac=False), "authorization"),
            (lambda: self.request["socket"].update(uid_authorized=False), "authorization"),
            (lambda: self.obs["producer"].update(role="dashboard"), "producer_health"),
            (lambda: self.obs["daemon"].update(backlog=1), "producer_health"),
            (lambda: self.obs["daemon"].update(degraded=True), "producer_health"),
        ]
        for mutate, category in cases:
            self.setUp()
            result, _ = self.run_cli("apply", "--adapter", self.make_adapter())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.obs = json.loads(self.obs_path.read_text(encoding="utf-8"))
            mutate()
            self._write_inputs()
            result, output = self.run_cli("verify")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output["category"], category)

    def test_reload_required_without_authorization(self):
        self.request["restart_authorized"] = False
        self._write_inputs()
        adapter = self.make_adapter()
        result, output = self.run_cli("apply", "--adapter", adapter)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output["state"], "RELOAD_REQUIRED")
        result, output = self.run_cli("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output["state"], "RELOAD_REQUIRED")
        self.request["restart_authorized"] = True
        self._write_inputs()
        result, output = self.run_cli("apply", "--adapter", adapter)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output["state"], "ENROLLED")

    def test_unenroll_is_repeatable_preserves_evidence_and_other_profile(self):
        adapter = self.make_adapter()
        result, _ = self.run_cli("apply", "--adapter", adapter)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = self.state / "evidence" / "keep.log"
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text("fixed-category-only", encoding="utf-8")
        other = self.home / "plugins" / "other"
        other.mkdir()
        result, output = self.run_cli("unenroll", "--adapter", adapter)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output["state"], "ABSENT")
        self.assertTrue(evidence.exists())
        self.assertTrue(other.exists())
        result, output = self.run_cli("unenroll", "--adapter", adapter)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(output["noop"])

    def test_concurrent_apply_serializes_to_one_mutation(self):
        adapter = self.make_adapter()
        outputs = []
        def run():
            outputs.append(self.run_cli("apply", "--adapter", adapter))
        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertTrue(all(result.returncode == 0 for result, _ in outputs), outputs)
        self.assertEqual(sum(bool(output.get("noop")) for _, output in outputs), 1)

    def test_hostile_adapter_diagnostics_and_fake_secret_are_sanitized(self):
        marker = "FAKE_SECRET_DO_NOT_STORE_7b91"
        adapter = self.base / "bad.py"
        adapter.write_text(f"#!/usr/bin/env python3\nimport sys\nprint('{marker}', file=sys.stderr)\nsys.exit(9)\n", encoding="utf-8")
        adapter.chmod(0o700)
        result, output = self.run_cli("apply", "--adapter", str(adapter))
        combined = result.stdout + result.stderr
        self.assertNotIn(marker, combined)
        self.assertEqual(output["category"], "rollback")

    def test_all_package_formats_and_tarball_require_python_runtime(self):
        nfpm = (ROOT / "packaging" / "nfpm.yaml").read_text(encoding="utf-8")
        self.assertIn("deb:\n    depends:\n      - systemd\n      - python3", nfpm)
        self.assertIn("rpm:\n    depends:\n      - systemd\n      - python3", nfpm)
        self.assertIn("archlinux:\n    depends:\n      - systemd\n      - python", nfpm)
        installer = (ROOT / "packaging" / "tarball" / "install.sh").read_text(encoding="utf-8")
        self.assertIn("command -v python3", installer)


if __name__ == "__main__":
    unittest.main()
