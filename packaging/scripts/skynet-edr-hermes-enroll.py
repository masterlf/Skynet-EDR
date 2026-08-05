#!/usr/bin/env python3
"""Fail-closed, transactional Hermes enrollment for the bounded S3 contract.

External service and Hermes operations are performed by one reviewed adapter
executable. Adapter output is never forwarded. Every invocation receives the
selected HERMES_HOME/profile and the expected generation in a minimal
environment; success is accepted only after fresh observation-file read-back.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ALLOWED_FILES = (
    "plugin.yaml",
    "__init__.py",
    "README.md",
    "dashboard/manifest.json",
    "dashboard/plugin.js",
    "dashboard/plugin_api.py",
    "desktop/plugin.js",
)
SUPPORTED_HOST = {"id": "ubuntu", "version": "24.04", "arch": "x86_64", "init": "systemd"}
SUPPORTED_HERMES = {"0.19.0"}
SYSTEM_SOURCE = Path("/usr/share/skynet-edr/hermes-plugin/skynet-edr")
SYSTEM_MANIFEST = SYSTEM_SOURCE.parent / "manifest.json"
SYSTEM_STATE_ROOT = Path("/var/lib/skynet-edr-hermes-enrollment")
SYSTEM_OBSERVATIONS = SYSTEM_STATE_ROOT / "observations.json"
SYSTEM_ADAPTER = Path("/usr/libexec/skynet-edr/hermes-enrollment-adapter.py")
MAX_PAYLOAD_FILE = 8 * 1024 * 1024
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
REVIEWED_UNITS = ["hermes-gateway.service"]


class EnrollmentError(Exception):
    def __init__(self, category: str, state: str = "DRIFTED") -> None:
        super().__init__(category)
        self.category = category
        self.state = state


def emit(state: str, category: str, *, noop: bool = False, success: bool = False) -> int:
    print(json.dumps({"schema": 1, "state": state, "category": category, "noop": noop}, sort_keys=True))
    return 0 if state == "ENROLLED" or success else 1


def load_json(path: Path, category: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnrollmentError(category) from exc
    if not isinstance(value, dict):
        raise EnrollmentError(category)
    return value


def canonical_generation(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()


def checked_absolute(value: Any, category: str) -> Path:
    if not isinstance(value, str) or not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise EnrollmentError(category)
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or str(path) == "/":
        raise EnrollmentError(category)
    return path


def check_existing_path(path: Path, uid: int, *, writable_leaf: bool) -> None:
    current = Path("/")
    parts = path.parts[1:]
    for index, component in enumerate(parts):
        current /= component
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise EnrollmentError("invalid_input")
        is_leaf = index == len(parts) - 1
        if is_leaf and writable_leaf:
            if info.st_uid != uid or info.st_mode & 0o077:
                raise EnrollmentError("ownership")
        elif info.st_mode & 0o022 and not (info.st_mode & stat.S_ISVTX and info.st_uid == 0):
            raise EnrollmentError("untrusted_ancestor")


def validate_request(request: dict[str, Any], source: Path) -> tuple[int, Path, str, dict[str, Any]]:
    try:
        uid = int(request["uid"])
    except (KeyError, TypeError, ValueError) as exc:
        raise EnrollmentError("invalid_input") from exc
    account = request.get("account")
    try:
        resolved = pwd.getpwuid(uid)
    except KeyError as exc:
        raise EnrollmentError("identity") from exc
    if account != resolved.pw_name or not isinstance(account, str) or not SAFE_NAME.fullmatch(account):
        raise EnrollmentError("identity")
    if uid == 0 and request.get("allow_root") is not True:
        raise EnrollmentError("root_denied")
    home = checked_absolute(request.get("hermes_home"), "invalid_input")
    check_existing_path(home, uid, writable_leaf=True)
    profile = request.get("profile")
    if not isinstance(profile, str) or not SAFE_NAME.fullmatch(profile):
        raise EnrollmentError("invalid_input")
    if request.get("host") != SUPPORTED_HOST or request.get("hermes_version") not in SUPPORTED_HERMES:
        raise EnrollmentError("unsupported_contract")
    if request.get("payload_version") != "0.4.1":
        raise EnrollmentError("unsupported_contract")
    socket = request.get("socket")
    if not isinstance(socket, dict) or socket.get("dac") is not True or socket.get("uid_authorized") is not True:
        raise EnrollmentError("authorization")
    if request.get("required_role") != "gateway":
        raise EnrollmentError("authorization")
    units = request.get("units")
    if units != REVIEWED_UNITS:
        raise EnrollmentError("invalid_input")
    source = checked_absolute(str(source), "payload_identity")
    check_existing_path(source, uid, writable_leaf=False)
    if request.get("fixture") is True:
        manifest = request.get("manifest")
        expected_generation = request.get("manifest_sha256")
    else:
        if source != SYSTEM_SOURCE:
            raise EnrollmentError("payload_identity")
        try:
            manifest_info = os.lstat(SYSTEM_MANIFEST)
        except OSError as exc:
            raise EnrollmentError("payload_identity") from exc
        if (not stat.S_ISREG(manifest_info.st_mode) or manifest_info.st_nlink != 1 or manifest_info.st_uid != 0
                or manifest_info.st_mode & 0o022):
            raise EnrollmentError("payload_identity")
        package_manifest = load_json(SYSTEM_MANIFEST, "payload_identity")
        if package_manifest.get("schema") != 1 or package_manifest.get("payload_version") != "0.4.1":
            raise EnrollmentError("payload_identity")
        manifest = package_manifest.get("files")
        expected_generation = package_manifest.get("generation")
    if not isinstance(manifest, dict) or set(manifest) != set(ALLOWED_FILES):
        raise EnrollmentError("payload_identity")
    if expected_generation != canonical_generation(manifest):
        raise EnrollmentError("payload_identity")
    validate_tree(source, manifest)
    return uid, home, profile, manifest


def validate_tree(root: Path, manifest: dict[str, Any], *, installed_owner: int | None = None) -> None:
    try:
        actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file() or path.is_symlink()}
    except OSError as exc:
        raise EnrollmentError("payload_identity") from exc
    if actual != set(ALLOWED_FILES):
        raise EnrollmentError("payload_identity")
    for relative in ALLOWED_FILES:
        path = root / relative
        try:
            before = os.lstat(path)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise EnrollmentError("payload_identity")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                digest = hashlib.sha256()
                length = 0
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    length += len(chunk)
                    if length > MAX_PAYLOAD_FILE:
                        raise EnrollmentError("payload_identity")
                    digest.update(chunk)
                after = os.fstat(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise EnrollmentError("payload_identity") from exc
        expected = manifest.get(relative)
        if not isinstance(expected, dict):
            raise EnrollmentError("payload_identity")
        if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
            raise EnrollmentError("payload_identity")
        if length != expected.get("size") or digest.hexdigest() != expected.get("sha256"):
            raise EnrollmentError("payload_identity")
        if expected.get("mode") != 0o644 or stat.S_IMODE(before.st_mode) != expected.get("mode"):
            raise EnrollmentError("payload_identity")
        expected_owner = expected.get("owner") if installed_owner is None else installed_owner
        if before.st_uid != expected_owner:
            raise EnrollmentError("payload_identity")
    try:
        plugin_yaml = (root / "plugin.yaml").read_text(encoding="utf-8")
        init_py = (root / "__init__.py").read_text(encoding="utf-8")
        dashboard = json.loads((root / "dashboard/manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnrollmentError("payload_identity") from exc
    if 'version: "0.4.1"' not in plugin_yaml or 'PLUGIN_VERSION = "0.4.1"' not in init_py or dashboard.get("version") != "0.4.1":
        raise EnrollmentError("payload_identity")


def installed_state(home: Path, state_root: Path, manifest: dict[str, Any], uid: int, profile: str) -> tuple[bool, str, dict[str, Any]]:
    target = home / "plugins" / "skynet-edr"
    metadata = state_root / "enrollment.json"
    if not target.exists() and not metadata.exists():
        return False, "ABSENT", {}
    if target.is_symlink() or not target.is_dir() or not metadata.is_file():
        return False, "DRIFTED", {}
    try:
        validate_tree(target, manifest, installed_owner=uid)
        enrolled = load_json(metadata, "installed_state")
    except EnrollmentError:
        return False, "DRIFTED", {}
    generation = canonical_generation(manifest)
    if (enrolled.get("generation") != generation or enrolled.get("uid") != uid
            or enrolled.get("profile") != profile):
        return False, "DRIFTED", {}
    return True, generation, enrolled


def observe(path: Path) -> dict[str, Any]:
    return load_json(path, "observation_failure")


def assess(request: dict[str, Any], home: Path, state_root: Path, manifest: dict[str, Any], observations: Path) -> tuple[str, str]:
    installed, detail, enrolled = installed_state(home, state_root, manifest, request["uid"], request["profile"])
    if not installed:
        return detail, "enrollment_state"
    obs = observe(observations)
    generation = canonical_generation(manifest)
    observed_at = obs.get("observed_at_ns")
    now = time.time_ns()
    if (
        obs.get("action") != "hook"
        or obs.get("transaction_nonce") != enrolled.get("verified_nonce")
        or obs.get("observed_generation") != generation
        or obs.get("target_uid") != request["uid"]
        or obs.get("effective_uid") != 0
        or not isinstance(observed_at, int)
        or observed_at > now
        or now - observed_at > 30_000_000_000
    ):
        return "DRIFTED", "observation_failure"
    if obs.get("plugin_enabled") is not True or obs.get("loaded_generation") != generation:
        return "DRIFTED", "enablement"
    if obs.get("process_fresh") is not True:
        return "RELOAD_REQUIRED", "reload_boundary"
    daemon = obs.get("daemon")
    producer = obs.get("producer")
    if not isinstance(daemon, dict) or not isinstance(producer, dict):
        return "DEGRADED", "producer_health"
    healthy = (
        daemon.get("healthy") is True
        and daemon.get("listener") is True
        and daemon.get("transport") == "available"
        and daemon.get("backlog") == 0
        and daemon.get("degraded") is False
        and producer.get("uid") == request["uid"]
        and producer.get("role") == request["required_role"]
        and producer.get("fresh") is True
    )
    hook = obs.get("real_hook")
    hook_ok = isinstance(hook, dict) and hook.get("correlated") is True and hook.get("committed") is True and hook.get("incident_opened") is False
    if not healthy or not hook_ok:
        return "DEGRADED", "producer_health"
    return "ENROLLED", "verified"


def adapter_env(home: Path, profile: str, observations: Path, generation: str, uid: int) -> dict[str, str]:
    return {
        "HOME": str(home.parent),
        "HERMES_HOME": str(home),
        "HERMES_PROFILE": profile,
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "SKYNET_EDR_GENERATION": generation,
        "SKYNET_EDR_OBSERVATIONS": str(observations),
        "SKYNET_EDR_TARGET_UID": str(uid),
    }


def run_adapter(adapter: Path, action: str, env: dict[str, str], observations: Path) -> dict[str, Any]:
    nonce = secrets.token_hex(32)
    action_env = dict(env)
    action_env["SKYNET_EDR_NONCE"] = nonce
    action_env["SKYNET_EDR_ACTION"] = action
    target_uid = int(env["SKYNET_EDR_TARGET_UID"])
    target_gid = pwd.getpwuid(target_uid).pw_gid

    def use_target_identity() -> None:
        if target_uid == os.geteuid():
            return
        if os.geteuid() != 0:
            raise OSError("identity transition unavailable")
        os.setgroups([])
        os.setgid(target_gid)
        os.setuid(target_uid)

    target_action = action in {"enable", "disable"}
    try:
        info = os.lstat(adapter)
        if (adapter.is_symlink() or not stat.S_ISREG(info.st_mode) or not os.access(adapter, os.X_OK)
                or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_uid != 0):
            raise OSError("invalid adapter")
        result = subprocess.run(
            ["/usr/bin/python3", str(adapter), action], env=action_env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=30, check=False, preexec_fn=use_target_identity if target_action else None,
        )
        if len(result.stdout) > 65_536:
            raise OSError("oversized adapter response")
        response = json.loads(result.stdout)
    except (OSError, KeyError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        raise EnrollmentError("adapter_failure") from exc
    if result.returncode != 0 or not isinstance(response, dict):
        raise EnrollmentError("adapter_failure")
    response.update({
        "transaction_nonce": nonce,
        "action": action,
        "observed_generation": env["SKYNET_EDR_GENERATION"],
        "target_uid": target_uid,
        "effective_uid": target_uid if target_action else os.geteuid(),
        "observed_at_ns": time.time_ns(),
    })
    observations.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".observation.", dir=observations.parent)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, json.dumps(response, sort_keys=True).encode("ascii"))
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, observations)
        fsync_dir(observations.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return response


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def copy_generation(source: Path, stage: Path, manifest: dict[str, Any], uid: int, gid: int) -> None:
    stage.mkdir(mode=0o700)
    os.chown(stage, uid, gid)
    for relative in ALLOWED_FILES:
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chown(destination.parent, uid, gid)
        source_path = source / relative
        source_info = os.lstat(source_path)
        source_fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                while True:
                    chunk = os.read(source_fd, 65536)
                    if not chunk:
                        break
                    os.write(destination_fd, chunk)
                os.fchmod(destination_fd, 0o644)
                os.fchown(destination_fd, uid, gid)
                os.fsync(destination_fd)
            finally:
                os.close(destination_fd)
            after = os.fstat(source_fd)
        finally:
            os.close(source_fd)
        if (source_info.st_dev, source_info.st_ino, source_info.st_size) != (after.st_dev, after.st_ino, after.st_size):
            raise EnrollmentError("payload_identity")
    validate_tree(stage, manifest, installed_owner=uid)
    for directory in sorted((path for path in stage.rglob("*") if path.is_dir()), reverse=True):
        fsync_dir(directory)
    fsync_dir(stage)


def write_metadata(state_root: Path, generation: str, uid: int, profile: str, verified_nonce: str | None) -> None:
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".enrollment.", dir=state_root)
    try:
        os.fchmod(fd, 0o600)
        data = json.dumps({"schema": 1, "generation": generation, "uid": uid, "profile": profile,
                           "verified_nonce": verified_nonce}, sort_keys=True).encode("ascii")
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, state_root / "enrollment.json")
        fsync_dir(state_root)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def scoped_runtime_state(state_root: Path, uid: int, profile: str) -> Path:
    identity = f"{uid}\0{profile}".encode("utf-8")
    return state_root / "targets" / hashlib.sha256(identity).hexdigest()


def enrollment_lock(state_root: Path) -> Path:
    if state_root.parent.name == "targets":
        return state_root.parent.parent / "enrollment.lock"
    return state_root / "enrollment.lock"


def restore_metadata(state_root: Path, previous: bytes | None) -> None:
    metadata = state_root / "enrollment.json"
    if previous is None:
        try:
            metadata.unlink()
        except FileNotFoundError:
            pass
        return
    fd, temporary = tempfile.mkstemp(prefix=".rollback-metadata.", dir=state_root)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, previous)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, metadata)
        fsync_dir(state_root)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def rollback_target(target: Path, prior: Path, state_root: Path, previous_metadata: bytes | None) -> None:
    if target.exists():
        shutil.rmtree(target)
    if prior.exists():
        os.replace(prior, target)
    restore_metadata(state_root, previous_metadata)


def install_desktop(source: Path, home: Path, state_root: Path, uid: int, gid: int) -> tuple[Path, Path]:
    parent = home / "desktop-plugins"
    parent.mkdir(mode=0o700, exist_ok=True)
    os.chown(parent, uid, gid)
    target = parent / "skynet-edr"
    prior = state_root / "prior-desktop"
    if prior.exists():
        shutil.rmtree(prior)
    stage = Path(tempfile.mkdtemp(prefix=".skynet-edr-desktop-", dir=parent))
    os.chown(stage, uid, gid)
    try:
        copy_generation_file(source / "desktop" / "plugin.js", stage / "plugin.js", uid, gid)
        fsync_dir(stage)
        if target.exists():
            if target.is_symlink() or not target.is_dir() or {entry.name for entry in target.iterdir()} != {"plugin.js"}:
                raise EnrollmentError("invalid_target")
            os.replace(target, prior)
        os.replace(stage, target)
        fsync_dir(parent)
    except Exception:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
        raise
    return target, prior


def copy_generation_file(source: Path, destination: Path, uid: int, gid: int) -> None:
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            while chunk := os.read(source_fd, 65536):
                os.write(destination_fd, chunk)
            os.fchmod(destination_fd, 0o644)
            os.fchown(destination_fd, uid, gid)
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)


def rollback_desktop(target: Path, prior: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    if prior.exists():
        os.replace(prior, target)
        fsync_dir(target.parent)


def apply(request: dict[str, Any], source: Path, state_root: Path, observations: Path, adapter: Path) -> int:
    uid, home, profile, manifest = validate_request(request, source)
    gid = pwd.getpwuid(uid).pw_gid
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = enrollment_lock(state_root)
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("a+b") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state, category = assess(request, home, state_root, manifest, observations)
        if state == "ENROLLED":
            return emit(state, category, noop=True)
        generation = canonical_generation(manifest)
        target_parent = home / "plugins"
        target_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chown(target_parent, uid, gid)
        target = target_parent / "skynet-edr"
        stage = target_parent / f".skynet-edr-stage-{os.getpid()}"
        prior = state_root / "prior-generation"
        metadata_path = state_root / "enrollment.json"
        previous_metadata = metadata_path.read_bytes() if metadata_path.exists() else None
        desktop_target: Path | None = None
        desktop_prior: Path | None = None
        if stage.exists():
            shutil.rmtree(stage)
        if prior.exists():
            shutil.rmtree(prior)
        committed = False
        host_prepared = False
        try:
            run_adapter(adapter, "prepare", adapter_env(home, profile, observations, generation, uid), observations)
            host_prepared = True
            copy_generation(source, stage, manifest, uid, gid)
            if target.exists():
                if target.is_symlink() or not target.is_dir():
                    raise EnrollmentError("invalid_target")
                os.replace(target, prior)
            committed = True
            os.replace(stage, target)
            fsync_dir(target_parent)
            desktop_target, desktop_prior = install_desktop(source, home, state_root, uid, gid)
            write_metadata(state_root, generation, uid, profile, None)
            env = adapter_env(home, profile, observations, generation, uid)
            enabled = run_adapter(adapter, "enable", env, observations)
            if enabled.get("plugin_enabled") is not True:
                raise EnrollmentError("enablement")
            if request.get("restart_authorized") is not True:
                return emit("RELOAD_REQUIRED", "reload_boundary")
            run_adapter(adapter, "restart", env, observations)
            hooked = run_adapter(adapter, "hook", env, observations)
            write_metadata(state_root, generation, uid, profile, hooked["transaction_nonce"])
            final_state, final_category = assess(request, home, state_root, manifest, observations)
            if final_state != "ENROLLED":
                raise EnrollmentError(final_category, final_state)
            return emit(final_state, final_category)
        except (EnrollmentError, OSError) as exc:
            failure_state = exc.state if isinstance(exc, EnrollmentError) else "DRIFTED"
            failure_category = exc.category if isinstance(exc, EnrollmentError) else "internal_failure"
            try:
                if committed:
                    run_adapter(adapter, "disable", adapter_env(home, profile, observations, generation, uid), observations)
                    if desktop_target is not None and desktop_prior is not None:
                        rollback_desktop(desktop_target, desktop_prior)
                    rollback_target(target, prior, state_root, previous_metadata)
                if host_prepared:
                    run_adapter(adapter, "rollback", adapter_env(home, profile, observations, generation, uid), observations)
            except (EnrollmentError, OSError):
                return emit("ROLLBACK_REQUIRED", "rollback")
            if stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
            return emit(failure_state, failure_category)


def unenroll(request: dict[str, Any], source: Path, state_root: Path, observations: Path, adapter: Path) -> int:
    _, home, profile, manifest = validate_request(request, source)
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = enrollment_lock(state_root)
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        target = home / "plugins" / "skynet-edr"
        if not target.exists() and not (state_root / "enrollment.json").exists():
            return emit("ABSENT", "unenrolled", noop=True, success=True)
        generation = canonical_generation(manifest)
        if target.is_symlink() or not target.is_dir():
            return emit("DRIFTED", "invalid_target")
        try:
            validate_tree(target, manifest, installed_owner=request["uid"])
        except EnrollmentError:
            return emit("DRIFTED", "invalid_target")
        desktop = home / "desktop-plugins" / "skynet-edr"
        if desktop.exists():
            expected = manifest["desktop/plugin.js"]
            plugin = desktop / "plugin.js"
            if (desktop.is_symlink() or not desktop.is_dir() or {entry.name for entry in desktop.iterdir()} != {"plugin.js"}
                    or plugin.is_symlink() or not plugin.is_file() or plugin.stat().st_nlink != 1
                    or plugin.stat().st_uid != request["uid"]
                    or plugin.stat().st_size != expected["size"]
                    or hashlib.sha256(plugin.read_bytes()).hexdigest() != expected["sha256"]):
                return emit("DRIFTED", "invalid_target")
        try:
            disabled = run_adapter(adapter, "disable", adapter_env(home, profile, observations, generation, request["uid"]), observations)
            if disabled.get("plugin_enabled") is not False:
                raise EnrollmentError("enablement")
            run_adapter(adapter, "rollback", adapter_env(home, profile, observations, generation, request["uid"]), observations)
            if desktop.exists():
                shutil.rmtree(desktop)
                fsync_dir(desktop.parent)
            shutil.rmtree(target)
            try:
                (state_root / "enrollment.json").unlink()
            except FileNotFoundError:
                pass
            return emit("ABSENT", "unenrolled", success=True)
        except EnrollmentError as exc:
            return emit(exc.state, exc.category)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail-closed Skynet-EDR Hermes enrollment")
    parser.add_argument("verb", choices=("check", "apply", "verify", "unenroll"))
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--observations", required=True, type=Path)
    parser.add_argument("--adapter", type=Path)
    return parser.parse_args()


def main(*, test_mode: bool = False) -> int:
    args = parse_args()
    try:
        request = load_json(args.request, "invalid_input")
        if not test_mode:
            trusted_paths = (
                args.source == SYSTEM_SOURCE
                and args.state_root == SYSTEM_STATE_ROOT
                and args.observations == SYSTEM_OBSERVATIONS
                and request.get("fixture") is not True
                and os.geteuid() == 0
            )
            if args.verb in {"apply", "unenroll"}:
                trusted_paths = trusted_paths and args.adapter == SYSTEM_ADAPTER
            if not trusted_paths:
                raise EnrollmentError("untrusted_runtime")
            if request.get("uid") == 0:
                raise EnrollmentError("root_denied")
        _, home, profile, manifest = validate_request(request, args.source)
        runtime_state = args.state_root if test_mode else scoped_runtime_state(args.state_root, request["uid"], profile)
        runtime_observations = args.observations if test_mode else runtime_state / "observations.json"
        if args.verb in {"apply", "unenroll"}:
            if args.adapter is None or not args.adapter.is_absolute():
                raise EnrollmentError("invalid_input")
            if args.verb == "apply":
                return apply(request, args.source, runtime_state, runtime_observations, args.adapter)
            return unenroll(request, args.source, runtime_state, runtime_observations, args.adapter)
        state, category = assess(request, home, runtime_state, manifest, runtime_observations)
        return emit(state, category)
    except EnrollmentError as exc:
        return emit(exc.state, exc.category)
    except Exception:
        return emit("DRIFTED", "internal_failure")


if __name__ == "__main__":
    sys.exit(main())
