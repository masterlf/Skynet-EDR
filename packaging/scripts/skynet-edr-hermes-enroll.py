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
import shutil
import stat
import subprocess
import sys
import tempfile
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
MAX_PAYLOAD_FILE = 8 * 1024 * 1024
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
SAFE_UNIT = re.compile(r"^hermes-[A-Za-z0-9_.@-]+\.service$")


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
    if not isinstance(units, list) or not units or any(not isinstance(unit, str) or not SAFE_UNIT.fullmatch(unit) for unit in units):
        raise EnrollmentError("invalid_input")
    source = checked_absolute(str(source), "payload_identity")
    check_existing_path(source, uid, writable_leaf=False)
    manifest = request.get("manifest")
    if not isinstance(manifest, dict) or set(manifest) != set(ALLOWED_FILES):
        raise EnrollmentError("payload_identity")
    if request.get("manifest_sha256") != canonical_generation(manifest):
        raise EnrollmentError("payload_identity")
    if request.get("fixture") is not True and source != SYSTEM_SOURCE:
        raise EnrollmentError("payload_identity")
    validate_tree(source, manifest)
    return uid, home, profile, manifest


def validate_tree(root: Path, manifest: dict[str, Any]) -> None:
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
        if before.st_uid != expected.get("owner"):
            raise EnrollmentError("payload_identity")
    try:
        plugin_yaml = (root / "plugin.yaml").read_text(encoding="utf-8")
        init_py = (root / "__init__.py").read_text(encoding="utf-8")
        dashboard = json.loads((root / "dashboard/manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnrollmentError("payload_identity") from exc
    if 'version: "0.4.1"' not in plugin_yaml or 'PLUGIN_VERSION = "0.4.1"' not in init_py or dashboard.get("version") != "0.4.1":
        raise EnrollmentError("payload_identity")


def installed_state(home: Path, state_root: Path, manifest: dict[str, Any]) -> tuple[bool, str]:
    target = home / "plugins" / "skynet-edr"
    metadata = state_root / "enrollment.json"
    if not target.exists() and not metadata.exists():
        return False, "ABSENT"
    if target.is_symlink() or not target.is_dir() or not metadata.is_file():
        return False, "DRIFTED"
    try:
        validate_tree(target, manifest)
        enrolled = load_json(metadata, "installed_state")
    except EnrollmentError:
        return False, "DRIFTED"
    generation = canonical_generation(manifest)
    if enrolled.get("generation") != generation:
        return False, "DRIFTED"
    return True, generation


def observe(path: Path) -> dict[str, Any]:
    return load_json(path, "observation_failure")


def assess(request: dict[str, Any], home: Path, state_root: Path, manifest: dict[str, Any], observations: Path) -> tuple[str, str]:
    installed, detail = installed_state(home, state_root, manifest)
    if not installed:
        return detail, "enrollment_state"
    obs = observe(observations)
    generation = canonical_generation(manifest)
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


def adapter_env(home: Path, profile: str, observations: Path, generation: str) -> dict[str, str]:
    return {
        "HOME": str(home.parent),
        "HERMES_HOME": str(home),
        "HERMES_PROFILE": profile,
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "SKYNET_EDR_GENERATION": generation,
        "SKYNET_EDR_OBSERVATIONS": str(observations),
    }


def run_adapter(adapter: Path, action: str, env: dict[str, str]) -> None:
    try:
        info = os.lstat(adapter)
        if adapter.is_symlink() or not stat.S_ISREG(info.st_mode) or not os.access(adapter, os.X_OK):
            raise OSError("invalid adapter")
        result = subprocess.run([str(adapter), action], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise EnrollmentError("adapter_failure") from exc
    if result.returncode != 0:
        raise EnrollmentError("adapter_failure")


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def copy_generation(source: Path, stage: Path, manifest: dict[str, Any]) -> None:
    stage.mkdir(mode=0o700)
    for relative in ALLOWED_FILES:
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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
                os.fsync(destination_fd)
            finally:
                os.close(destination_fd)
            after = os.fstat(source_fd)
        finally:
            os.close(source_fd)
        if (source_info.st_dev, source_info.st_ino, source_info.st_size) != (after.st_dev, after.st_ino, after.st_size):
            raise EnrollmentError("payload_identity")
    validate_tree(stage, manifest)
    for directory in sorted((path for path in stage.rglob("*") if path.is_dir()), reverse=True):
        fsync_dir(directory)
    fsync_dir(stage)


def write_metadata(state_root: Path, generation: str, uid: int, profile: str) -> None:
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".enrollment.", dir=state_root)
    try:
        os.fchmod(fd, 0o600)
        data = json.dumps({"schema": 1, "generation": generation, "uid": uid, "profile": profile}, sort_keys=True).encode("ascii")
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


def rollback_target(target: Path, prior: Path, state_root: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    if prior.exists():
        os.replace(prior, target)
    try:
        (state_root / "enrollment.json").unlink()
    except FileNotFoundError:
        pass


def apply(request: dict[str, Any], source: Path, state_root: Path, observations: Path, adapter: Path) -> int:
    uid, home, profile, manifest = validate_request(request, source)
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = state_root / "enrollment.lock"
    with lock_path.open("a+b") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state, category = assess(request, home, state_root, manifest, observations)
        if state == "ENROLLED":
            return emit(state, category, noop=True)
        generation = canonical_generation(manifest)
        target_parent = home / "plugins"
        target_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = target_parent / "skynet-edr"
        stage = target_parent / f".skynet-edr-stage-{os.getpid()}"
        prior = state_root / "prior-generation"
        if stage.exists():
            shutil.rmtree(stage)
        if prior.exists():
            shutil.rmtree(prior)
        committed = False
        try:
            copy_generation(source, stage, manifest)
            if target.exists():
                if target.is_symlink() or not target.is_dir():
                    raise EnrollmentError("invalid_target")
                os.replace(target, prior)
            os.replace(stage, target)
            fsync_dir(target_parent)
            write_metadata(state_root, generation, uid, profile)
            committed = True
            env = adapter_env(home, profile, observations, generation)
            run_adapter(adapter, "enable", env)
            if observe(observations).get("plugin_enabled") is not True:
                raise EnrollmentError("enablement")
            if request.get("restart_authorized") is not True:
                return emit("RELOAD_REQUIRED", "reload_boundary")
            run_adapter(adapter, "restart", env)
            run_adapter(adapter, "hook", env)
            final_state, final_category = assess(request, home, state_root, manifest, observations)
            if final_state != "ENROLLED":
                raise EnrollmentError(final_category, final_state)
            return emit(final_state, final_category)
        except EnrollmentError as exc:
            if committed:
                try:
                    run_adapter(adapter, "disable", adapter_env(home, profile, observations, generation))
                    rollback_target(target, prior, state_root)
                except (EnrollmentError, OSError):
                    return emit("ROLLBACK_REQUIRED", "rollback")
            if stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
            return emit(exc.state, exc.category)


def unenroll(request: dict[str, Any], source: Path, state_root: Path, observations: Path, adapter: Path) -> int:
    _, home, profile, manifest = validate_request(request, source)
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (state_root / "enrollment.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        target = home / "plugins" / "skynet-edr"
        if not target.exists() and not (state_root / "enrollment.json").exists():
            return emit("ABSENT", "unenrolled", noop=True, success=True)
        generation = canonical_generation(manifest)
        try:
            run_adapter(adapter, "disable", adapter_env(home, profile, observations, generation))
            if observe(observations).get("plugin_enabled") is not False:
                raise EnrollmentError("enablement")
            if target.is_symlink() or not target.is_dir():
                raise EnrollmentError("invalid_target")
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


def main() -> int:
    args = parse_args()
    try:
        request = load_json(args.request, "invalid_input")
        _, home, _, manifest = validate_request(request, args.source)
        if args.verb in {"apply", "unenroll"}:
            if args.adapter is None or not args.adapter.is_absolute():
                raise EnrollmentError("invalid_input")
            if args.verb == "apply":
                return apply(request, args.source, args.state_root, args.observations, args.adapter)
            return unenroll(request, args.source, args.state_root, args.observations, args.adapter)
        state, category = assess(request, home, args.state_root, manifest, args.observations)
        return emit(state, category)
    except EnrollmentError as exc:
        return emit(exc.state, exc.category)
    except Exception:
        return emit("DRIFTED", "internal_failure")


if __name__ == "__main__":
    sys.exit(main())
