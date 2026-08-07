#!/usr/bin/env python3
"""Fail-closed, transactional Hermes enrollment for the bounded S3 contract.

External service and Hermes operations are performed by one reviewed adapter
executable. Adapter output is never forwarded. Every invocation receives the
selected HERMES_HOME/profile and the expected generation in a minimal
environment; success is accepted only after fresh observation-file read-back.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import signal
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
ATTEST_BUDGET_NS = 15_000_000_000
JOURNAL_KEYS = {"schema", "transaction_nonce", "operation", "target", "objects", "phase", "result", "manual_recovery"}
JOURNAL_OBJECT_KEYS = {"source_parent", "source_name", "source_identity", "quarantine_parent", "quarantine_name", "quarantine_identity"}
IDENTITY_KEYS = {"dev", "ino", "type", "mode", "uid", "gid", "nlink", "size", "tree_sha256"}
PARENT_IDENTITY_KEYS = {"dev", "ino", "mode", "uid", "gid"}
JOURNAL_OBJECT_NAMES = {"backend", "desktop", "metadata", "observation"}
JOURNAL_PHASES = {"STARTED", "DISABLED", "ADAPTER_RESTORED", "QUARANTINING", "QUARANTINED"}
MANUAL_RECOVERY = ("Manual root recovery required: inspect the exact quarantine and transaction journal; "
                   "restore only an identity-matching object to an absent source with atomic no-replace rename. "
                   "No quarantined managed content is removed automatically.")
ATTEST_RESPONSE_KEYS = {
    "plugin_enabled", "loaded_generation", "process_fresh", "daemon", "producer",
    "real_hook", "restart_blast_radius", "identities", "commit_sequence",
}
ATTEST_OBSERVATION_KEYS = ATTEST_RESPONSE_KEYS | {
    "target_uid", "observed_generation", "transaction_nonce",
    "action", "effective_uid", "observed_at_ns",
}
ADAPTER_BASE_KEYS = {
    "prepare": {"prepared", "plugin_enabled"},
    "rollback": {"prepared", "plugin_enabled", "reload_required", "rollback_phase"},
    "enable": {"plugin_enabled", "loaded_generation", "process_fresh"},
    "disable": {"plugin_enabled", "loaded_generation", "process_fresh"},
}
ADAPTER_ENVELOPE_KEYS = {"transaction_nonce", "action", "observed_generation", "target_uid", "effective_uid", "observed_at_ns"}


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
    if request.get("fixture") is not True and home != Path(resolved.pw_dir) / ".hermes":
        raise EnrollmentError("untrusted_path")
    check_existing_path(home, uid, writable_leaf=True)
    profile = request.get("profile")
    if not isinstance(profile, str) or not SAFE_NAME.fullmatch(profile):
        raise EnrollmentError("invalid_input")
    if request.get("fixture") is not True and profile != "default":
        raise EnrollmentError("unsupported_contract")
    if request.get("host") != SUPPORTED_HOST or request.get("hermes_version") not in SUPPORTED_HERMES:
        raise EnrollmentError("unsupported_contract")
    if request.get("payload_version") != "0.5.0":
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
        if package_manifest.get("schema") != 1 or package_manifest.get("payload_version") != "0.5.0":
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
        entries = {str(path.relative_to(root)): os.lstat(path) for path in root.rglob("*")}
    except OSError as exc:
        raise EnrollmentError("payload_identity") from exc
    expected_directories = {"dashboard", "desktop"}
    actual_files = {name for name, info in entries.items() if stat.S_ISREG(info.st_mode)}
    actual_directories = {name for name, info in entries.items() if stat.S_ISDIR(info.st_mode)}
    if actual_files != set(ALLOWED_FILES) or actual_directories != expected_directories:
        raise EnrollmentError("payload_identity")
    if len(entries) != len(actual_files) + len(actual_directories):
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
    if 'version: "0.5.0"' not in plugin_yaml or 'PLUGIN_VERSION = "0.5.0"' not in init_py or dashboard.get("version") != "0.5.0":
        raise EnrollmentError("payload_identity")


def installed_state(home: Path, state_root: Path, manifest: dict[str, Any], uid: int, profile: str,
                    target_parent: Path | None = None) -> tuple[bool, str, dict[str, Any]]:
    target = (target_parent if target_parent is not None else home / "plugins") / "skynet-edr"
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


def assess(request: dict[str, Any], home: Path, state_root: Path, manifest: dict[str, Any], observations: Path,
           target_parent: Path | None = None) -> tuple[str, str]:
    installed, detail, enrolled = installed_state(
        home, state_root, manifest, request["uid"], request["profile"], target_parent
    )
    if not installed:
        return detail, "enrollment_state"
    reload_required = enrolled.get("reload_required")
    if type(reload_required) is not bool:
        return "DRIFTED", "installed_state"
    if reload_required:
        return "RELOAD_REQUIRED", "reload_boundary"
    obs = observe(observations)
    if set(obs) != ATTEST_OBSERVATION_KEYS:
        return "DRIFTED", "enablement"
    generation = canonical_generation(manifest)
    try:
        validate_attest_response(
            {key: obs[key] for key in ATTEST_RESPONSE_KEYS},
            {"SKYNET_EDR_TARGET_UID": str(request["uid"]),
             "SKYNET_EDR_GENERATION": generation},
            obs.get("real_hook", {}).get("event_id"),
        )
    except (EnrollmentError, AttributeError, TypeError):
        return "DRIFTED", "enablement"
    observed_at = obs.get("observed_at_ns")
    now = time.time_ns()
    if (
        obs.get("action") != "attest"
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
    try:
        home_info = os.stat(home, follow_symlinks=False)
    except OSError as exc:
        raise EnrollmentError("invalid_target") from exc
    if not stat.S_ISDIR(home_info.st_mode) or home_info.st_uid != uid:
        raise EnrollmentError("invalid_target")
    return {
        "HOME": str(home.parent),
        "HERMES_HOME": str(home),
        "HERMES_PROFILE": profile,
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "SKYNET_EDR_GENERATION": generation,
        "SKYNET_EDR_OBSERVATIONS": str(observations),
        "SKYNET_EDR_TARGET_UID": str(uid),
        "SKYNET_EDR_HOME_DEVICE": str(home_info.st_dev),
        "SKYNET_EDR_HOME_INODE": str(home_info.st_ino),
    }


def canary_event_id(token: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", token) is None:
        raise EnrollmentError("adapter_failure")
    return "evt_skynet_attest_" + hashlib.sha256(
        b"skynet-edr-attestation-v1\0" + token.encode("ascii")
    ).hexdigest()


def validate_attest_response(response: dict[str, Any], env: dict[str, str], event_id: str) -> None:
    daemon = response.get("daemon")
    producer = response.get("producer")
    hook = response.get("real_hook")
    identities = response.get("identities")
    expected_units = {"user@" + env["SKYNET_EDR_TARGET_UID"] + ".service",
                      "hermes-gateway.service", "skynet-edr.service"}
    identity_values_ok = (type(identities) is dict and set(identities) == expected_units
                          and all(type(value) is list and len(value) == 3
                                  and all(type(item) is int and item > 0 for item in value)
                                  for value in identities.values()))
    daemon_ok = (
        type(daemon) is dict
        and set(daemon) == {"healthy", "listener", "transport", "backlog", "degraded"}
        and type(daemon.get("healthy")) is bool and daemon["healthy"] is True
        and type(daemon.get("listener")) is bool and daemon["listener"] is True
        and type(daemon.get("transport")) is str and daemon["transport"] == "available"
        and type(daemon.get("backlog")) is int and daemon["backlog"] == 0
        and type(daemon.get("degraded")) is bool and daemon["degraded"] is False
    )
    producer_ok = (
        type(producer) is dict
        and set(producer) == {"uid", "role", "fresh", "generation", "runtime_nonce"}
        and type(producer.get("uid")) is int
        and producer["uid"] == int(env["SKYNET_EDR_TARGET_UID"])
        and type(producer.get("role")) is str and producer["role"] == "gateway"
        and type(producer.get("fresh")) is bool and producer["fresh"] is True
        and type(producer.get("generation")) is str
        and producer["generation"] == env["SKYNET_EDR_GENERATION"]
        and type(producer.get("runtime_nonce")) is str
        and re.fullmatch(r"[0-9a-f]{64}", producer["runtime_nonce"]) is not None
        and producer["runtime_nonce"] not in {
            env["SKYNET_EDR_GENERATION"], env.get("SKYNET_EDR_ATTESTATION_TOKEN")
        }
    )
    hook_ok = (
        type(hook) is dict
        and set(hook) == {"correlated", "committed", "incident_opened", "event_id", "receipt_status"}
        and type(hook.get("correlated")) is bool and hook["correlated"] is True
        and type(hook.get("committed")) is bool and hook["committed"] is True
        and type(hook.get("incident_opened")) is bool and hook["incident_opened"] is False
        and type(hook.get("event_id")) is str and hook["event_id"] == event_id
        and type(hook.get("receipt_status")) is str and hook["receipt_status"] == "persisted"
    )
    if (type(event_id) is not str
            or re.fullmatch(r"evt_skynet_attest_[0-9a-f]{64}", event_id) is None
            or type(response) is not dict
            or set(response) != ATTEST_RESPONSE_KEYS
            or type(response.get("plugin_enabled")) is not bool or response["plugin_enabled"] is not True
            or type(response.get("loaded_generation")) is not str
            or response["loaded_generation"] != env["SKYNET_EDR_GENERATION"]
            or type(response.get("process_fresh")) is not bool or response["process_fresh"] is not True
            or not daemon_ok or not producer_ok or not hook_ok
            or type(response.get("restart_blast_radius")) is not str
            or response["restart_blast_radius"] != "complete_user_manager"
            or not identity_values_ok
            or type(response.get("commit_sequence")) is not int
            or response["commit_sequence"] <= 0):
        raise EnrollmentError("adapter_failure")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def _parent_identity(fd: int) -> dict[str, int]:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
    return {"dev": info.st_dev, "ino": info.st_ino, "mode": info.st_mode,
            "uid": info.st_uid, "gid": info.st_gid}


def _tree_digest(fd: int, device: int, owner: int, *, depth: int = 0,
                 budget: list[int] | None = None) -> str:
    if depth > 16:
        raise EnrollmentError("quarantine_bounds", "MANUAL_RECOVERY_REQUIRED")
    budget = [0, 0] if budget is None else budget
    digest = hashlib.sha256()
    for name in sorted(os.listdir(fd)):
        if not name or name in {".", ".."} or "/" in name or "\0" in name:
            raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
        budget[0] += 1
        budget[1] += len(name.encode("utf-8"))
        if budget[0] > 256 or budget[1] > 64 * 1024 * 1024:
            raise EnrollmentError("quarantine_bounds", "MANUAL_RECOVERY_REQUIRED")
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if before.st_dev != device or before.st_uid != owner:
            raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(f"{before.st_mode}:{before.st_uid}:{before.st_gid}:".encode("ascii"))
        flags = os.O_RDONLY | os.O_NOFOLLOW
        if stat.S_ISDIR(before.st_mode):
            flags |= os.O_DIRECTORY
        elif not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise EnrollmentError("quarantine_type", "MANUAL_RECOVERY_REQUIRED")
        child = os.open(name, flags, dir_fd=fd)
        try:
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_gid,
                    opened.st_nlink, opened.st_size) != (before.st_dev, before.st_ino,
                    before.st_mode, before.st_uid, before.st_gid, before.st_nlink, before.st_size):
                raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
            if stat.S_ISDIR(opened.st_mode):
                digest.update(b"d" + bytes.fromhex(_tree_digest(
                    child, device, owner, depth=depth + 1, budget=budget
                )))
            else:
                content = hashlib.sha256()
                length = 0
                while chunk := os.read(child, 65_536):
                    length += len(chunk)
                    budget[1] += len(chunk)
                    if budget[1] > 64 * 1024 * 1024:
                        raise EnrollmentError("quarantine_bounds", "MANUAL_RECOVERY_REQUIRED")
                    content.update(chunk)
                if length != before.st_size or os.fstat(child).st_ino != before.st_ino:
                    raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
                digest.update(b"f" + content.digest())
        finally:
            os.close(child)
    return digest.hexdigest()


def object_identity(parent_fd: int, name: str, owner: int) -> dict[str, Any]:
    if SAFE_NAME.fullmatch(name) is None:
        raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    kind = "directory" if stat.S_ISDIR(before.st_mode) else "regular" if stat.S_ISREG(before.st_mode) else ""
    if before.st_uid != owner or not kind or (kind == "regular" and before.st_nlink != 1):
        raise EnrollmentError("quarantine_type", "MANUAL_RECOVERY_REQUIRED")
    flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if kind == "directory" else 0)
    fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(fd)
        fixed = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                              info.st_gid, info.st_nlink, info.st_size)
        if fixed(before) != fixed(opened):
            raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
        if kind == "directory":
            tree_sha256 = _tree_digest(fd, opened.st_dev, owner)
        else:
            data = os.read(fd, 65_537)
            if len(data) != opened.st_size or len(data) > 65_536:
                raise EnrollmentError("quarantine_bounds", "MANUAL_RECOVERY_REQUIRED")
            tree_sha256 = hashlib.sha256(data).hexdigest()
    finally:
        os.close(fd)
    return {"dev": before.st_dev, "ino": before.st_ino, "type": kind,
            "mode": before.st_mode, "uid": before.st_uid, "gid": before.st_gid,
            "nlink": before.st_nlink, "size": before.st_size, "tree_sha256": tree_sha256}


def _rename_noreplace(source_fd: int, source_name: str, destination_fd: int,
                      destination_name: str, state: str) -> None:
    if SAFE_NAME.fullmatch(source_name) is None or SAFE_NAME.fullmatch(destination_name) is None:
        raise EnrollmentError("quarantine_identity", state)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                              ctypes.c_char_p, ctypes.c_uint]
        renameat2.restype = ctypes.c_int
    except (AttributeError, OSError) as exc:
        raise EnrollmentError("unsupported_layout", state) from exc
    if renameat2(source_fd, source_name.encode("ascii"), destination_fd,
                 destination_name.encode("ascii"), 1) != 0:
        value = ctypes.get_errno()
        category = "unsupported_layout" if value in {errno.ENOSYS, errno.EINVAL, errno.EXDEV} else "quarantine_collision"
        raise EnrollmentError(category, state) from OSError(value, os.strerror(value))


def detach_nondestructive(source_fd: int, source_name: str, quarantine_fd: int,
                          quarantine_name: str, owner: int) -> dict[str, Any]:
    if _parent_identity(source_fd)["dev"] != _parent_identity(quarantine_fd)["dev"]:
        raise EnrollmentError("unsupported_layout", "MANUAL_RECOVERY_REQUIRED")
    expected = object_identity(source_fd, source_name, owner)
    try:
        os.stat(quarantine_name, dir_fd=quarantine_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise EnrollmentError("quarantine_collision", "MANUAL_RECOVERY_REQUIRED")
    if object_identity(source_fd, source_name, owner) != expected:
        raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
    _rename_noreplace(source_fd, source_name, quarantine_fd, quarantine_name,
                      "MANUAL_RECOVERY_REQUIRED")
    os.fsync(source_fd)
    os.fsync(quarantine_fd)
    actual = object_identity(quarantine_fd, quarantine_name, owner)
    try:
        os.stat(source_name, dir_fd=source_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
    if actual != expected:
        raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
    return actual


def restore_nondestructive(quarantine_fd: int, quarantine_name: str, source_fd: int,
                           source_name: str, expected: dict[str, Any], owner: int) -> dict[str, Any]:
    if _parent_identity(quarantine_fd)["dev"] != _parent_identity(source_fd)["dev"]:
        raise EnrollmentError("unsupported_layout", "MANUAL_RECOVERY_REQUIRED")
    try:
        os.stat(source_name, dir_fd=source_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise EnrollmentError("restore_collision", "MANUAL_RECOVERY_REQUIRED")
    if object_identity(quarantine_fd, quarantine_name, owner) != expected:
        raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
    _rename_noreplace(quarantine_fd, quarantine_name, source_fd, source_name,
                      "MANUAL_RECOVERY_REQUIRED")
    os.fsync(quarantine_fd)
    os.fsync(source_fd)
    actual = object_identity(source_fd, source_name, owner)
    if actual != expected:
        raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
    return actual


def new_quarantine_journal(nonce: str, operation: str, uid: int, home: Path,
                           profile: str, generation: str) -> dict[str, Any]:
    if (re.fullmatch(r"[0-9a-f]{64}", nonce) is None or operation not in {"unenroll", "rollback"}
            or type(uid) is not int or uid < 0 or type(profile) is not str
            or SAFE_NAME.fullmatch(profile) is None
            or re.fullmatch(r"[0-9a-f]{64}", generation) is None):
        raise EnrollmentError("journal", "MANUAL_RECOVERY_REQUIRED")
    return {"schema": 1, "transaction_nonce": nonce, "operation": operation,
            "target": {"uid": uid, "home": str(home), "profile": profile, "generation": generation},
            "objects": {}, "phase": "STARTED", "result": None,
            "manual_recovery": MANUAL_RECOVERY}


def _valid_identity(value: Any) -> bool:
    return (type(value) is dict and set(value) == IDENTITY_KEYS
            and value.get("type") in {"directory", "regular"}
            and all(type(value.get(key)) is int and value[key] >= 0
                    for key in IDENTITY_KEYS - {"type", "tree_sha256"})
            and type(value.get("tree_sha256")) is str
            and re.fullmatch(r"[0-9a-f]{64}", value["tree_sha256"]) is not None)


def load_quarantine_journal(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if not raw or len(raw) > 262_144:
            raise ValueError("journal size")
        value = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise EnrollmentError("journal", "MANUAL_RECOVERY_REQUIRED") from exc
    target = value.get("target") if type(value) is dict else None
    objects = value.get("objects") if type(value) is dict else None
    if (type(value) is not dict or set(value) != JOURNAL_KEYS
            or type(value.get("schema")) is not int or value["schema"] != 1
            or re.fullmatch(r"[0-9a-f]{64}", value.get("transaction_nonce", "")) is None
            or value.get("operation") not in {"unenroll", "rollback"}
            or type(target) is not dict or set(target) != {"uid", "home", "profile", "generation"}
            or type(target.get("uid")) is not int or target["uid"] < 0
            or type(target.get("home")) is not str or type(target.get("profile")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", target.get("generation", "")) is None
            or type(objects) is not dict or value.get("phase") not in JOURNAL_PHASES
            or not set(objects).issubset(JOURNAL_OBJECT_NAMES)
            or value.get("result") not in {None, "QUARANTINED", "MANUAL_RECOVERY_REQUIRED"}
            or value.get("manual_recovery") != MANUAL_RECOVERY):
        raise EnrollmentError("journal", "MANUAL_RECOVERY_REQUIRED")
    for record in objects.values():
        if (type(record) is not dict or set(record) != JOURNAL_OBJECT_KEYS
                or type(record.get("source_parent")) is not dict
                or type(record.get("quarantine_parent")) is not dict
                or type(record.get("source_name")) is not str
                or SAFE_NAME.fullmatch(record["source_name"]) is None
                or type(record.get("quarantine_name")) is not str
                or SAFE_NAME.fullmatch(record["quarantine_name"]) is None
                or not _valid_identity(record.get("source_identity"))
                or not _valid_identity(record.get("quarantine_identity"))):
            raise EnrollmentError("journal", "MANUAL_RECOVERY_REQUIRED")
        for parent in (record["source_parent"], record["quarantine_parent"]):
            if (set(parent) != PARENT_IDENTITY_KEYS
                    or any(type(parent.get(key)) is not int or parent[key] < 0
                           for key in PARENT_IDENTITY_KEYS)):
                raise EnrollmentError("journal", "MANUAL_RECOVERY_REQUIRED")
    return value


def write_quarantine_journal(path: Path, journal: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, json.dumps(journal, sort_keys=True, separators=(",", ":")).encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
        os.replace(temporary, path)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _remaining_seconds(deadline_ns: int) -> float:
    remaining = deadline_ns - time.monotonic_ns()
    if remaining <= 0:
        raise EnrollmentError("adapter_failure")
    return remaining / 1_000_000_000


@contextlib.contextmanager
def _deadline_guard(deadline_ns: int):
    def expired(_signum, _frame):
        raise EnrollmentError("adapter_failure")

    started_ns = time.monotonic_ns()
    remaining_ns = deadline_ns - started_ns
    if remaining_ns <= 0:
        raise EnrollmentError("adapter_failure")
    previous = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, remaining_ns / 1_000_000_000)
    try:
        yield
        _remaining_seconds(deadline_ns)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        elapsed = max(0.0, (time.monotonic_ns() - started_ns) / 1_000_000_000)
        previous_delay = max(1e-9, previous_timer[0] - elapsed) if previous_timer[0] > 0 else 0.0
        signal.signal(signal.SIGALRM, previous)
        signal.setitimer(signal.ITIMER_REAL, previous_delay, previous_timer[1])


def run_attest_lane(adapter: Path, env: dict[str, str], observations: Path,
                    state_root: Path, generation: str, uid: int, profile: str,
                    request: dict[str, Any], home: Path, manifest: dict[str, Any],
                    target_parent: Path) -> tuple[dict[str, Any], str, str]:
    token = secrets.token_hex(32)
    while token == generation:
        token = secrets.token_hex(32)
    event_id = canary_event_id(token)
    deadline_ns = time.monotonic_ns() + ATTEST_BUDGET_NS
    with _deadline_guard(deadline_ns):
        attested = run_adapter(
            adapter, "attest", env, observations, deadline_ns=deadline_ns,
            attestation_token=token, expected_event_id=event_id,
        )
        _remaining_seconds(deadline_ns)
        write_metadata(
            state_root, generation, uid, profile, attested["transaction_nonce"],
            deadline_ns=deadline_ns,
        )
        _remaining_seconds(deadline_ns)
        final_state, final_category = assess(
            request, home, state_root, manifest, observations, target_parent
        )
        _remaining_seconds(deadline_ns)
    return attested, final_state, final_category


def run_adapter(adapter: Path, action: str, env: dict[str, str], observations: Path, *,
                deadline_ns: int | None = None, attestation_token: str | None = None,
                expected_event_id: str | None = None) -> dict[str, Any]:
    if deadline_ns is not None:
        _remaining_seconds(deadline_ns)
    nonce = secrets.token_hex(32)
    action_env = dict(env)
    action_env["SKYNET_EDR_NONCE"] = nonce
    action_env["SKYNET_EDR_ACTION"] = action
    if deadline_ns is not None:
        if (action != "attest" or attestation_token is None or expected_event_id is None
                or expected_event_id != canary_event_id(attestation_token)
                or attestation_token in {nonce, env["SKYNET_EDR_GENERATION"]}):
            raise EnrollmentError("adapter_failure")
        action_env["SKYNET_EDR_DEADLINE_NS"] = str(deadline_ns)
        action_env["SKYNET_EDR_ATTESTATION_TOKEN"] = attestation_token
        action_env["SKYNET_EDR_CANARY_EVENT_ID"] = expected_event_id
    target_uid = int(env["SKYNET_EDR_TARGET_UID"])
    if deadline_ns is not None:
        _remaining_seconds(deadline_ns)
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
        if deadline_ns is not None:
            _remaining_seconds(deadline_ns)
        if (adapter.is_symlink() or not stat.S_ISREG(info.st_mode) or not os.access(adapter, os.X_OK)
                or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_uid != 0):
            raise OSError("invalid adapter")
        result = subprocess.run(
            ["/usr/bin/python3", str(adapter), action], env=action_env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30 if deadline_ns is None else _remaining_seconds(deadline_ns),
            check=False, preexec_fn=use_target_identity if target_action else None,
        )
        if deadline_ns is not None:
            _remaining_seconds(deadline_ns)
        if len(result.stdout) > 65_536:
            raise OSError("oversized adapter response")
        response = json.loads(result.stdout, object_pairs_hook=_unique_json_object)
        if deadline_ns is not None:
            _remaining_seconds(deadline_ns)
    except (OSError, KeyError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        raise EnrollmentError("adapter_failure") from exc
    if result.returncode != 0 or not isinstance(response, dict):
        raise EnrollmentError("adapter_failure")
    if action == "attest":
        if expected_event_id is None or deadline_ns is None:
            raise EnrollmentError("adapter_failure")
        validate_attest_response(response, action_env, expected_event_id)
        _remaining_seconds(deadline_ns)
    elif (action not in ADAPTER_BASE_KEYS or set(response) != ADAPTER_BASE_KEYS[action]
          or type(response.get("plugin_enabled")) is not bool
          or (action == "prepare" and response.get("prepared") is not True)
          or (action == "rollback" and (
              response.get("prepared") is not False
              or response.get("reload_required") is not True
              or response.get("rollback_phase") != "RESTORED_VERIFIED"))
          or (action in {"enable", "disable"} and (
              type(response.get("process_fresh")) is not bool
              or response.get("process_fresh") is not False
              or response.get("plugin_enabled") is not (action == "enable")
              or response.get("loaded_generation") != (
                  env["SKYNET_EDR_GENERATION"] if action == "enable" else None)))):
        raise EnrollmentError("adapter_failure")
    response.update({
        "transaction_nonce": nonce,
        "action": action,
        "observed_generation": env["SKYNET_EDR_GENERATION"],
        "target_uid": target_uid,
        "effective_uid": target_uid if target_action else os.geteuid(),
        "observed_at_ns": time.time_ns(),
    })
    if deadline_ns is not None:
        _remaining_seconds(deadline_ns)
    snapshot_optional_regular(observations)
    if deadline_ns is not None:
        _remaining_seconds(deadline_ns)
    observations.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".observation.", dir=observations.parent)
    replaced = False
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, json.dumps(response, sort_keys=True).encode("ascii"))
        os.fsync(fd)
        os.close(fd)
        fd = -1
        if deadline_ns is not None:
            _remaining_seconds(deadline_ns)
        os.replace(temporary, observations)
        replaced = True
        fsync_dir(observations.parent)
        if deadline_ns is not None:
            _remaining_seconds(deadline_ns)
    except Exception:
        raise
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


def snapshot_optional_regular(path: Path) -> tuple[bool, bytes]:
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return False, b""
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 65_536:
        raise EnrollmentError("observation_failure")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            data = os.read(fd, 65_537)
            after = os.fstat(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise EnrollmentError("observation_failure") from exc
    if (len(data) > 65_536 or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)):
        raise EnrollmentError("observation_failure")
    return True, data


def restore_optional_regular(path: Path, previous: tuple[bool, bytes]) -> None:
    existed, data = previous
    if not existed:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.rollback-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        fsync_dir(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def remove_empty_user_directory(home: Path, name: str, uid: int,
                                expected_identity: tuple[int, int]) -> None:
    """Remove only the still-bound directory created by this transaction.

    The target UID is a documented cooperative boundary: the final relative
    stat is immediately followed by rmdir, without claiming same-UID exclusion.
    """
    home_fd = -1
    child_fd = -1
    try:
        home_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home_fd)
        info = os.fstat(child_fd)
        named_info = os.stat(name, dir_fd=home_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != expected_identity
                or not stat.S_ISDIR(named_info.st_mode) or named_info.st_uid != uid
                or stat.S_IMODE(named_info.st_mode) != 0o700
                or (named_info.st_dev, named_info.st_ino) != expected_identity):
            raise EnrollmentError("rollback", "ROLLBACK_REQUIRED")
        os.rmdir(name, dir_fd=home_fd)
        os.fsync(home_fd)
    except OSError as exc:
        raise EnrollmentError("rollback", "ROLLBACK_REQUIRED") from exc
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        if home_fd >= 0:
            os.close(home_fd)


def remove_created_regular(path: Path) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise EnrollmentError("rollback", "ROLLBACK_REQUIRED")
    path.unlink()


def remove_created_directory(path: Path) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise EnrollmentError("rollback", "ROLLBACK_REQUIRED")
    try:
        path.rmdir()
    except OSError as exc:
        raise EnrollmentError("rollback", "ROLLBACK_REQUIRED") from exc


def exists_nofollow(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


@contextlib.contextmanager
def opened_user_directory(home: Path, name: str, uid: int, gid: int, *, create: bool):
    """Pin a target-owned directory without following target-controlled links."""
    home_fd = -1
    child_fd = -1
    created = False
    created_identity: tuple[int, int] | None = None
    try:
        try:
            home_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            home_info = os.fstat(home_fd)
        except OSError as exc:
            raise EnrollmentError("invalid_target") from exc
        if home_info.st_uid != uid or home_info.st_mode & 0o077 or not stat.S_ISDIR(home_info.st_mode):
            raise EnrollmentError("ownership")
        try:
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home_fd)
        except FileNotFoundError:
            if not create:
                yield None, None
                return
            try:
                os.mkdir(name, mode=0o700, dir_fd=home_fd)
                created = True
                created_info = os.stat(name, dir_fd=home_fd, follow_symlinks=False)
                created_identity = created_info.st_dev, created_info.st_ino
            except FileExistsError:
                pass
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home_fd)
            if created:
                opened_identity = os.fstat(child_fd)
                named_identity = os.stat(name, dir_fd=home_fd, follow_symlinks=False)
                if ((opened_identity.st_dev, opened_identity.st_ino) != created_identity
                        or (named_identity.st_dev, named_identity.st_ino) != created_identity):
                    raise EnrollmentError("invalid_target")
                os.fchown(child_fd, uid, gid)
        except OSError as exc:
            raise EnrollmentError("invalid_target") from exc
        child_info = os.fstat(child_fd)
        if (not stat.S_ISDIR(child_info.st_mode) or child_info.st_uid != uid
                or child_info.st_mode & 0o022):
            raise EnrollmentError("invalid_target")
        if created and (child_info.st_dev, child_info.st_ino) != created_identity:
            raise EnrollmentError("invalid_target")
        yield Path(f"/proc/self/fd/{child_fd}"), created_identity
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        if home_fd >= 0:
            os.close(home_fd)


def validate_managed_parents(home: Path, uid: int, gid: int) -> None:
    for name in ("plugins", "desktop-plugins"):
        with opened_user_directory(home, name, uid, gid, create=False):
            pass


def require_same_filesystem(home: Path, state_root: Path) -> None:
    """Reject unsupported cross-filesystem transactions before creating state or targets."""
    candidate = state_root
    while True:
        try:
            state_info = os.stat(candidate, follow_symlinks=False)
            break
        except FileNotFoundError:
            parent = candidate.parent
            if parent == candidate:
                raise EnrollmentError("unsupported_layout")
            candidate = parent
        except OSError as exc:
            raise EnrollmentError("unsupported_layout") from exc
    try:
        home_info = os.stat(home, follow_symlinks=False)
    except OSError as exc:
        raise EnrollmentError("unsupported_layout") from exc
    if home_info.st_dev != state_info.st_dev:
        raise EnrollmentError("unsupported_layout")


def open_private_state_directory(path: Path, expected_dev: int) -> int:
    """Pin root-owned private state without repairing hostile pre-existing paths."""
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or info.st_dev != expected_dev):
        raise EnrollmentError("unsupported_layout", "MANUAL_RECOVERY_REQUIRED")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    pinned = os.fstat(fd)
    if (pinned.st_dev != info.st_dev or pinned.st_ino != info.st_ino or pinned.st_uid != 0
            or pinned.st_mode & 0o022 or not stat.S_ISDIR(pinned.st_mode)):
        os.close(fd)
        raise EnrollmentError("unsupported_layout", "MANUAL_RECOVERY_REQUIRED")
    return fd


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


def write_metadata(state_root: Path, generation: str, uid: int, profile: str, verified_nonce: str | None,
                   *, reload_required: bool = False, deadline_ns: int | None = None) -> None:
    if deadline_ns is not None:
        _remaining_seconds(deadline_ns)
    metadata_path = state_root / "enrollment.json"
    snapshot_optional_regular(metadata_path)
    if deadline_ns is not None:
        _remaining_seconds(deadline_ns)
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".enrollment.", dir=state_root)
    replaced = False
    try:
        os.fchmod(fd, 0o600)
        data = json.dumps({"schema": 1, "generation": generation, "uid": uid, "profile": profile,
                           "verified_nonce": verified_nonce, "reload_required": reload_required},
                          sort_keys=True).encode("ascii")
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        if deadline_ns is not None:
            _remaining_seconds(deadline_ns)
        os.replace(temporary, metadata_path)
        replaced = True
        fsync_dir(state_root)
        if deadline_ns is not None:
            _remaining_seconds(deadline_ns)
    except Exception:
        raise
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


def install_desktop(source: Path, parent: Path, state_root: Path, uid: int, gid: int) -> tuple[Path, Path]:
    target = parent / "skynet-edr"
    prior = state_root / "prior-desktop"
    if prior.exists():
        raise EnrollmentError("active_transaction", "MANUAL_RECOVERY_REQUIRED")
    stage = Path(tempfile.mkdtemp(prefix=".skynet-edr-desktop-", dir=state_root))
    mutation_started = False
    try:
        copy_generation_file(source / "desktop" / "plugin.js", stage / "plugin.js", uid, gid)
        os.chown(stage, uid, gid)
        fsync_dir(stage)
        if target.exists() or target.is_symlink():
            target_info = os.lstat(target)
            if (not stat.S_ISDIR(target_info.st_mode)
                    or {entry.name for entry in target.iterdir()} != {"plugin.js"}):
                raise EnrollmentError("invalid_target")
            mutation_started = True
            os.replace(target, prior)
        else:
            mutation_started = True
        os.replace(stage, target)
        fsync_dir(parent)
    except Exception:
        if not mutation_started and stage.exists():
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


def apply(request: dict[str, Any], source: Path, state_root: Path, observations: Path, adapter: Path) -> int:
    uid, home, profile, manifest = validate_request(request, source)
    gid = pwd.getpwuid(uid).pw_gid
    validate_managed_parents(home, uid, gid)
    require_same_filesystem(home, state_root)
    state_root_created = not exists_nofollow(state_root)
    state_parent_created = not exists_nofollow(state_root.parent)
    previous_observation = snapshot_optional_regular(observations)
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = enrollment_lock(state_root)
    lock_created = not exists_nofollow(lock_path)
    lock_parent_created = not exists_nofollow(lock_path.parent)
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (opened_user_directory(home, "plugins", uid, gid, create=True) as plugin_directory,
          opened_user_directory(home, "desktop-plugins", uid, gid, create=True) as desktop_directory,
          lock_path.open("a+b") as lock):
        opened, plugins_created = plugin_directory
        desktop_parent, desktop_parent_created = desktop_directory
        assert opened is not None and desktop_parent is not None
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if (state_root / "transaction.json").exists():
            return emit("MANUAL_RECOVERY_REQUIRED", "active_transaction")
        state, category = assess(request, home, state_root, manifest, observations, opened)
        initial_absent = state == "ABSENT"
        if state == "ENROLLED":
            return emit(state, category, noop=True)
        generation = canonical_generation(manifest)
        if state == "RELOAD_REQUIRED":
            if request.get("restart_authorized") is not True:
                return emit(state, category, noop=True)
            env = adapter_env(home, profile, observations, generation, uid)
            try:
                _, final_state, final_category = run_attest_lane(
                    adapter, env, observations, state_root, generation, uid, profile,
                    request, home, manifest, opened,
                )
            except EnrollmentError as exc:
                return emit(exc.state, exc.category)
            return emit(final_state, final_category) if final_state == "ENROLLED" else emit("DRIFTED", final_category)
        target_parent = opened
        target = target_parent / "skynet-edr"
        stage = state_root / f".skynet-edr-stage-{os.getpid()}"
        prior = state_root / "prior-generation"
        if stage.exists() or prior.exists():
            journal = new_quarantine_journal(
                secrets.token_hex(32), "rollback", uid, home, profile,
                canonical_generation(manifest),
            )
            journal["result"] = "MANUAL_RECOVERY_REQUIRED"
            try:
                write_quarantine_journal(state_root / "transaction.json", journal)
            except (EnrollmentError, OSError):
                pass
            return emit("MANUAL_RECOVERY_REQUIRED", "active_transaction")
        committed = False
        try:
            copy_generation(source, stage, manifest, uid, gid)
            if target.exists() or target.is_symlink():
                target_info = os.lstat(target)
                if not stat.S_ISDIR(target_info.st_mode):
                    raise EnrollmentError("invalid_target")
                os.replace(target, prior)
            committed = True
            os.replace(stage, target)
            fsync_dir(target_parent)
            install_desktop(source, desktop_parent, state_root, uid, gid)
            write_metadata(state_root, generation, uid, profile, None)
            run_adapter(adapter, "prepare", adapter_env(home, profile, observations, generation, uid), observations)
            env = adapter_env(home, profile, observations, generation, uid)
            enabled = run_adapter(adapter, "enable", env, observations)
            if enabled.get("plugin_enabled") is not True:
                raise EnrollmentError("enablement")
            if request.get("restart_authorized") is not True:
                write_metadata(state_root, generation, uid, profile, None, reload_required=True)
                return emit("RELOAD_REQUIRED", "reload_boundary")
            _, final_state, final_category = run_attest_lane(
                adapter, env, observations, state_root, generation, uid, profile,
                request, home, manifest, opened,
            )
            if final_state != "ENROLLED":
                raise EnrollmentError(final_category, final_state)
            return emit(final_state, final_category)
        except (EnrollmentError, OSError) as exc:
            failure_state = exc.state if isinstance(exc, EnrollmentError) else "DRIFTED"
            failure_category = exc.category if isinstance(exc, EnrollmentError) else "internal_failure"
            if committed:
                journal = new_quarantine_journal(
                    secrets.token_hex(32), "rollback", uid, home, profile, generation
                )
                journal["result"] = "MANUAL_RECOVERY_REQUIRED"
                try:
                    write_quarantine_journal(state_root / "transaction.json", journal)
                except (EnrollmentError, OSError):
                    pass
                return emit("MANUAL_RECOVERY_REQUIRED", failure_category)
            try:
                if initial_absent:
                    restore_optional_regular(observations, previous_observation)
                    if lock_created:
                        remove_created_regular(lock_path)
                    if state_root_created:
                        remove_created_directory(state_root)
                    if state_parent_created:
                        remove_created_directory(state_root.parent)
                    if lock_parent_created and lock_path.parent not in {state_root, state_root.parent}:
                        remove_created_directory(lock_path.parent)
                    if plugins_created is not None:
                        remove_empty_user_directory(home, "plugins", uid, plugins_created)
                    if desktop_parent_created is not None:
                        remove_empty_user_directory(
                            home, "desktop-plugins", uid, desktop_parent_created
                        )
            except (EnrollmentError, OSError):
                return emit("ROLLBACK_REQUIRED", "rollback")
            if stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
            return emit(failure_state, failure_category)


def _quarantine_one(journal_path: Path, journal: dict[str, Any], key: str,
                    source_fd: int, source_name: str, quarantine_fd: int,
                    quarantine_name: str, owner: int) -> None:
    record = journal["objects"].get(key)
    if record is None:
        try:
            source_identity = object_identity(source_fd, source_name, owner)
        except FileNotFoundError:
            return
        record = {
            "source_parent": _parent_identity(source_fd), "source_name": source_name,
            "source_identity": source_identity,
            "quarantine_parent": _parent_identity(quarantine_fd),
            "quarantine_name": quarantine_name,
            # rename preserves the exact object identity; recording this before the
            # syscall makes a crash after durable rename safely adoptable.
            "quarantine_identity": source_identity,
        }
        journal["objects"][key] = record
        journal["phase"] = "QUARANTINING"
        write_quarantine_journal(journal_path, journal)
    if (_parent_identity(source_fd) != record["source_parent"]
            or _parent_identity(quarantine_fd) != record["quarantine_parent"]):
        raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
    try:
        source_identity = object_identity(source_fd, source_name, owner)
    except FileNotFoundError:
        source_identity = None
    try:
        quarantine_identity = object_identity(quarantine_fd, quarantine_name, owner)
    except FileNotFoundError:
        quarantine_identity = None
    if source_identity is not None and quarantine_identity is not None:
        raise EnrollmentError("quarantine_collision", "MANUAL_RECOVERY_REQUIRED")
    if quarantine_identity is None:
        if source_identity != record["source_identity"]:
            raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
        quarantine_identity = detach_nondestructive(
            source_fd, source_name, quarantine_fd, quarantine_name, owner
        )
    if source_identity is None and quarantine_identity != record["quarantine_identity"]:
        raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")


def _fresh_quarantine_proof(journal: dict[str, Any], bindings: dict[str, tuple[int, int]]) -> None:
    for key, record in journal["objects"].items():
        source_fd, quarantine_fd = bindings[key]
        if (_parent_identity(source_fd) != record["source_parent"]
                or _parent_identity(quarantine_fd) != record["quarantine_parent"]):
            raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
        try:
            os.stat(record["source_name"], dir_fd=source_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise EnrollmentError("active_source", "MANUAL_RECOVERY_REQUIRED")
        owner = record["source_identity"]["uid"]
        if object_identity(quarantine_fd, record["quarantine_name"], owner) != record["quarantine_identity"]:
            raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")


def unenroll(request: dict[str, Any], source: Path, state_root: Path, observations: Path, adapter: Path) -> int:
    uid, home, profile, manifest = validate_request(request, source)
    gid = pwd.getpwuid(uid).pw_gid
    validate_managed_parents(home, uid, gid)
    require_same_filesystem(home, state_root)
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = enrollment_lock(state_root)
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (opened_user_directory(home, "plugins", uid, gid, create=False) as plugin_directory,
          opened_user_directory(home, "desktop-plugins", uid, gid, create=False) as desktop_directory,
          lock_path.open("a+b") as lock):
        plugins_parent, _ = plugin_directory
        desktop_parent, _ = desktop_directory
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        journal_path = state_root / "transaction.json"
        if plugins_parent is None and not (state_root / "enrollment.json").exists() and not journal_path.exists():
            return emit("ABSENT", "unenrolled", noop=True, success=True)
        if plugins_parent is None and not journal_path.exists():
            return emit("DRIFTED", "invalid_target")
        target = plugins_parent / "skynet-edr" if plugins_parent is not None else None
        if target is not None and not target.exists() and not (state_root / "enrollment.json").exists() and not journal_path.exists():
            return emit("ABSENT", "unenrolled", noop=True, success=True)
        generation = canonical_generation(manifest)
        repeated = journal_path.exists()
        journal = load_quarantine_journal(journal_path) if repeated else None
        if journal is not None and journal["target"] != {
                "uid": uid, "home": str(home), "profile": profile, "generation": generation}:
            return emit("MANUAL_RECOVERY_REQUIRED", "journal")
        if journal is None:
            if target is None or target.is_symlink() or not target.is_dir():
                return emit("DRIFTED", "invalid_target")
            try:
                validate_tree(target, manifest, installed_owner=request["uid"])
            except EnrollmentError:
                return emit("DRIFTED", "invalid_target")
        desktop = desktop_parent / "skynet-edr" if desktop_parent is not None else None
        if journal is None and desktop is not None and desktop.exists():
            expected = manifest["desktop/plugin.js"]
            plugin = desktop / "plugin.js"
            if (desktop.is_symlink() or not desktop.is_dir() or {entry.name for entry in desktop.iterdir()} != {"plugin.js"}
                    or plugin.is_symlink() or not plugin.is_file() or plugin.stat().st_nlink != 1
                    or plugin.stat().st_uid != request["uid"]
                    or plugin.stat().st_size != expected["size"]
                    or hashlib.sha256(plugin.read_bytes()).hexdigest() != expected["sha256"]):
                return emit("DRIFTED", "invalid_target")
        transaction_fd = -1
        quarantine_root_fd = -1
        private_state_fd = -1
        try:
            state_info = os.lstat(state_root)
            private_state_fd = open_private_state_directory(state_root, state_info.st_dev)
            quarantine_root = state_root / "quarantine"
            if exists_nofollow(quarantine_root):
                quarantine_root_fd = open_private_state_directory(quarantine_root, state_info.st_dev)
            if journal is None:
                nonce = secrets.token_hex(32)
                journal = new_quarantine_journal(nonce, "unenroll", uid, home, profile, generation)
                quarantine_root.mkdir(mode=0o700, exist_ok=True)
                quarantine_root_fd = open_private_state_directory(quarantine_root, state_info.st_dev)
                fsync_dir(state_root)
                transaction = quarantine_root / nonce
                transaction.mkdir(mode=0o700)
                fsync_dir(quarantine_root)
                write_quarantine_journal(journal_path, journal)
            else:
                nonce = journal["transaction_nonce"]
                transaction = quarantine_root / nonce
            if quarantine_root_fd < 0:
                raise EnrollmentError("unsupported_layout", "MANUAL_RECOVERY_REQUIRED")
            transaction_fd = open_private_state_directory(transaction, state_info.st_dev)
            transaction_info = os.fstat(transaction_fd)
            expected_owner = 0
            if (transaction_info.st_uid != expected_owner or transaction_info.st_mode & 0o022
                    or transaction_info.st_dev != os.fstat(quarantine_root_fd).st_dev):
                raise EnrollmentError("unsupported_layout", "MANUAL_RECOVERY_REQUIRED")
            if journal["phase"] == "QUARANTINED" and journal["result"] == "QUARANTINED":
                bindings: dict[str, tuple[int, int]] = {}
                for key in journal["objects"]:
                    if key == "backend" and plugins_parent is not None:
                        source_fd = os.open(plugins_parent, os.O_RDONLY | os.O_DIRECTORY)
                    elif key == "desktop" and desktop_parent is not None:
                        source_fd = os.open(desktop_parent, os.O_RDONLY | os.O_DIRECTORY)
                    elif key == "metadata":
                        source_fd = private_state_fd
                    elif key == "observation":
                        source_fd = os.open(observations.parent, os.O_RDONLY | os.O_DIRECTORY
                                            | os.O_NOFOLLOW)
                    else:
                        raise EnrollmentError("quarantine_identity", "MANUAL_RECOVERY_REQUIRED")
                    bindings[key] = (source_fd, transaction_fd)
                _fresh_quarantine_proof(journal, bindings)
                return emit("QUARANTINED", "unenrolled", noop=True, success=True)
            if journal["phase"] == "STARTED":
                disabled = run_adapter(adapter, "disable", adapter_env(home, profile, observations, generation, uid), observations)
                if set(disabled) != ADAPTER_BASE_KEYS["disable"] | ADAPTER_ENVELOPE_KEYS \
                        or disabled.get("plugin_enabled") is not False \
                        or disabled.get("loaded_generation") is not None \
                        or type(disabled.get("process_fresh")) is not bool:
                    raise EnrollmentError("enablement", "MANUAL_RECOVERY_REQUIRED")
                journal["phase"] = "DISABLED"
                write_quarantine_journal(journal_path, journal)
            if journal["phase"] == "DISABLED":
                restored = run_adapter(adapter, "rollback", adapter_env(home, profile, observations, generation, uid), observations)
                if set(restored) != ADAPTER_BASE_KEYS["rollback"] | ADAPTER_ENVELOPE_KEYS \
                        or restored.get("prepared") is not False \
                        or type(restored.get("plugin_enabled")) is not bool \
                        or restored.get("reload_required") is not True \
                        or restored.get("rollback_phase") != "RESTORED_VERIFIED":
                    raise EnrollmentError("rollback", "MANUAL_RECOVERY_REQUIRED")
                journal["phase"] = "ADAPTER_RESTORED"
                write_quarantine_journal(journal_path, journal)
            bindings: dict[str, tuple[int, int]] = {}
            if plugins_parent is not None:
                # opened_user_directory already pins and validates this proc-fd path.
                plugin_fd = os.open(plugins_parent, os.O_RDONLY | os.O_DIRECTORY)
                bindings["backend"] = (plugin_fd, transaction_fd)
                _quarantine_one(journal_path, journal, "backend", plugin_fd, "skynet-edr",
                                transaction_fd, "backend", uid)
            if desktop_parent is not None:
                desktop_fd = os.open(desktop_parent, os.O_RDONLY | os.O_DIRECTORY)
                bindings["desktop"] = (desktop_fd, transaction_fd)
                _quarantine_one(journal_path, journal, "desktop", desktop_fd, "skynet-edr",
                                transaction_fd, "desktop", uid)
            for key, path, name in (("metadata", state_root / "enrollment.json", "metadata"),
                                    ("observation", observations, "observation")):
                parent_fd = private_state_fd if path.parent == state_root else os.open(
                    path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                )
                bindings[key] = (parent_fd, transaction_fd)
                _quarantine_one(journal_path, journal, key, parent_fd, path.name,
                                transaction_fd, name, expected_owner)
            journal["phase"] = "QUARANTINED"
            journal["result"] = "QUARANTINED"
            write_quarantine_journal(journal_path, journal)
            _fresh_quarantine_proof(journal, bindings)
            return emit("QUARANTINED", "unenrolled", noop=repeated,
                        success=True)
        except (EnrollmentError, OSError) as exc:
            category = exc.category if isinstance(exc, EnrollmentError) else "internal_failure"
            if journal is not None:
                journal["result"] = "MANUAL_RECOVERY_REQUIRED"
                try:
                    write_quarantine_journal(journal_path, journal)
                except OSError:
                    pass
            return emit("MANUAL_RECOVERY_REQUIRED", category)
        finally:
            # Closing descriptors is not deletion; quarantined objects and the journal survive.
            for value in list(locals().get("bindings", {}).values()):
                fd = value[0]
                if fd != private_state_fd:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            for fd in (private_state_fd, transaction_fd, quarantine_root_fd):
                if fd >= 0:
                    os.close(fd)


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
        gid = pwd.getpwuid(request["uid"]).pw_gid
        validate_managed_parents(home, request["uid"], gid)
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
