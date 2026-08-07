#!/usr/bin/env python3
"""Bounded privileged host adapter for Skynet-EDR Hermes enrollment.

This executable is package-owned and intentionally has no path override flags.
It accepts only the fixed actions used by the enrollment transaction, emits one
bounded sanitized JSON object, and never forwards child diagnostics.
"""

from __future__ import annotations

import base64
import contextlib
import grp
import hashlib
import json
import os
import pwd
import re
import shlex
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, NamedTuple, cast

import tomllib

CONFIG = Path("/etc/skynet-edr/config.toml")
STATE_ROOT = Path("/var/lib/skynet-edr-hermes-enrollment/adapter")
DROPIN = Path("/etc/systemd/user/hermes-gateway.service.d/50-skynet-edr.conf")
SOCKET = Path("/run/skynet-edr-ingest/ingest.sock")
HERMES = Path("/usr/bin/hermes")
SYSTEMCTL = Path("/usr/bin/systemctl")
USERMOD = Path("/usr/sbin/usermod")
GPASSWD = Path("/usr/bin/gpasswd")
GROUP = "skynet-edr-ingest"
UNIT = "hermes-gateway.service"
DAEMON_UNIT = "skynet-edr.service"
MANAGED_MANAGER_ENVIRONMENT = (
    "HERMES_HOME",
    "HERMES_PROFILE",
    "HERMES_RUNTIME_ROLE",
    "PYTHONDONTWRITEBYTECODE",
    "SKYNET_EDR_PLUGIN_GENERATION",
    "SKYNET_EDR_ATTESTATION_TOKEN",
)
MAX_OUTPUT = 65_536
ATTEST_BUDGET_NS = 15_000_000_000
CLEANUP_BUDGET_NS = 15_000_000_000
POLL_SECONDS = 0.2
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CANARY_EVENT_ID = re.compile(r"^evt_skynet_attest_[0-9a-f]{64}$")
V3_SOURCE_KEYS = {
    "source_id", "authenticated_uid", "runtime_role", "protocol_version", "s3_eligible",
    "instance_id", "plugin_generation", "runtime_instance_nonce", "kernel_peer_pid",
    "kernel_peer_start_ticks", "commit_sequence", "events_persisted_total",
    "last_event_received_at_unix_ms", "last_event_committed_at_unix_ms",
    "producer_checkpoint_bytes", "backlog_bytes", "backlog_age_ms", "events_malformed_total",
    "events_dropped_total", "events_duplicate_total", "events_collision_total",
    "last_error_category", "last_error_at_unix_ms", "last_error_age_ms",
    "producer_reported_at_unix_ms", "producer_report_age_ms", "transport_state",
    "last_persisted_canary_event_id", "last_persisted_canary_receipt_status",
    "last_persisted_canary_incidents_opened",
}
STATUS_KEYS = {
    "product", "binary", "run_mode", "server", "read_only", "tool_count",
    "incident_count", "event_count", "version", "ingestion",
}
INGESTION_STATUS_KEYS = {
    "state", "role_identity_assurance", "listener_live", "transport_heartbeat_state",
    "hook_event_state", "hook_event_freshness_affects_state",
    "last_event_received_at_unix_ms", "last_event_received_age_ms",
    "last_event_committed_at_unix_ms", "last_event_committed_age_ms",
    "required_reported_roles", "connections_accepted_total",
    "connections_unauthorized_total", "connections_capacity_rejected_total",
    "listener_errors_total", "peer_credential_errors_total", "frames_received_total",
    "frames_oversize_total", "frames_invalid_total", "frames_timeout_total",
    "events_persisted_total", "events_duplicate_total", "events_collision_total",
    "incident_integrity_collision_total", "correlation_truncated_total",
    "storage_errors_total", "sources",
}
BOOT_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SAFE_PROFILE = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
SAFE_HOME = re.compile(r"^/[A-Za-z0-9_./@-]{1,4095}$")
INGEST_KEYS = {
    "enabled",
    "socket",
    "socket_group",
    "allowed_uids",
    "allow_root",
    "required_reported_roles",
}


class AdapterError(Exception):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


def _notify_parent_cleanup() -> None:
    raw_fd = os.environ.pop("SKYNET_EDR_CLEANUP_FD", "")
    if not raw_fd.isascii() or not raw_fd.isdigit():
        return
    fd = int(raw_fd)
    if fd < 3:
        return
    try:
        if not stat.S_ISFIFO(os.fstat(fd).st_mode):
            return
        if os.write(fd, b"C") != 1:
            return
    except OSError:
        return
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


@contextlib.contextmanager
def _deadline_watchdog(deadline_ns: int):
    started_ns = time.monotonic_ns()
    remaining = deadline_ns - started_ns
    if remaining <= 0:
        raise AdapterError("deadline")

    def expired(_signum: int, _frame: Any) -> None:
        _notify_parent_cleanup()
        raise AdapterError("deadline")

    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, remaining / 1_000_000_000)
    try:
        yield
        _check_deadline(deadline_ns)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        elapsed = max(0.0, (time.monotonic_ns() - started_ns) / 1_000_000_000)
        previous_delay = max(1e-9, previous_timer[0] - elapsed) if previous_timer[0] > 0 else 0.0
        signal.signal(signal.SIGALRM, previous_handler)
        signal.setitimer(signal.ITIMER_REAL, previous_delay, previous_timer[1])


class ProcessIdentity(NamedTuple):
    main_pid: int
    proc_start_ticks: int
    exec_start_monotonic_us: int


def _duplicates_rejected(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdapterError("command_failure")
        result[key] = value
    return result


def parse_bounded_json(data: bytes) -> Any:
    if not data or len(data) > MAX_OUTPUT:
        raise AdapterError("command_failure")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_duplicates_rejected)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, AdapterError):
            raise
        raise AdapterError("command_failure") from exc


def validate_context(action: str, env: dict[str, str], *, effective_uid: int | None = None) -> dict[str, Any]:
    if action not in {"prepare", "rollback", "enable", "disable", "attest"}:
        raise AdapterError("invalid_action")
    effective_uid = os.geteuid() if effective_uid is None else effective_uid
    privileged = action in {"prepare", "rollback", "attest"}
    if privileged and effective_uid != 0:
        raise AdapterError("identity")
    try:
        uid_text = env["SKYNET_EDR_TARGET_UID"]
        uid = int(uid_text)
        nonce = env["SKYNET_EDR_NONCE"]
        generation = env["SKYNET_EDR_GENERATION"]
        home_text = env["HERMES_HOME"]
        profile = env["HERMES_PROFILE"]
        expected_device = int(env["SKYNET_EDR_HOME_DEVICE"])
        expected_inode = int(env["SKYNET_EDR_HOME_INODE"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AdapterError("invalid_context") from exc
    if str(uid) != uid_text or uid <= 0 or uid > 2**31 - 1:
        raise AdapterError("identity")
    if not HEX64.fullmatch(nonce) or not HEX64.fullmatch(generation):
        raise AdapterError("invalid_context")
    deadline_ns = None
    attestation_token = None
    canary_event_id = None
    if action == "attest":
        try:
            deadline_text = env["SKYNET_EDR_DEADLINE_NS"]
            deadline_ns = int(deadline_text)
            attestation_token = env["SKYNET_EDR_ATTESTATION_TOKEN"]
            canary_event_id = env["SKYNET_EDR_CANARY_EVENT_ID"]
        except (KeyError, TypeError, ValueError) as exc:
            raise AdapterError("invalid_context") from exc
        if str(deadline_ns) != deadline_text or deadline_ns <= 0 or time.monotonic_ns() >= deadline_ns:
            raise AdapterError("deadline")
        expected_event_id = ""
        if type(attestation_token) is str and HEX64.fullmatch(attestation_token):
            expected_event_id = "evt_skynet_attest_" + hashlib.sha256(
                b"skynet-edr-attestation-v1\0" + attestation_token.encode("ascii")
            ).hexdigest()
        if (attestation_token in {nonce, generation} or canary_event_id != expected_event_id
                or CANARY_EVENT_ID.fullmatch(canary_event_id or "") is None):
            raise AdapterError("invalid_context")
    home = Path(home_text)
    if (not home.is_absolute() or ".." in home.parts or home == Path("/")
            or not SAFE_HOME.fullmatch(home_text)):
        raise AdapterError("invalid_context")
    if not SAFE_PROFILE.fullmatch(profile):
        raise AdapterError("invalid_context")
    if profile != "default":
        raise AdapterError("unsupported_contract")
    try:
        account = pwd.getpwuid(uid)
    except KeyError as exc:
        raise AdapterError("identity") from exc
    if action in {"enable", "disable"} and effective_uid != uid:
        raise AdapterError("identity")
    if home != Path(account.pw_dir) / ".hermes":
        raise AdapterError("untrusted_path")
    try:
        home_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        home_info = os.fstat(home_fd)
    except OSError as exc:
        raise AdapterError("untrusted_path") from exc
    if ((home_info.st_dev, home_info.st_ino) != (expected_device, expected_inode)
            or home_info.st_uid != uid or home_info.st_mode & 0o022):
        os.close(home_fd)
        raise AdapterError("untrusted_path")
    ingest_gid = None
    if action == "attest":
        try:
            ingest_gid = grp.getgrnam(GROUP).gr_gid
        except KeyError as exc:
            raise AdapterError("missing_prerequisite") from exc
    return {"uid": uid, "account": account.pw_name, "account_gid": account.pw_gid,
            "ingest_gid": ingest_gid,
            "home": home, "profile": profile,
            "nonce": nonce, "generation": generation, "action": action, "home_fd": home_fd,
            "deadline_ns": deadline_ns, "attestation_token": attestation_token,
            "canary_event_id": canary_event_id}


def _toml_ingest(text: str) -> dict[str, Any]:
    if len(text.encode("utf-8")) > 1_048_576 or text.count("[ingest]") != 1:
        raise AdapterError("config_ambiguous")
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, UnicodeError, RecursionError) as exc:
        raise AdapterError("config_ambiguous") from exc
    ingest = document.get("ingest")
    if type(ingest) is not dict or not INGEST_KEYS.issubset(ingest):
        raise AdapterError("config_ambiguous")
    if type(ingest["enabled"]) is not bool or type(ingest["allow_root"]) is not bool:
        raise AdapterError("config_ambiguous")
    if ingest["allow_root"] is not False:
        raise AdapterError("authorization")
    if ingest["socket"] != str(SOCKET) or ingest["socket_group"] != GROUP:
        raise AdapterError("authorization")
    uids = ingest["allowed_uids"]
    roles = ingest["required_reported_roles"]
    if type(uids) is not list or any(type(uid) is not int or uid <= 0 for uid in uids) or len(set(uids)) != len(uids):
        raise AdapterError("config_ambiguous")
    if type(roles) is not list or any(type(role) is not str for role in roles) or len(set(roles)) != len(roles):
        raise AdapterError("config_ambiguous")
    if any(role != "gateway" for role in roles):
        raise AdapterError("authorization")
    return ingest


def _replace_ingest_key(text: str, key: str, value: str) -> str:
    lines = text.splitlines(keepends=True)
    in_ingest = False
    found = 0
    pattern = re.compile(rf"^(\s*){re.escape(key)}\s*=.*?(\r?\n)?$")
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_ingest = stripped == "[ingest]"
        if in_ingest and pattern.fullmatch(line):
            found += 1
            newline = "\r\n" if line.endswith("\r\n") else "\n"
            lines[index] = f"{key} = {value}{newline}"
    if found != 1:
        raise AdapterError("config_ambiguous")
    return "".join(lines)


def rewrite_ingest_toml(text: str, uid: int, *, enabled: bool) -> str:
    ingest = _toml_ingest(text)
    uids = sorted(set(ingest["allowed_uids"]) | {uid}) if enabled else sorted(set(ingest["allowed_uids"]) - {uid})
    roles = ["gateway"] if uids else []
    replacements = {
        "enabled": "true" if uids else "false",
        "socket_group": json.dumps(GROUP),
        "allowed_uids": json.dumps(uids, separators=(", ", ":")),
        "allow_root": "false",
        "required_reported_roles": json.dumps(roles, separators=(", ", ":")),
    }
    updated = text
    for key, value in replacements.items():
        updated = _replace_ingest_key(updated, key, value)
    _toml_ingest(updated)
    return updated


def render_dropin(units: list[str], generation: str, home: Path, profile: str,
                  attestation_token: str | None = None) -> str:
    if units != [UNIT]:
        raise AdapterError("unit_scope")
    if profile != "default" or home.name != ".hermes":
        raise AdapterError("unsupported_contract")
    if attestation_token is not None and not HEX64.fullmatch(attestation_token):
        raise AdapterError("invalid_context")
    token_line = (f"Environment=SKYNET_EDR_ATTESTATION_TOKEN={attestation_token}\n"
                  if attestation_token is not None else "")
    return ("[Service]\n"
            "Environment=HERMES_RUNTIME_ROLE=gateway\n"
            f"Environment=SKYNET_EDR_PLUGIN_GENERATION={generation}\n"
            f"{token_line}"
            "Environment=HERMES_HOME=%h/.hermes\n"
            "Environment=HERMES_PROFILE=default\n"
            "Environment=PYTHONDONTWRITEBYTECODE=1\n")


def authorization_ok(*, dac: bool, configured_uids: list[int], target_uid: int) -> bool:
    return dac and target_uid != 0 and target_uid in configured_uids


def socket_dac_ok(path: Path, group_id: int) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o660 and info.st_gid == group_id


def _safe_regular(path: Path, *, may_be_absent: bool = False) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if may_be_absent:
            return
        raise AdapterError("missing_prerequisite")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o022:
        raise AdapterError("untrusted_path")


def _trusted_parent(path: Path, *, require_existing: bool = False) -> None:
    current = Path("/")
    for component in path.parent.parts[1:]:
        current /= component
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if require_existing:
                raise AdapterError("missing_prerequisite")
            break
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != 0 or info.st_mode & 0o022):
            raise AdapterError("untrusted_path")


def _resolve_hermes_launcher(entry: Path) -> Path:
    normalized_entry = Path(os.path.normpath(str(entry)))
    if not entry.is_absolute() or normalized_entry != entry:
        raise AdapterError("untrusted_path")
    current = entry
    visited: set[Path] = set()
    symlink_count = 0
    while True:
        if current in visited:
            raise AdapterError("untrusted_path")
        visited.add(current)
        _trusted_parent(current, require_existing=True)
        try:
            info = os.lstat(current)
        except FileNotFoundError as exc:
            raise AdapterError("missing_prerequisite") from exc
        if stat.S_ISLNK(info.st_mode):
            if info.st_uid != 0 or info.st_nlink != 1:
                raise AdapterError("untrusted_path")
            symlink_count += 1
            if symlink_count > 8:
                raise AdapterError("untrusted_path")
            try:
                raw_target = os.readlink(current)
            except OSError as exc:
                raise AdapterError("untrusted_path") from exc
            target = Path(raw_target)
            if not target.is_absolute():
                if ".." in target.parts:
                    raise AdapterError("untrusted_path")
                target = current.parent / target
            current = Path(os.path.normpath(str(target)))
            if not current.is_absolute():
                raise AdapterError("untrusted_path")
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                or info.st_mode & 0o022 or not info.st_mode & 0o111):
            raise AdapterError("untrusted_path")
        return current


def _hermes_launcher(context: dict[str, Any]) -> Path:
    launcher = context.get("_hermes_launcher")
    if launcher is None:
        launcher = _resolve_hermes_launcher(HERMES)
        context["_hermes_launcher"] = launcher
    if not isinstance(launcher, Path):
        raise AdapterError("untrusted_path")
    return launcher


def snapshot_files(paths: dict[str, Path]) -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    for name, path in paths.items():
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            snapshot[name] = {"exists": False}
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AdapterError("untrusted_path")
        data = path.read_bytes()
        if len(data) > 1_048_576:
            raise AdapterError("untrusted_path")
        snapshot[name] = {"exists": True, "data": base64.b64encode(data).decode("ascii"),
                          "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}
    return snapshot


def _atomic_write(path: Path, data: bytes, mode: int, uid: int = 0, gid: int = 0, *,
                  deadline_ns: int | None = None) -> None:
    if deadline_ns is not None:
        _check_deadline(deadline_ns)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    if deadline_ns is not None:
        _check_deadline(deadline_ns)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if deadline_ns is not None:
            _check_deadline(deadline_ns)
        os.fchmod(fd, mode)
        if os.geteuid() == 0:
            os.fchown(fd, uid, gid)
        os.write(fd, data)
        os.fsync(fd)
        if deadline_ns is not None:
            _check_deadline(deadline_ns)
        os.close(fd)
        fd = -1
        if deadline_ns is not None:
            _check_deadline(deadline_ns)
        os.replace(temporary, path)
        if deadline_ns is not None:
            _check_deadline(deadline_ns)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
            if deadline_ns is not None:
                _check_deadline(deadline_ns)
        finally:
            os.close(directory)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def restore_files(snapshot: dict[str, dict[str, Any]], paths: dict[str, Path]) -> None:
    if set(snapshot) != set(paths):
        raise AdapterError("rollback")
    for name, path in paths.items():
        item = snapshot[name]
        if item.get("exists") is False:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            continue
        try:
            data = base64.b64decode(item["data"], validate=True)
            mode, uid, gid = int(item["mode"]), int(item["uid"]), int(item["gid"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AdapterError("rollback") from exc
        _atomic_write(path, data, mode, uid, gid)


def _scope(context: dict[str, Any]) -> Path:
    identity = f"{context['uid']}\0{context['profile']}".encode("utf-8")
    return STATE_ROOT / hashlib.sha256(identity).hexdigest()


def _managed_state() -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for name, path in {"config": CONFIG, "dropin": DROPIN}.items():
        try:
            os.lstat(path)
        except FileNotFoundError:
            result[name] = None
            continue
        _safe_regular(path)
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _verify_managed() -> None:
    path = STATE_ROOT / "managed.json"
    if not path.exists():
        return
    _safe_regular(path)
    expected = parse_bounded_json(path.read_bytes())
    if type(expected) is not dict or expected != _managed_state():
        raise AdapterError("config_drift")


def _write_managed() -> None:
    data = json.dumps(_managed_state(), sort_keys=True).encode("ascii")
    _atomic_write(STATE_ROOT / "managed.json", data, 0o600)


def _runtime_instance(context: dict[str, Any]) -> str:
    return context["generation"]


def _remaining_seconds(deadline_ns: int, cap: float | None = None) -> float:
    remaining_ns = deadline_ns - time.monotonic_ns()
    if remaining_ns <= 0:
        raise AdapterError("deadline")
    remaining = remaining_ns / 1_000_000_000
    return min(remaining, cap) if cap is not None else remaining


def _check_deadline(deadline_ns: int) -> None:
    if time.monotonic_ns() >= deadline_ns:
        raise AdapterError("deadline")


def _bounded_sleep(deadline_ns: int, cap: float = POLL_SECONDS) -> None:
    time.sleep(_remaining_seconds(deadline_ns, cap))
    _check_deadline(deadline_ns)


def _wait_for_socket_ready(path: Path, expected_gid: int, deadline_ns: int) -> bool:
    while True:
        _check_deadline(deadline_ns)
        try:
            socket_info = os.lstat(path)
        except FileNotFoundError:
            _bounded_sleep(deadline_ns)
            continue
        except OSError as exc:
            raise AdapterError("readback_failure") from exc
        if not stat.S_ISSOCK(socket_info.st_mode):
            raise AdapterError("readback_failure")
        if stat.S_IMODE(socket_info.st_mode) == 0o660 and socket_info.st_gid == expected_gid:
            return True
        _bounded_sleep(deadline_ns)


def _run(argv: list[str], *, env: dict[str, str], target: dict[str, Any] | None = None,
         deadline_ns: int | None = None, operation_cap: float = 30.0) -> bytes:
    def drop_identity() -> None:
        if target is None:
            return
        os.setgroups([])
        os.setgid(target["account_gid"])
        os.setuid(target["uid"])

    try:
        timeout = operation_cap if deadline_ns is None else _remaining_seconds(deadline_ns, operation_cap)
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=env, timeout=timeout, check=False,
                                preexec_fn=drop_identity if target else None)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AdapterError("command_failure") from exc
    if deadline_ns is not None:
        _check_deadline(deadline_ns)
    if result.returncode != 0 or len(result.stdout) > MAX_OUTPUT:
        raise AdapterError("command_failure")
    return result.stdout


def _minimal_env(context: dict[str, Any]) -> dict[str, str]:
    environment = {"HOME": str(context["home"].parent), "HERMES_HOME": str(context["home"]),
            "HERMES_PROFILE": context["profile"], "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "XDG_RUNTIME_DIR": f"/run/user/{context['uid']}",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{context['uid']}/bus"}
    if context.get("attestation_token") is not None:
        environment["SKYNET_EDR_ATTESTATION_TOKEN"] = context["attestation_token"]
    return environment


def _import_manager_environment(context: dict[str, Any], deadline_ns: int) -> None:
    environment = _minimal_env(context)
    environment.update({
        "HERMES_RUNTIME_ROLE": "gateway",
        "SKYNET_EDR_PLUGIN_GENERATION": context["generation"],
    })
    if set(MANAGED_MANAGER_ENVIRONMENT) - environment.keys():
        raise AdapterError("invalid_context")
    _run(
        [str(SYSTEMCTL), "--user", "import-environment", *MANAGED_MANAGER_ENVIRONMENT],
        env=environment,
        target=context,
        deadline_ns=deadline_ns,
    )


def _clear_manager_environment(context: dict[str, Any], deadline_ns: int | None = None) -> None:
    if deadline_ns is None:
        deadline_ns = time.monotonic_ns() + CLEANUP_BUDGET_NS
    environment = _minimal_env(context)
    try:
        _run(
            [str(SYSTEMCTL), "--user", "unset-environment", *MANAGED_MANAGER_ENVIRONMENT],
            env=environment,
            target=context,
            deadline_ns=deadline_ns,
        )
        _run([str(SYSTEMCTL), "--user", "restart", UNIT], env=environment, target=context,
             deadline_ns=deadline_ns)
        _run(
            [str(SYSTEMCTL), "restart", DAEMON_UNIT],
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            deadline_ns=deadline_ns,
        )
        shown = _run(
            [str(SYSTEMCTL), "--user", "show-environment"],
            env=environment,
            target=context,
            deadline_ns=deadline_ns,
        )
        names: set[str] = set()
        for line in shown.splitlines():
            try:
                name, _value = line.decode("utf-8").split("=", 1)
            except (UnicodeError, ValueError) as exc:
                raise AdapterError("rollback") from exc
            names.add(name)
        if names.intersection(MANAGED_MANAGER_ENVIRONMENT):
            raise AdapterError("rollback")
    except AdapterError as exc:
        if exc.category == "rollback":
            raise
        raise AdapterError("rollback") from exc


def _clear_manager_attestation_token(context: dict[str, Any], deadline_ns: int) -> None:
    environment = _minimal_env(context)
    _run(
        [str(SYSTEMCTL), "--user", "unset-environment", "SKYNET_EDR_ATTESTATION_TOKEN"],
        env=environment,
        target=context,
        deadline_ns=deadline_ns,
    )
    shown = _run(
        [str(SYSTEMCTL), "--user", "show-environment"],
        env=environment,
        target=context,
        deadline_ns=deadline_ns,
    )
    for line in shown.splitlines():
        try:
            name, _value = line.decode("utf-8").split("=", 1)
        except (UnicodeError, ValueError) as exc:
            raise AdapterError("readback_failure") from exc
        if name == "SKYNET_EDR_ATTESTATION_TOKEN":
            raise AdapterError("readback_failure")


def _plugin_enabled(context: dict[str, Any], deadline_ns: int | None = None) -> bool:
    target = context if os.geteuid() == 0 else None
    value = parse_bounded_json(_run([str(_hermes_launcher(context)), "plugins", "list", "--json"],
                                    env=_minimal_env(context), target=target, deadline_ns=deadline_ns))
    if type(value) is dict:
        value = value.get("plugins")
    if type(value) is not list:
        raise AdapterError("readback_failure")
    matches = [item for item in value if type(item) is dict and item.get("name") == "skynet-edr"]
    if len(matches) != 1 or "enabled" in matches[0]:
        raise AdapterError("readback_failure")
    status = matches[0].get("status")
    if status == "enabled":
        return True
    if status == "not enabled":
        return False
    raise AdapterError("readback_failure")


def _status(deadline_ns: int | None = None, *, allow_disabled: bool = False) -> dict[str, Any]:
    if deadline_ns is None:
        deadline_ns = time.monotonic_ns() + 3_000_000_000
    response = bytearray()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(_remaining_seconds(deadline_ns, 3.0))
            client.connect(("127.0.0.1", 8787))
            request = b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            client.settimeout(_remaining_seconds(deadline_ns, 1.0))
            client.sendall(request)
            while len(response) <= MAX_OUTPUT + 8192:
                client.settimeout(_remaining_seconds(deadline_ns, 1.0))
                part = client.recv(4096)
                _check_deadline(deadline_ns)
                if not part:
                    break
                response.extend(part)
    except (OSError, TimeoutError) as exc:
        raise AdapterError("readback_failure") from exc
    if len(response) > MAX_OUTPUT + 8192 or b"\r\n\r\n" not in response:
        raise AdapterError("readback_failure")
    raw_headers, body = bytes(response).split(b"\r\n\r\n", 1)
    lines = raw_headers.split(b"\r\n")
    if not lines or lines[0] != b"HTTP/1.1 200 OK":
        raise AdapterError("readback_failure")
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        if b":" not in line:
            raise AdapterError("readback_failure")
        name, value = line.split(b":", 1)
        name = name.strip().lower()
        if name in headers:
            raise AdapterError("readback_failure")
        headers[name] = value.strip()
    if b"transfer-encoding" in headers:
        raise AdapterError("readback_failure")
    try:
        length = int(headers[b"content-length"])
    except (KeyError, ValueError) as exc:
        raise AdapterError("readback_failure") from exc
    if length < 1 or length > MAX_OUTPUT or len(body) != length:
        raise AdapterError("readback_failure")
    value = parse_bounded_json(body)
    if type(value) is not dict:
        raise AdapterError("readback_failure")
    ingestion = value.get("ingestion")
    if allow_disabled and type(ingestion) is dict and ingestion.get("state") == "disabled":
        _validate_disabled_status_schema(value)
    else:
        _validate_status_schema(value)
    return value


def _validate_status_root(status: dict[str, Any]) -> dict[str, Any]:
    if set(status) != STATUS_KEYS:
        raise AdapterError("readback_failure")
    ingestion = status.get("ingestion")
    root_counts = ("tool_count", "incident_count", "event_count")
    if (type(ingestion) is not dict
            or status.get("product") != "Skynet-EDR" or status.get("binary") != "skynet-edr"
            or status.get("run_mode") != "passive" or status.get("server") != "skynet-edr-mcp"
            or status.get("read_only") is not True
            or type(status.get("version")) is not str or not status["version"]
            or any(type(status.get(key)) is not int or status[key] < 0 for key in root_counts)):
        raise AdapterError("readback_failure")
    return ingestion


def _validate_disabled_status_schema(status: dict[str, Any]) -> dict[str, Any]:
    ingestion = _validate_status_root(status)
    if (set(ingestion) != {"state", "role_identity_assurance", "listener_live", "sources"}
            or ingestion.get("state") != "disabled"
            or ingestion.get("role_identity_assurance") != "authorized_uid_self_reported"
            or ingestion.get("listener_live") is not False
            or type(ingestion.get("sources")) is not list or ingestion["sources"]):
        raise AdapterError("readback_failure")
    return ingestion


def _validate_status_schema(status: dict[str, Any]) -> dict[str, Any]:
    ingestion = _validate_status_root(status)
    if set(ingestion) != INGESTION_STATUS_KEYS:
        raise AdapterError("readback_failure")
    ingestion_counts = (
        "connections_accepted_total", "connections_unauthorized_total",
        "connections_capacity_rejected_total", "listener_errors_total",
        "peer_credential_errors_total", "frames_received_total", "frames_oversize_total",
        "frames_invalid_total", "frames_timeout_total", "events_persisted_total",
        "events_duplicate_total", "events_collision_total", "incident_integrity_collision_total",
        "correlation_truncated_total", "storage_errors_total",
    )
    optional_times = (
        "last_event_received_at_unix_ms", "last_event_received_age_ms",
        "last_event_committed_at_unix_ms", "last_event_committed_age_ms",
    )
    required = ingestion.get("required_reported_roles")
    if (ingestion.get("state") not in {"healthy", "degraded"}
            or ingestion.get("role_identity_assurance") != "authorized_uid_self_reported"
            or type(ingestion.get("listener_live")) is not bool
            or ingestion.get("transport_heartbeat_state") not in {"fresh", "stale", "not_observed"}
            or ingestion.get("hook_event_state") not in {"fresh", "stale", "not_observed"}
            or ingestion.get("hook_event_freshness_affects_state") is not False
            or any(value is not None and (type(value) is not int or value < 0)
                   for value in (ingestion.get(key) for key in optional_times))
            or any(type(ingestion.get(key)) is not int or ingestion[key] < 0
                   for key in ingestion_counts)
            or type(required) is not list or len(required) != 1
            or type(required[0]) is not dict
            or set(required[0]) != {"runtime_role", "state"}
            or required[0].get("runtime_role") != "gateway"
            or required[0].get("state") not in {"fresh", "stale", "absent"}
            or type(ingestion.get("sources")) is not list):
        raise AdapterError("readback_failure")
    return ingestion


def _source_identity(source: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(source.get(key) for key in (
        "authenticated_uid", "runtime_role", "plugin_generation", "runtime_instance_nonce",
        "kernel_peer_pid", "kernel_peer_start_ticks",
    ))


def _exact_source(ingestion: dict[str, Any], context: dict[str, Any],
                  gateway: ProcessIdentity, *, reject_competing: bool = True) -> dict[str, Any]:
    sources = ingestion.get("sources")
    if type(sources) is not list:
        raise AdapterError("source_cardinality")
    competing = [source for source in sources if type(source) is dict
                 and type(source.get("authenticated_uid")) is int
                 and source.get("authenticated_uid") == context["uid"]
                 and type(source.get("protocol_version")) is int
                 and source.get("protocol_version") == 3
                 and source.get("plugin_generation") == context["generation"]]
    if reject_competing and len(competing) != 1:
        raise AdapterError("source_missing" if not competing else "source_cardinality")
    matches = [source for source in sources if type(source) is dict
               and type(source.get("authenticated_uid")) is int
               and source.get("authenticated_uid") == context["uid"]
               and source.get("runtime_role") == "gateway"
               and type(source.get("protocol_version")) is int
               and source.get("protocol_version") == 3
               and source.get("plugin_generation") == context["generation"]
               and type(source.get("kernel_peer_pid")) is int
               and source.get("kernel_peer_pid") == gateway.main_pid
               and type(source.get("kernel_peer_start_ticks")) is int
               and source.get("kernel_peer_start_ticks") == gateway.proc_start_ticks]
    if len(matches) != 1:
        raise AdapterError("source_missing" if not matches else "source_cardinality")
    source = matches[0]
    if set(source) != V3_SOURCE_KEYS:
        raise AdapterError("producer_health")
    nonce = source.get("runtime_instance_nonce")
    age = source.get("producer_report_age_ms")
    integer_fields = ("authenticated_uid", "protocol_version", "kernel_peer_pid",
                      "kernel_peer_start_ticks", "commit_sequence", "events_persisted_total",
                      "producer_checkpoint_bytes", "backlog_bytes", "events_malformed_total",
                      "events_dropped_total", "events_duplicate_total", "events_collision_total",
                      "producer_reported_at_unix_ms", "producer_report_age_ms")
    timestamps = ("last_event_received_at_unix_ms", "last_event_committed_at_unix_ms")
    canary_values = (source.get("last_persisted_canary_event_id"),
                     source.get("last_persisted_canary_receipt_status"),
                     source.get("last_persisted_canary_incidents_opened"))
    canary_valid = (canary_values == (None, None, None)
                    or (type(canary_values[0]) is str
                        and CANARY_EVENT_ID.fullmatch(canary_values[0]) is not None
                        and canary_values[1] == "persisted"
                        and type(canary_values[2]) is int and canary_values[2] >= 0))
    source_id = f"uid:{context['uid']}:gateway:{context['generation']}:{nonce}"
    if (source.get("source_id") != source_id or source.get("s3_eligible") is not True
            or source.get("instance_id") is not None
            or type(nonce) is not str or not HEX64.fullmatch(nonce)
            or nonce in {context["generation"], context.get("attestation_token")}
            or any(type(source.get(field)) is not int or source[field] < 0 for field in integer_fields)
            or any(value is not None and (type(value) is not int or value < 0)
                   for value in (source.get(field) for field in timestamps))
            or type(age) is not int or not 0 <= age <= 30_000
            or source.get("transport_state") != "available"
            or source.get("backlog_bytes") != 0 or source.get("backlog_age_ms") is not None
            or (source.get("last_error_category"), source.get("last_error_at_unix_ms"),
                source.get("last_error_age_ms")) != (None, None, None)
            or not canary_valid):
        raise AdapterError("producer_health")
    return source


def _persisted_advanced(before: dict[str, Any], after: dict[str, Any], event_id: str) -> bool:
    before_sequence = before.get("commit_sequence")
    before_persisted = before.get("events_persisted_total")
    after_sequence = after.get("commit_sequence")
    after_persisted = after.get("events_persisted_total")
    integers = (before_sequence, before_persisted, after_sequence, after_persisted)
    failure_fields = ("events_malformed_total", "events_dropped_total",
                      "events_duplicate_total", "events_collision_total")
    if not all(type(value) is int and value >= 0 for value in integers):
        return False
    return (all(type(before.get(field)) is int and type(after.get(field)) is int
                    and before[field] == 0 and after[field] == 0 for field in failure_fields)
            and before.get("last_error_category") is None
            and after.get("last_error_category") is None
            and after.get("last_persisted_canary_event_id") == event_id
            and after.get("last_persisted_canary_receipt_status") == "persisted"
            and after.get("last_persisted_canary_incidents_opened") == 0
            and _source_identity(before) == _source_identity(after)
            and cast(int, after_sequence) - cast(int, before_sequence) == 1
            and cast(int, after_persisted) - cast(int, before_persisted) == 1)


def _startup_canary_baseline(source: dict[str, Any], event_id: str) -> dict[str, Any]:
    """Return the observable baseline, including safe replay-before-read handling."""
    receipt = (
        source.get("last_persisted_canary_event_id"),
        source.get("last_persisted_canary_receipt_status"),
        source.get("last_persisted_canary_incidents_opened"),
    )
    if receipt == (None, None, None):
        return source
    failure_fields = ("events_malformed_total", "events_dropped_total",
                      "events_duplicate_total", "events_collision_total")
    if (receipt != (event_id, "persisted", 0)
            or source.get("commit_sequence") != 1
            or source.get("events_persisted_total") != 1
            or any(source.get(field) != 0 for field in failure_fields)
            or source.get("last_error_category") is not None):
        raise AdapterError("hook_failure")
    baseline = dict(source)
    baseline["commit_sequence"] = 0
    baseline["events_persisted_total"] = 0
    baseline["last_persisted_canary_event_id"] = None
    baseline["last_persisted_canary_receipt_status"] = None
    baseline["last_persisted_canary_incidents_opened"] = None
    return baseline


def _previous_runtime_nonce(status: dict[str, Any], context: dict[str, Any],
                            gateway: ProcessIdentity) -> str | None:
    ingestion = status.get("ingestion")
    if type(ingestion) is not dict or type(ingestion.get("sources")) is not list:
        return None
    try:
        source = _exact_source(ingestion, context, gateway, reject_competing=False)
    except AdapterError as exc:
        if exc.category == "source_missing":
            return None
        raise
    nonce = source["runtime_instance_nonce"]
    if nonce == context.get("attestation_token"):
        raise AdapterError("producer_health")
    if type(nonce) is not str:
        return None
    return nonce


def _proc_start_ticks(pid: int, deadline_ns: int) -> int:
    _check_deadline(deadline_ns)
    try:
        fd = os.open(Path("/proc") / str(pid) / "stat", os.O_RDONLY | os.O_NOFOLLOW)
        try:
            _check_deadline(deadline_ns)
            data = os.read(fd, MAX_OUTPUT + 1)
        finally:
            os.close(fd)
    except FileNotFoundError as exc:
        raise AdapterError("process_missing") from exc
    except OSError as exc:
        raise AdapterError("readback_failure") from exc
    _check_deadline(deadline_ns)
    if len(data) > MAX_OUTPUT:
        raise AdapterError("readback_failure")
    try:
        text = data.decode("ascii")
        fields = text[text.rindex(")") + 2:].split()
        value = int(fields[19])
    except (UnicodeError, ValueError, IndexError) as exc:
        raise AdapterError("readback_failure") from exc
    if value <= 0:
        raise AdapterError("readback_failure")
    return value


def _service_identity(context: dict[str, Any], unit: str, deadline_ns: int) -> ProcessIdentity:
    user_unit = unit == UNIT
    argv = [str(SYSTEMCTL)]
    if user_unit:
        argv.append("--user")
    argv.extend(["show", unit, "--property=MainPID",
                 "--property=ExecMainStartTimestampMonotonic", "--value"])
    raw = _run(
        argv,
        env=_minimal_env(context) if user_unit else {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        target=context if user_unit and os.geteuid() == 0 else None,
        deadline_ns=deadline_ns,
    )
    try:
        values = [int(value) for value in raw.decode("ascii").splitlines()]
    except (UnicodeError, ValueError) as exc:
        raise AdapterError("readback_failure") from exc
    if len(values) != 2 or any(value <= 0 for value in values):
        raise AdapterError("readback_failure")
    return ProcessIdentity(values[0], _proc_start_ticks(values[0], deadline_ns), values[1])


def _process_groups(pid: int, deadline_ns: int) -> set[int]:
    if type(pid) is not int or pid <= 0:
        raise AdapterError("readback_failure")
    _check_deadline(deadline_ns)
    path = Path("/proc") / str(pid) / "status"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            _check_deadline(deadline_ns)
            info = os.fstat(fd)
            _check_deadline(deadline_ns)
            data = os.read(fd, MAX_OUTPUT + 1)
        finally:
            os.close(fd)
    except OSError as exc:
        raise AdapterError("readback_failure") from exc
    _check_deadline(deadline_ns)
    if not stat.S_ISREG(info.st_mode) or len(data) > MAX_OUTPUT:
        raise AdapterError("readback_failure")
    try:
        lines = data.decode("ascii").splitlines()
        groups_lines = [line for line in lines if line.startswith("Groups:")]
        if len(groups_lines) != 1:
            raise ValueError("ambiguous groups")
        groups = {int(value) for value in groups_lines[0].split()[1:]}
    except (UnicodeError, ValueError) as exc:
        raise AdapterError("readback_failure") from exc
    return groups


def _gateway_context_matches(context: dict[str, Any], deadline_ns: int | None = None) -> bool:
    raw = _run(
        [str(SYSTEMCTL), "--user", "show", UNIT, "--property=Environment", "--value"],
        env=_minimal_env(context),
        target=context if os.geteuid() == 0 else None,
        deadline_ns=deadline_ns,
    )
    try:
        values = set(shlex.split(raw.decode("utf-8")))
    except (UnicodeError, ValueError):
        return False
    expected = {
        f"HERMES_HOME={context['home']}",
        f"HERMES_PROFILE={context['profile']}",
        "HERMES_RUNTIME_ROLE=gateway",
        "PYTHONDONTWRITEBYTECODE=1",
        f"SKYNET_EDR_PLUGIN_GENERATION={context['generation']}",
    }
    if context.get("attestation_token") is not None:
        expected.add(f"SKYNET_EDR_ATTESTATION_TOKEN={context['attestation_token']}")
    return expected.issubset(values)


def _boot_id(deadline_ns: int | None = None) -> str:
    if deadline_ns is not None:
        _check_deadline(deadline_ns)
    try:
        fd = os.open("/proc/sys/kernel/random/boot_id", os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if deadline_ns is not None:
                _check_deadline(deadline_ns)
            data = os.read(fd, 64)
        finally:
            os.close(fd)
    except OSError as exc:
        raise AdapterError("readback_failure") from exc
    if deadline_ns is not None:
        _check_deadline(deadline_ns)
    try:
        value = data.decode("ascii").strip()
    except UnicodeError as exc:
        raise AdapterError("readback_failure") from exc
    if not BOOT_ID.fullmatch(value):
        raise AdapterError("readback_failure")
    return value


def _record_attestation(context: dict[str, Any], observation: dict[str, Any],
                        deadline_ns: int, boot_id: str) -> None:
    _check_deadline(deadline_ns)
    snapshot_path = _scope(context) / "snapshot.json"
    _safe_regular(snapshot_path)
    _check_deadline(deadline_ns)
    snapshot_bytes = snapshot_path.read_bytes()
    _check_deadline(deadline_ns)
    snapshot = parse_bounded_json(snapshot_bytes)
    _check_deadline(deadline_ns)
    if type(snapshot) is not dict or snapshot.get("generation") != context["generation"]:
        raise AdapterError("readback_failure")
    snapshot["attestation"] = {
        "boot_id": boot_id, "deadline_ns": deadline_ns, "observation": observation,
    }
    try:
        _atomic_write(
            snapshot_path, json.dumps(snapshot, sort_keys=True).encode("ascii"), 0o600,
            deadline_ns=deadline_ns,
        )
    except Exception:
        try:
            _atomic_write(snapshot_path, snapshot_bytes, 0o600)
        except Exception as rollback_error:
            raise AdapterError("rollback") from rollback_error
        raise
    _check_deadline(deadline_ns)


def _attestation(context: dict[str, Any]) -> dict[str, Any]:
    deadline_ns = context.get("deadline_ns")
    if type(deadline_ns) is not int:
        raise AdapterError("invalid_context")
    _check_deadline(deadline_ns)
    snapshot_path = _scope(context) / "snapshot.json"
    _safe_regular(snapshot_path)
    _check_deadline(deadline_ns)
    snapshot_bytes = snapshot_path.read_bytes()
    _check_deadline(deadline_ns)
    snapshot = parse_bounded_json(snapshot_bytes)
    _check_deadline(deadline_ns)
    if type(snapshot) is not dict or snapshot.get("generation") != context["generation"]:
        raise AdapterError("readback_failure")
    attestation = snapshot.get("attestation")
    recorded_deadline_ns = attestation.get("deadline_ns") if type(attestation) is dict else None
    if (type(attestation) is not dict or set(attestation) != {"boot_id", "deadline_ns", "observation"}
            or recorded_deadline_ns != deadline_ns):
        raise AdapterError("readback_failure")
    current_boot_id = _boot_id(deadline_ns)
    _check_deadline(deadline_ns)
    if attestation.get("boot_id") != current_boot_id:
        raise AdapterError("readback_failure")
    observation = attestation.get("observation")
    if type(observation) is not dict:
        raise AdapterError("readback_failure")
    return observation


def prepare(context: dict[str, Any]) -> dict[str, Any]:
    _trusted_parent(CONFIG)
    _trusted_parent(DROPIN)
    _trusted_parent(STATE_ROOT)
    _safe_regular(CONFIG)
    _hermes_launcher(context)
    for command in (SYSTEMCTL, USERMOD):
        _safe_regular(command)
    try:
        group = grp.getgrnam(GROUP)
    except KeyError as exc:
        raise AdapterError("missing_prerequisite") from exc
    state_root_created = not STATE_ROOT.exists()
    STATE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_info = os.lstat(STATE_ROOT)
    if (not stat.S_ISDIR(state_info.st_mode) or state_info.st_uid != 0
            or stat.S_IMODE(state_info.st_mode) != 0o700):
        raise AdapterError("untrusted_path")
    _verify_managed()
    scope = _scope(context)
    scope_created = not scope.exists()
    scope.mkdir(parents=True, exist_ok=True, mode=0o700)
    snapshot_path = scope / "snapshot.json"
    baseline_path = STATE_ROOT / "baseline.json"
    baseline_created = not baseline_path.exists()
    if not baseline_path.exists():
        baseline = snapshot_files({"config": CONFIG, "dropin": DROPIN})
        _atomic_write(baseline_path, json.dumps(baseline, sort_keys=True).encode("ascii"), 0o600)
    try:
        if not snapshot_path.exists():
            snapshot = {"uid": context["uid"], "profile": context["profile"],
                        "home": str(context["home"]), "generation": context["generation"],
                        "group_member": context["account"] in group.gr_mem,
                        "plugin_enabled": _plugin_enabled(context)}
            _atomic_write(snapshot_path, json.dumps(snapshot, sort_keys=True).encode("ascii"), 0o600)
        else:
            _safe_regular(snapshot_path)
            snapshot = parse_bounded_json(snapshot_path.read_bytes())
            if (type(snapshot) is not dict or snapshot.get("uid") != context["uid"]
                    or snapshot.get("profile") != context["profile"]
                    or snapshot.get("home") != str(context["home"])):
                raise AdapterError("existing_transaction")
            snapshot["generation"] = context["generation"]
            snapshot.pop("restart_identity", None)
            snapshot.pop("attestation", None)
            _atomic_write(snapshot_path, json.dumps(snapshot, sort_keys=True).encode("ascii"), 0o600)
    except Exception:
        if not snapshot_path.exists():
            if baseline_created:
                baseline_path.unlink(missing_ok=True)
            if scope_created:
                try:
                    scope.rmdir()
                except OSError as exc:
                    raise AdapterError("rollback") from exc
            if state_root_created:
                try:
                    STATE_ROOT.rmdir()
                except OSError as exc:
                    raise AdapterError("rollback") from exc
        raise
    try:
        config = CONFIG.read_text(encoding="utf-8")
        _atomic_write(CONFIG, rewrite_ingest_toml(config, context["uid"], enabled=True).encode("utf-8"),
                      0o640, 0, CONFIG.stat().st_gid)
        if context["account"] not in grp.getgrnam(GROUP).gr_mem:
            _run([str(USERMOD), "-a", "-G", GROUP, context["account"]],
                 env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        _atomic_write(
            DROPIN,
            render_dropin([UNIT], _runtime_instance(context), context["home"], context["profile"]).encode("ascii"),
            0o644,
        )
        _run([str(SYSTEMCTL), "--user", "daemon-reload"], env=_minimal_env(context), target=context)
        _write_managed()
    except Exception:
        try:
            rollback(context, verify_managed=False)
            if state_root_created:
                STATE_ROOT.rmdir()
        except Exception as rollback_error:
            raise AdapterError("rollback") from rollback_error
        raise
    return {"prepared": True, "plugin_enabled": False}


def rollback(context: dict[str, Any], *, verify_managed: bool = True) -> dict[str, Any]:
    if verify_managed:
        _verify_managed()
    scope = _scope(context)
    snapshot_path = scope / "snapshot.json"
    if not scope.exists() and not snapshot_path.exists():
        return {"prepared": False, "plugin_enabled": False}
    _safe_regular(snapshot_path)
    snapshot = parse_bounded_json(snapshot_path.read_bytes())
    if (type(snapshot) is not dict or snapshot.get("uid") != context["uid"]
            or snapshot.get("profile") != context["profile"]
            or snapshot.get("home") != str(context["home"])
            or snapshot.get("generation") != context["generation"]
            or type(snapshot.get("group_member")) is not bool
            or type(snapshot.get("plugin_enabled")) is not bool):
        raise AdapterError("rollback")
    other_scopes = [candidate for candidate in STATE_ROOT.glob("*/snapshot.json") if candidate != snapshot_path]
    other_uids: list[int] = []
    same_uid_snapshots: list[tuple[Path, dict[str, Any]]] = []
    for candidate in other_scopes:
        _safe_regular(candidate)
        other = parse_bounded_json(candidate.read_bytes())
        if type(other) is not dict or type(other.get("uid")) is not int:
            raise AdapterError("rollback")
        other_uids.append(other["uid"])
        if other["uid"] == context["uid"]:
            same_uid_snapshots.append((candidate, other))
    uid_still_active = context["uid"] in other_uids
    if snapshot["group_member"] is False and same_uid_snapshots:
        successor_path, successor = same_uid_snapshots[0]
        successor["group_member"] = False
        _atomic_write(successor_path, json.dumps(successor, sort_keys=True).encode("ascii"), 0o600)
    baseline_path = STATE_ROOT / "baseline.json"
    if other_scopes:
        if not uid_still_active:
            config = CONFIG.read_text(encoding="utf-8")
            _atomic_write(CONFIG, rewrite_ingest_toml(config, context["uid"], enabled=False).encode("utf-8"),
                          0o640, 0, CONFIG.stat().st_gid)
    else:
        _safe_regular(baseline_path)
        baseline = parse_bounded_json(baseline_path.read_bytes())
        if type(baseline) is not dict:
            raise AdapterError("rollback")
        restore_files(baseline, {"config": CONFIG, "dropin": DROPIN})
    if snapshot["group_member"] is False and not uid_still_active:
        try:
            current = grp.getgrnam(GROUP)
            if context["account"] in current.gr_mem:
                _safe_regular(GPASSWD)
                _run([str(GPASSWD), "-d", context["account"], GROUP], env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        except KeyError as exc:
            raise AdapterError("rollback") from exc
    enabled = _plugin_enabled(context)
    if enabled is not snapshot["plugin_enabled"]:
        desired_action = "enable" if snapshot["plugin_enabled"] else "disable"
        _run([str(_hermes_launcher(context)), "plugins", desired_action, "skynet-edr"],
             env=_minimal_env(context), target=context)
        if _plugin_enabled(context) is not snapshot["plugin_enabled"]:
            raise AdapterError("rollback")
    _run([str(SYSTEMCTL), "--user", "daemon-reload"], env=_minimal_env(context), target=context)
    _clear_manager_environment(context)
    if other_scopes:
        _write_managed()
    else:
        _verify_managed()
    # S3-V3C-Lite intentionally keeps rollback authority and its exact snapshot.
    # A later root operator may inspect/recover/remove it; this adapter never
    # deletes managed transaction evidence automatically.
    return {"prepared": False, "plugin_enabled": snapshot["plugin_enabled"],
            "reload_required": True, "rollback_phase": "RESTORED_VERIFIED"}


def _old_identity_gone(identity: ProcessIdentity, deadline_ns: int) -> bool:
    try:
        current = _proc_start_ticks(identity.main_pid, deadline_ns)
    except AdapterError as exc:
        if exc.category == "process_missing":
            return True
        raise
    return current != identity.proc_start_ticks


def _wait_for_source(context: dict[str, Any], gateway: ProcessIdentity,
                     deadline_ns: int) -> tuple[dict[str, Any], dict[str, Any]]:
    while True:
        status = _status(deadline_ns)
        ingestion = status.get("ingestion")
        if type(ingestion) is not dict:
            raise AdapterError("readback_failure")
        try:
            return status, _exact_source(ingestion, context, gateway)
        except AdapterError as exc:
            if exc.category != "source_missing":
                raise
        _bounded_sleep(deadline_ns)


def _restart_attestation(context: dict[str, Any]) -> dict[str, Any]:
    deadline_ns = context.get("deadline_ns")
    if type(deadline_ns) is not int:
        deadline_ns = time.monotonic_ns() + ATTEST_BUDGET_NS
    event_id = context.get("canary_event_id")
    token = context.get("attestation_token")
    if type(event_id) is not str or CANARY_EVENT_ID.fullmatch(event_id) is None or type(token) is not str:
        raise AdapterError("invalid_context")
    _check_deadline(deadline_ns)
    _atomic_write(
        DROPIN,
        render_dropin([UNIT], context["generation"], context["home"], context["profile"], token).encode("ascii"),
        0o644,
        deadline_ns=deadline_ns,
    )
    _check_deadline(deadline_ns)
    manager_unit = f"user@{context['uid']}.service"
    units = (manager_unit, UNIT, DAEMON_UNIT)
    before = {unit: _service_identity(context, unit, deadline_ns) for unit in units}
    previous_nonce = _previous_runtime_nonce(
        _status(deadline_ns, allow_disabled=True), context, before[UNIT]
    )
    _run([str(SYSTEMCTL), "stop", DAEMON_UNIT],
         env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}, deadline_ns=deadline_ns)
    _run([str(SYSTEMCTL), "restart", manager_unit],
         env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}, deadline_ns=deadline_ns)
    _import_manager_environment(context, deadline_ns)
    _run([str(SYSTEMCTL), "--user", "restart", UNIT],
         env=_minimal_env(context), target=context, deadline_ns=deadline_ns)
    _run([str(SYSTEMCTL), "restart", DAEMON_UNIT],
         env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}, deadline_ns=deadline_ns)
    after = {unit: _service_identity(context, unit, deadline_ns) for unit in units}
    if any(after[unit] == before[unit] for unit in units):
        raise AdapterError("identity_epoch")
    if any(not _old_identity_gone(identity, deadline_ns) for identity in before.values()):
        raise AdapterError("identity_epoch")

    _check_deadline(deadline_ns)
    try:
        config_text = CONFIG.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise AdapterError("readback_failure") from exc
    _check_deadline(deadline_ns)
    ingest = _toml_ingest(config_text)
    ingest_gid = context["ingest_gid"]
    exact_dac = _wait_for_socket_ready(SOCKET, ingest_gid, deadline_ns)
    if (not authorization_ok(dac=exact_dac, configured_uids=ingest["allowed_uids"], target_uid=context["uid"])
            or ingest_gid not in _process_groups(after[manager_unit].main_pid, deadline_ns)
            or ingest_gid not in _process_groups(after[UNIT].main_pid, deadline_ns)
            or not _gateway_context_matches(context, deadline_ns)):
        raise AdapterError("readback_failure")

    status, source = _wait_for_source(context, after[UNIT], deadline_ns)
    baseline = _startup_canary_baseline(source, event_id)
    if previous_nonce is not None and baseline["runtime_instance_nonce"] == previous_nonce:
        raise AdapterError("source_identity")
    ingestion = status.get("ingestion", {})
    if (ingestion.get("listener_live") is not True or ingestion.get("state") != "healthy"):
        raise AdapterError("producer_health")
    while True:
        if _persisted_advanced(baseline, source, event_id):
            break
        if (source.get("events_duplicate_total") != baseline.get("events_duplicate_total")
                or source.get("events_collision_total") != baseline.get("events_collision_total")
                or source.get("last_error_category") != baseline.get("last_error_category")):
            raise AdapterError("hook_failure")
        _bounded_sleep(deadline_ns)
        status, source = _wait_for_source(context, after[UNIT], deadline_ns)

    if not _plugin_enabled(context, deadline_ns):
        raise AdapterError("readback_failure")
    final = {unit: _service_identity(context, unit, deadline_ns) for unit in units}
    if final != after:
        raise AdapterError("identity_epoch")
    final_status = _status(deadline_ns)
    final_ingestion = final_status.get("ingestion")
    if (type(final_ingestion) is not dict or final_ingestion.get("listener_live") is not True
            or final_ingestion.get("state") != "healthy"):
        raise AdapterError("readback_failure")
    final_source = _exact_source(final_ingestion, context, final[UNIT])
    if (_source_identity(final_source) != _source_identity(source)
            or not _persisted_advanced(baseline, final_source, event_id)):
        raise AdapterError("source_identity")
    if {unit: _service_identity(context, unit, deadline_ns) for unit in units} != final:
        raise AdapterError("identity_epoch")
    source = final_source
    observation = {
        "plugin_enabled": True,
        "loaded_generation": context["generation"],
        "process_fresh": True,
        "daemon": {"healthy": True, "listener": True, "transport": "available",
                   "backlog": 0, "degraded": False},
        "producer": {"uid": context["uid"], "role": "gateway", "fresh": True,
                     "generation": context["generation"],
                     "runtime_nonce": source["runtime_instance_nonce"]},
        "real_hook": {"correlated": True, "committed": True, "incident_opened": False,
                      "event_id": event_id, "receipt_status": "persisted"},
        "restart_blast_radius": "complete_user_manager",
        "identities": {unit: [identity.main_pid, identity.proc_start_ticks,
                                identity.exec_start_monotonic_us]
                       for unit, identity in final.items()},
        "commit_sequence": source["commit_sequence"],
    }
    _check_deadline(deadline_ns)
    return observation


def _restart(context: dict[str, Any]) -> dict[str, Any]:
    deadline_ns = context.get("deadline_ns")
    token_free_dropin = render_dropin(
        [UNIT], context["generation"], context["home"], context["profile"]
    ).encode("ascii")
    observation = _restart_attestation(context)
    if type(deadline_ns) is not int:
        raise AdapterError("invalid_context")
    _clear_manager_attestation_token(context, deadline_ns)
    _atomic_write(DROPIN, token_free_dropin, 0o644, deadline_ns=deadline_ns)
    boot_id = _boot_id(deadline_ns)
    _check_deadline(deadline_ns)
    _record_attestation(context, observation, deadline_ns, boot_id)
    _check_deadline(deadline_ns)
    return observation


def _cleanup_failed_attestation(context: dict[str, Any]) -> None:
    deadline_ns = time.monotonic_ns() + CLEANUP_BUDGET_NS
    token_free_dropin = render_dropin(
        [UNIT], context["generation"], context["home"], context["profile"]
    ).encode("ascii")
    cleanup_error: Exception | None = None
    try:
        _atomic_write(DROPIN, token_free_dropin, 0o644, deadline_ns=deadline_ns)
    except Exception as exc:
        cleanup_error = exc
    try:
        _clear_manager_environment(context, deadline_ns)
    except Exception as exc:
        cleanup_error = exc
    if cleanup_error is not None:
        raise AdapterError("rollback") from cleanup_error


def execute(action: str, context: dict[str, Any]) -> dict[str, Any]:
    context["_hermes_launcher"] = _resolve_hermes_launcher(HERMES)
    if action == "prepare":
        return prepare(context)
    if action == "rollback":
        return rollback(context)
    if action in {"enable", "disable"}:
        desired = action == "enable"
        _run([str(_hermes_launcher(context)), "plugins", action, "skynet-edr"], env=_minimal_env(context))
        enabled = _plugin_enabled(context)
        if enabled is not desired:
            raise AdapterError("readback_failure")
        return {"plugin_enabled": enabled, "loaded_generation": context["generation"] if enabled else None,
                "process_fresh": False}
    if action == "attest":
        _safe_regular(SYSTEMCTL)
        return _restart(context)
    raise AdapterError("invalid_action")


def emit(value: dict[str, Any], *, ok: bool) -> int:
    if ok:
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    print(json.dumps({"error": "adapter_failure"}, sort_keys=True))
    return 1


def main() -> int:
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    try:
        environment = dict(os.environ)
        if action == "attest":
            raw_deadline = environment.get("SKYNET_EDR_DEADLINE_NS", "")
            if not raw_deadline.isascii() or not raw_deadline.isdigit():
                raise AdapterError("invalid_context")
            context: dict[str, Any] | None = None
            try:
                with _deadline_watchdog(int(raw_deadline)):
                    context = validate_context(action, environment)
                    result = execute(action, context)
            except Exception:
                if context is not None:
                    _notify_parent_cleanup()
                    try:
                        _cleanup_failed_attestation(context)
                    except Exception:
                        pass
                return emit({}, ok=False)
            return emit(result, ok=True)
        context = validate_context(action, environment)
        return emit(execute(action, context), ok=True)
    except Exception:
        return emit({}, ok=False)


if __name__ == "__main__":
    raise SystemExit(main())
