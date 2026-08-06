#!/usr/bin/env python3
"""Bounded privileged host adapter for Skynet-EDR Hermes enrollment.

This executable is package-owned and intentionally has no path override flags.
It accepts only the fixed actions used by the enrollment transaction, emits one
bounded sanitized JSON object, and never forwards child diagnostics.
"""

from __future__ import annotations

import base64
import grp
import hashlib
import json
import os
import pwd
import re
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any, NamedTuple

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
MAX_OUTPUT = 65_536
ATTEST_BUDGET_NS = 15_000_000_000
POLL_SECONDS = 0.2
HEX64 = re.compile(r"^[0-9a-f]{64}$")
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
    if action not in {"prepare", "rollback", "enable", "disable", "restart", "hook"}:
        raise AdapterError("invalid_action")
    effective_uid = os.geteuid() if effective_uid is None else effective_uid
    privileged = action in {"prepare", "rollback", "restart", "hook"}
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
    if action == "restart":
        try:
            ingest_gid = grp.getgrnam(GROUP).gr_gid
        except KeyError as exc:
            raise AdapterError("missing_prerequisite") from exc
    return {"uid": uid, "account": account.pw_name, "account_gid": account.pw_gid,
            "ingest_gid": ingest_gid,
            "home": home, "profile": profile,
            "nonce": nonce, "generation": generation, "action": action, "home_fd": home_fd}


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


def render_dropin(units: list[str], generation: str, home: Path, profile: str) -> str:
    if units != [UNIT]:
        raise AdapterError("unit_scope")
    if profile != "default" or home.name != ".hermes":
        raise AdapterError("unsupported_contract")
    return ("[Service]\n"
            "Environment=HERMES_RUNTIME_ROLE=gateway\n"
            f"Environment=SKYNET_EDR_PLUGIN_GENERATION={generation}\n"
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


def _trusted_parent(path: Path) -> None:
    current = Path("/")
    for component in path.parent.parts[1:]:
        current /= component
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            break
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != 0 or info.st_mode & 0o022):
            raise AdapterError("untrusted_path")


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


def _atomic_write(path: Path, data: bytes, mode: int, uid: int = 0, gid: int = 0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        if os.geteuid() == 0:
            os.fchown(fd, uid, gid)
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
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
    return {"HOME": str(context["home"].parent), "HERMES_HOME": str(context["home"]),
            "HERMES_PROFILE": context["profile"], "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "XDG_RUNTIME_DIR": f"/run/user/{context['uid']}",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{context['uid']}/bus"}


def _plugin_enabled(context: dict[str, Any], deadline_ns: int | None = None) -> bool:
    target = context if os.geteuid() == 0 else None
    value = parse_bounded_json(_run([str(HERMES), "plugins", "list", "--json"],
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


def _status(deadline_ns: int | None = None) -> dict[str, Any]:
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
    return value


def _source_identity(source: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(source.get(key) for key in (
        "authenticated_uid", "runtime_role", "plugin_generation", "runtime_instance_nonce",
        "kernel_peer_pid", "kernel_peer_start_ticks",
    ))


def _exact_source(ingestion: dict[str, Any], context: dict[str, Any],
                  gateway: ProcessIdentity) -> dict[str, Any]:
    sources = ingestion.get("sources")
    if type(sources) is not list:
        raise AdapterError("source_cardinality")
    matches = [source for source in sources if type(source) is dict
               and source.get("authenticated_uid") == context["uid"]
               and source.get("runtime_role") == "gateway"]
    if len(matches) != 1:
        raise AdapterError("source_missing" if not matches else "source_cardinality")
    source = matches[0]
    nonce = source.get("runtime_instance_nonce")
    age = source.get("producer_report_age_ms")
    if (source.get("protocol_version") != 3 or source.get("s3_eligible") is not True
            or source.get("plugin_generation") != context["generation"]
            or source.get("kernel_peer_pid") != gateway.main_pid
            or source.get("kernel_peer_start_ticks") != gateway.proc_start_ticks
            or type(nonce) is not str or not HEX64.fullmatch(nonce)
            or nonce == context["generation"]
            or type(age) is not int or isinstance(age, bool) or not 0 <= age <= 30_000
            or source.get("transport_state") != "available" or source.get("backlog_bytes") != 0):
        raise AdapterError("producer_health")
    return source


def _persisted_advanced(before: dict[str, Any], after: dict[str, Any]) -> bool:
    before_sequence = before.get("commit_sequence")
    before_persisted = before.get("events_persisted_total")
    after_sequence = after.get("commit_sequence")
    after_persisted = after.get("events_persisted_total")
    integers = (before_sequence, before_persisted, after_sequence, after_persisted)
    failure_fields = ("events_malformed_total", "events_dropped_total",
                      "events_duplicate_total", "events_collision_total")
    if not all(type(value) is int and value >= 0 for value in integers):
        return False
    assert isinstance(before_sequence, int) and isinstance(before_persisted, int)
    assert isinstance(after_sequence, int) and isinstance(after_persisted, int)
    return (all(type(before.get(field)) is int and type(after.get(field)) is int
                    and before[field] == 0 and after[field] == 0 for field in failure_fields)
            and before.get("last_error_category") is None
            and after.get("last_error_category") is None
            and _source_identity(before) == _source_identity(after)
            and after_sequence - before_sequence == 1
            and after_persisted - before_persisted == 1)


def _previous_runtime_nonce(status: dict[str, Any], context: dict[str, Any],
                            gateway: ProcessIdentity) -> str | None:
    ingestion = status.get("ingestion")
    sources = ingestion.get("sources") if type(ingestion) is dict else None
    if type(sources) is not list:
        return None
    candidates = [source for source in sources if type(source) is dict
                  and source.get("authenticated_uid") == context["uid"]
                  and source.get("runtime_role") == "gateway"]
    if len(candidates) > 1:
        raise AdapterError("source_cardinality")
    if not candidates:
        return None
    source = candidates[0]
    nonce = source.get("runtime_instance_nonce")
    if (source.get("protocol_version") == 3
            and source.get("kernel_peer_pid") == gateway.main_pid
            and source.get("kernel_peer_start_ticks") == gateway.proc_start_ticks
            and type(nonce) is str and HEX64.fullmatch(nonce)):
        return nonce
    return None


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
    return {
        f"HERMES_HOME={context['home']}",
        f"HERMES_PROFILE={context['profile']}",
        "HERMES_RUNTIME_ROLE=gateway",
        "PYTHONDONTWRITEBYTECODE=1",
        f"SKYNET_EDR_PLUGIN_GENERATION={context['generation']}",
    }.issubset(values)


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
    snapshot_path = _scope(context) / "snapshot.json"
    _safe_regular(snapshot_path)
    snapshot = parse_bounded_json(snapshot_path.read_bytes())
    if type(snapshot) is not dict or snapshot.get("generation") != context["generation"]:
        raise AdapterError("readback_failure")
    snapshot["attestation"] = {
        "boot_id": boot_id, "deadline_ns": deadline_ns, "observation": observation,
    }
    _atomic_write(snapshot_path, json.dumps(snapshot, sort_keys=True).encode("ascii"), 0o600)


def _attestation(context: dict[str, Any]) -> dict[str, Any]:
    snapshot_path = _scope(context) / "snapshot.json"
    _safe_regular(snapshot_path)
    snapshot = parse_bounded_json(snapshot_path.read_bytes())
    if type(snapshot) is not dict or snapshot.get("generation") != context["generation"]:
        raise AdapterError("readback_failure")
    attestation = snapshot.get("attestation")
    deadline_ns = attestation.get("deadline_ns") if type(attestation) is dict else None
    if (type(attestation) is not dict or set(attestation) != {"boot_id", "deadline_ns", "observation"}
            or type(deadline_ns) is not int):
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
    for command in (HERMES, SYSTEMCTL, USERMOD):
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
        _run([str(HERMES), "plugins", desired_action, "skynet-edr"],
             env=_minimal_env(context), target=context)
        if _plugin_enabled(context) is not snapshot["plugin_enabled"]:
            raise AdapterError("rollback")
    _run([str(SYSTEMCTL), "--user", "daemon-reload"], env=_minimal_env(context), target=context)
    if other_scopes:
        _write_managed()
    else:
        (STATE_ROOT / "managed.json").unlink(missing_ok=True)
    snapshot_path.unlink()
    try:
        scope.rmdir()
    except OSError:
        pass
    if not other_scopes:
        baseline_path.unlink()
    return {"prepared": False, "plugin_enabled": False}


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


def _restart(context: dict[str, Any]) -> dict[str, Any]:
    deadline_ns = time.monotonic_ns() + ATTEST_BUDGET_NS
    manager_unit = f"user@{context['uid']}.service"
    units = (manager_unit, UNIT, DAEMON_UNIT)
    before = {unit: _service_identity(context, unit, deadline_ns) for unit in units}
    previous_nonce = _previous_runtime_nonce(_status(deadline_ns), context, before[UNIT])
    _run([str(SYSTEMCTL), "restart", manager_unit],
         env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}, deadline_ns=deadline_ns)
    _run([str(SYSTEMCTL), "restart", DAEMON_UNIT],
         env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}, deadline_ns=deadline_ns)
    after = {unit: _service_identity(context, unit, deadline_ns) for unit in units}
    if any(after[unit] == before[unit] for unit in units):
        raise AdapterError("identity_epoch")
    if any(not _old_identity_gone(identity, deadline_ns) for identity in before.values()):
        raise AdapterError("identity_epoch")

    _check_deadline(deadline_ns)
    try:
        socket_info = os.lstat(SOCKET)
        config_text = CONFIG.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise AdapterError("readback_failure") from exc
    _check_deadline(deadline_ns)
    ingest = _toml_ingest(config_text)
    ingest_gid = context["ingest_gid"]
    dac = (stat.S_ISSOCK(socket_info.st_mode) and stat.S_IMODE(socket_info.st_mode) == 0o660)
    if (socket_info.st_gid != ingest_gid
            or not authorization_ok(dac=dac, configured_uids=ingest["allowed_uids"], target_uid=context["uid"])
            or ingest_gid not in _process_groups(after[manager_unit].main_pid, deadline_ns)
            or ingest_gid not in _process_groups(after[UNIT].main_pid, deadline_ns)
            or not _gateway_context_matches(context, deadline_ns)):
        raise AdapterError("readback_failure")

    status, baseline = _wait_for_source(context, after[UNIT], deadline_ns)
    if previous_nonce is not None and baseline["runtime_instance_nonce"] == previous_nonce:
        raise AdapterError("source_identity")
    ingestion = status.get("ingestion", {})
    if (ingestion.get("listener_live") is not True or ingestion.get("state") != "healthy"):
        raise AdapterError("producer_health")
    _run([str(HERMES), "chat", "--max-turns", "1", "--toolsets", "none", "-q",
          "Enrollment health check: reply exactly OK and perform no tool calls."],
         env=_minimal_env(context), target=context, deadline_ns=deadline_ns)
    while True:
        status, source = _wait_for_source(context, after[UNIT], deadline_ns)
        if _persisted_advanced(baseline, source):
            break
        if (source.get("events_duplicate_total") != baseline.get("events_duplicate_total")
                or source.get("events_collision_total") != baseline.get("events_collision_total")
                or source.get("last_error_category") != baseline.get("last_error_category")):
            raise AdapterError("hook_failure")
        _bounded_sleep(deadline_ns)

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
            or not _persisted_advanced(baseline, final_source)):
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
        "real_hook": {"correlated": True, "committed": True, "incident_opened": False},
        "restart_blast_radius": "complete_user_manager",
        "identities": {unit: [identity.main_pid, identity.proc_start_ticks,
                                identity.exec_start_monotonic_us]
                       for unit, identity in final.items()},
        "commit_sequence": source["commit_sequence"],
    }
    boot_id = _boot_id(deadline_ns)
    _check_deadline(deadline_ns)
    _record_attestation(context, observation, deadline_ns, boot_id)
    _check_deadline(deadline_ns)
    return observation


def _hook(context: dict[str, Any]) -> dict[str, Any]:
    observation = _attestation(context)
    if (observation.get("loaded_generation") != context["generation"]
            or observation.get("process_fresh") is not True
            or observation.get("real_hook") != {
                "correlated": True, "committed": True, "incident_opened": False}):
        raise AdapterError("hook_failure")
    return observation


def execute(action: str, context: dict[str, Any]) -> dict[str, Any]:
    if action == "prepare":
        return prepare(context)
    if action == "rollback":
        return rollback(context)
    if action in {"enable", "disable"}:
        _safe_regular(HERMES)
        desired = action == "enable"
        _run([str(HERMES), "plugins", action, "skynet-edr"], env=_minimal_env(context))
        enabled = _plugin_enabled(context)
        if enabled is not desired:
            raise AdapterError("readback_failure")
        return {"plugin_enabled": enabled, "loaded_generation": context["generation"] if enabled else None,
                "process_fresh": False}
    if action == "restart":
        _safe_regular(SYSTEMCTL)
        _safe_regular(HERMES)
        return _restart(context)
    _safe_regular(HERMES)
    return _hook(context)


def emit(value: dict[str, Any], *, ok: bool) -> int:
    if ok:
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    print(json.dumps({"error": "adapter_failure"}, sort_keys=True))
    return 1


def main() -> int:
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    try:
        context = validate_context(action, dict(os.environ))
        return emit(execute(action, context), ok=True)
    except Exception:
        return emit({}, ok=False)


if __name__ == "__main__":
    raise SystemExit(main())
