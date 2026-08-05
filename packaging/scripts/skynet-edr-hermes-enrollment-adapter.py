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
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

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
HEX64 = re.compile(r"^[0-9a-f]{64}$")
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
    return {"uid": uid, "account": account.pw_name, "home": home, "profile": profile,
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
            f"Environment=SKYNET_EDR_RUNTIME_INSTANCE={generation}\n"
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


def _run(argv: list[str], *, env: dict[str, str], target: dict[str, Any] | None = None) -> bytes:
    def drop_identity() -> None:
        if target is None:
            return
        account = pwd.getpwuid(target["uid"])
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)

    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=env, timeout=30, check=False, preexec_fn=drop_identity if target else None)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AdapterError("command_failure") from exc
    if result.returncode != 0 or len(result.stdout) > MAX_OUTPUT:
        raise AdapterError("command_failure")
    return result.stdout


def _minimal_env(context: dict[str, Any]) -> dict[str, str]:
    return {"HOME": str(context["home"].parent), "HERMES_HOME": str(context["home"]),
            "HERMES_PROFILE": context["profile"], "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "XDG_RUNTIME_DIR": f"/run/user/{context['uid']}",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{context['uid']}/bus"}


def _plugin_enabled(context: dict[str, Any]) -> bool:
    target = context if os.geteuid() == 0 else None
    value = parse_bounded_json(_run([str(HERMES), "plugins", "list", "--json"],
                                    env=_minimal_env(context), target=target))
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


def _status() -> dict[str, Any]:
    request = urllib.request.Request("http://127.0.0.1:8787/api/status", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            if response.status != 200:
                raise AdapterError("readback_failure")
            value = parse_bounded_json(response.read(MAX_OUTPUT + 1))
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise AdapterError("readback_failure") from exc
    if type(value) is not dict:
        raise AdapterError("readback_failure")
    return value


def _matching_source(ingestion: dict[str, Any], context: dict[str, Any], instance_id: str | None = None) -> dict[str, Any] | None:
    sources = ingestion.get("sources", [])
    if type(sources) is not list:
        return None
    for source in sources:
        if (type(source) is dict
                and source.get("authenticated_uid") == context["uid"]
                and source.get("runtime_role") == "gateway"
                and source.get("instance_id") == (instance_id or _runtime_instance(context))):
            return source
    return None


def _fresh_committed_source(ingestion: dict[str, Any], context: dict[str, Any], instance_id: str,
                            previous_commit: int) -> dict[str, Any] | None:
    source = _matching_source(ingestion, context, instance_id)
    if source is None:
        return None
    committed = source.get("last_event_committed_at_unix_ms")
    if (not isinstance(committed, int) or isinstance(committed, bool)
            or committed <= previous_commit):
        return None
    return source


def _service_identity(context: dict[str, Any], unit: str) -> tuple[int, int]:
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
    )
    try:
        values = [int(value) for value in raw.decode("ascii").splitlines()]
    except (UnicodeError, ValueError) as exc:
        raise AdapterError("readback_failure") from exc
    if len(values) != 2 or any(value <= 0 for value in values):
        raise AdapterError("readback_failure")
    return values[0], values[1]


def _process_groups(pid: int) -> set[int]:
    if type(pid) is not int or pid <= 0:
        raise AdapterError("readback_failure")
    path = Path("/proc") / str(pid) / "status"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            data = os.read(fd, MAX_OUTPUT + 1)
        finally:
            os.close(fd)
    except OSError as exc:
        raise AdapterError("readback_failure") from exc
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


def _gateway_identity(context: dict[str, Any]) -> tuple[int, int]:
    return _service_identity(context, UNIT)


def _gateway_context_matches(context: dict[str, Any], instance_id: str | None = None) -> bool:
    raw = _run(
        [str(SYSTEMCTL), "--user", "show", UNIT, "--property=Environment", "--value"],
        env=_minimal_env(context),
        target=context if os.geteuid() == 0 else None,
    )
    try:
        values = set(shlex.split(raw.decode("utf-8")))
    except (UnicodeError, ValueError):
        return False
    expected_instance = context["generation"] if instance_id is None else instance_id
    return {
        f"HERMES_HOME={context['home']}",
        f"HERMES_PROFILE={context['profile']}",
        "HERMES_RUNTIME_ROLE=gateway",
        "PYTHONDONTWRITEBYTECODE=1",
        f"SKYNET_EDR_RUNTIME_INSTANCE={expected_instance}",
    }.issubset(values)


def _record_restart_identity(context: dict[str, Any], identity: tuple[int, int]) -> None:
    snapshot_path = _scope(context) / "snapshot.json"
    _safe_regular(snapshot_path)
    snapshot = parse_bounded_json(snapshot_path.read_bytes())
    if type(snapshot) is not dict or snapshot.get("generation") != context["generation"]:
        raise AdapterError("readback_failure")
    snapshot["restart_identity"] = list(identity)
    _atomic_write(snapshot_path, json.dumps(snapshot, sort_keys=True).encode("ascii"), 0o600)


def _restart_identity(context: dict[str, Any]) -> tuple[int, int]:
    snapshot_path = _scope(context) / "snapshot.json"
    _safe_regular(snapshot_path)
    snapshot = parse_bounded_json(snapshot_path.read_bytes())
    if type(snapshot) is not dict or snapshot.get("generation") != context["generation"]:
        raise AdapterError("readback_failure")
    identity = snapshot.get("restart_identity")
    if (type(identity) is not list or len(identity) != 2
            or any(type(value) is not int or value <= 0 for value in identity)):
        raise AdapterError("readback_failure")
    return identity[0], identity[1]


def _observation(context: dict[str, Any], *, process_fresh: bool, real_hook: bool = False) -> dict[str, Any]:
    status = _status() if process_fresh else {}
    ingestion = status.get("ingestion", {}) if type(status) is dict else {}
    producer = _matching_source(ingestion, context) or {}
    try:
        group_id = grp.getgrnam(GROUP).gr_gid
        configured = _toml_ingest(CONFIG.read_text(encoding="utf-8"))["allowed_uids"]
    except (KeyError, OSError, UnicodeError) as exc:
        raise AdapterError("readback_failure") from exc
    dac = socket_dac_ok(SOCKET, group_id)
    authorized = authorization_ok(dac=dac, configured_uids=configured, target_uid=context["uid"])
    report_age = producer.get("producer_report_age_ms")
    producer_fresh = (isinstance(report_age, int) and not isinstance(report_age, bool)
                      and 0 <= report_age <= 30_000)
    transport = producer.get("transport_state", "unknown")
    loaded_generation = context["generation"] if producer_fresh and transport == "available" else None
    healthy = (ingestion.get("state") == "healthy" and authorized
               and loaded_generation == context["generation"] and _gateway_context_matches(context))
    return {
        "plugin_enabled": _plugin_enabled(context),
        "loaded_generation": loaded_generation,
        "process_fresh": process_fresh,
        "daemon": {"healthy": healthy, "listener": ingestion.get("listener_live") is True and dac,
                   "transport": transport, "backlog": producer.get("backlog_bytes", -1),
                   "degraded": not healthy},
        "producer": {"uid": producer.get("authenticated_uid"), "role": producer.get("runtime_role"),
                     "fresh": producer_fresh},
        "real_hook": {"correlated": real_hook, "committed": real_hook, "incident_opened": False},
    }


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


def _restart(context: dict[str, Any]) -> dict[str, Any]:
    manager_unit = f"user@{context['uid']}.service"
    manager_before = _service_identity(context, manager_unit)
    gateway_before = _service_identity(context, UNIT)
    _run([str(SYSTEMCTL), "restart", manager_unit], env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    _run([str(SYSTEMCTL), "restart", DAEMON_UNIT], env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    manager_after = _service_identity(context, manager_unit)
    gateway_after = _service_identity(context, UNIT)
    try:
        ingest_gid = grp.getgrnam(GROUP).gr_gid
    except KeyError as exc:
        raise AdapterError("readback_failure") from exc
    if (manager_after == manager_before or gateway_after == gateway_before
            or ingest_gid not in _process_groups(manager_after[0])
            or ingest_gid not in _process_groups(gateway_after[0])
            or not _gateway_context_matches(context)):
        raise AdapterError("readback_failure")
    _record_restart_identity(context, gateway_after)
    return _observation(context, process_fresh=True)


def _restart_gateway(context: dict[str, Any], instance_id: str) -> tuple[int, int]:
    before = _gateway_identity(context)
    _run([str(SYSTEMCTL), "--user", "daemon-reload"], env=_minimal_env(context), target=context)
    _run([str(SYSTEMCTL), "--user", "restart", UNIT], env=_minimal_env(context), target=context)
    after = _gateway_identity(context)
    try:
        ingest_gid = grp.getgrnam(GROUP).gr_gid
    except KeyError as exc:
        raise AdapterError("readback_failure") from exc
    if (after == before or ingest_gid not in _process_groups(after[0])
            or not _gateway_context_matches(context, instance_id)):
        raise AdapterError("readback_failure")
    return after


def _hook(context: dict[str, Any]) -> dict[str, Any]:
    _safe_regular(DROPIN)
    generation_dropin = render_dropin(
        [UNIT], context["generation"], context["home"], context["profile"]
    ).encode("ascii")
    if DROPIN.read_bytes() != generation_dropin:
        raise AdapterError("config_drift")
    before_ingestion = _status().get("ingestion", {})
    before_source = (_matching_source(before_ingestion, context, context["nonce"])
                     if type(before_ingestion) is dict else None)
    before_commit = before_source.get("last_event_committed_at_unix_ms", 0) if before_source else 0
    if not isinstance(before_commit, int) or isinstance(before_commit, bool):
        raise AdapterError("hook_failure")
    hook_error: Exception | None = None
    committed_source: dict[str, Any] | None = None
    try:
        nonce_dropin = render_dropin(
            [UNIT], context["nonce"], context["home"], context["profile"]
        ).encode("ascii")
        _atomic_write(DROPIN, nonce_dropin, 0o644)
        _restart_gateway(context, context["nonce"])
        _run([str(HERMES), "chat", "--max-turns", "1", "--toolsets", "none", "-q",
              "Enrollment health check: reply exactly OK and perform no tool calls."],
             env=_minimal_env(context), target=context)
        for _ in range(10):
            ingestion = _status().get("ingestion", {})
            committed_source = (_fresh_committed_source(
                ingestion, context, context["nonce"], before_commit
            ) if type(ingestion) is dict else None)
            if committed_source is not None:
                break
            time.sleep(0.2)
        else:
            raise AdapterError("hook_failure")
    except Exception as exc:
        hook_error = exc
    try:
        _atomic_write(DROPIN, generation_dropin, 0o644)
        restored_identity = _restart_gateway(context, context["generation"])
        _record_restart_identity(context, restored_identity)
    except Exception as exc:
        raise AdapterError("hook_failure") from exc
    if hook_error is not None or committed_source is None:
        raise AdapterError("hook_failure") from hook_error
    return _observation(context, process_fresh=True, real_hook=True)


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
