"""Skynet-EDR passive telemetry plugin for Hermes Agent.

The plugin is intentionally non-blocking. It observes Hermes lifecycle hooks,
emits canonical ``skynet.event.v0`` JSONL records to a local spool, and writes a
sanitized operational log. It never executes tool content, never performs
network egress, and never stores raw tool output.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import queue
import re
import socket
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    import fcntl
except ImportError:  # pragma: no cover - continuous ingestion is Linux-first
    fcntl = None

PLUGIN_NAME = "skynet-edr"
PLUGIN_VERSION = "0.4.0"
SCHEMA_VERSION = "skynet.event.v0"
DEFAULT_MAX_FIELD_CHARS = 4096
DEFAULT_MAX_LOG_BYTES = 1_048_576
DEFAULT_EVENT_QUEUE_SIZE = 1024
DEFAULT_FALLBACK_MAX_BYTES = 64 * 1024 * 1024
MAX_FALLBACK_MAX_BYTES = 256 * 1024 * 1024
MAX_INGEST_FRAME_BYTES = 262_144
DEFAULT_INGEST_SOCKET = "/run/skynet-edr-ingest/ingest.sock"

_SECRET_RE = re.compile(
    r"(?i)(authorization\s*:\s*bearer\s+\S+|x-api-key\s*[:=]\s*\S+|api[_-]?key\s*[:=]\s*\S+|token\s*[:=]\s*\S+|secret\s*[:=]\s*\S+|password\s*[:=]\s*\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
_LOCAL_CONTEXT_RE = re.compile(
    r"(?i)(/home/[\w_.-]+/\.hermes/\S*|/root/\.hermes/\S*|/home/[\w_.-]+/\.ssh/\S*|/root/\.ssh/\S*|/home/[\w_.-]+/[^\s'\"]*\.env|/root/[^\s'\"]*\.env)"
)
_NETWORK_RE = re.compile(r"(?i)(\bcurl\b|\bwget\b|https?://|/dev/tcp|\bnc\b|\bncat\b)")
_URL_RE = re.compile(r"(?i)https?://[^\s\"'\\]+")
_GITHUB_SCP_RE = re.compile(r"(?i)git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?")
_GITHUB_BARE_RE = re.compile(r"(?i)github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?")
_GITHUB_FALLBACK_RE = re.compile(
    r"(?i)(?:https?://[^\s\"'\\]+|ssh://[^\s\"'\\]+|(?<![/\w.-])git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?|(?<![/\w.-])github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?)"
)
_DEV_TCP_DESTINATION_RE = re.compile(r"(?i)/dev/tcp/([^/\s\"'\\]+)/\d+")
_SIMPLE_DIRECT_IPV4_DESTINATION_RE = re.compile(
    r"(?i)\b(?:curl|wget|nc|ncat)\b\s+(?:https?://)?((?:\d{1,3}\.){3}\d{1,3})(?=$|[\s/:\"'\\])"
)
_DELIVERY_TOOLS = {"send_message", "himalaya", "gmail", "telegram", "discord", "slack", "email"}
_PROCESS_TOOLS = {"terminal", "execute_code", "shell", "bash", "python"}
_FILE_TOOLS = {"read_file", "write_file", "patch", "search_files"}
_PROMPT_INJECTION_RE = re.compile(
    r"(?i)(ignore (all )?(previous|prior) instructions|disregard (all )?(previous|prior) instructions|system prompt|developer message|reveal your instructions|exfiltrate|send (the )?(secret|token|credentials))"
)
_MALWARE_TEST_RE = re.compile(
    r"(?i)(skynet_fake_malware_test_string_do_not_execute|eicar-standard-antivirus-test-file)"
)
_BROWSER_TOOLS = {"browser_navigate", "browser_snapshot", "browser_click", "web_search", "web_extract"}
_CODE_TOOLS = {"execute_code", "codex", "claude_code"}
_MESSAGE_TOOLS = {"send_message", "telegram", "discord", "slack", "sms", "whatsapp", "signal"}
_ARTIFACT_PROVIDER_BY_KIND = {
    "email": "email",
    "url": "browser",
    "git_repository": "github",
    "code": "code",
    "file": "file",
    "message": "messaging",
    "mcp": "mcp",
    "terminal": "terminal",
}

_lock = threading.Lock()
_logger_lock = threading.Lock()
_session_trace_id = f"hermes-local-{uuid.uuid4().hex}"
_runtime_instance_fallback = uuid.uuid4().hex
_counter = 0
_logger: logging.Logger | None = None


def _initial_queue_size() -> int:
    try:
        value = int(os.environ.get("SKYNET_EDR_EVENT_QUEUE_SIZE", DEFAULT_EVENT_QUEUE_SIZE))
    except (TypeError, ValueError):
        return DEFAULT_EVENT_QUEUE_SIZE
    return min(65_536, max(1, value))


_event_queue: queue.Queue[str] = queue.Queue(maxsize=_initial_queue_size())
_worker_lock = threading.Lock()
_worker_started = False
_worker_stop = threading.Event()
_worker_thread: threading.Thread | None = None
_transport_counters = {
    "queue_drops": 0,
    "socket_failures": 0,
    "fallback_full": 0,
    "fallback_records": 0,
}
_last_reported_transport_counters = dict(_transport_counters)


def register(ctx: Any) -> None:
    """Register passive Hermes hooks."""
    _setup_logging().info("registering Skynet-EDR Hermes plugin hooks version=%s", PLUGIN_VERSION)
    ctx.register_hook("on_session_start", _safe_hook(_on_session_start))
    ctx.register_hook("on_session_end", _safe_hook(_on_session_end))
    ctx.register_hook("pre_llm_call", _safe_hook(_pre_llm_call))
    ctx.register_hook("pre_tool_call", _safe_hook(_pre_tool_call))
    ctx.register_hook("post_tool_call", _safe_hook(_post_tool_call))
    if _enabled():
        _ensure_worker()


def _safe_hook(handler):
    def wrapper(*args: Any, **kwargs: Any):
        try:
            return handler(*args, **kwargs)
        except Exception as exc:  # pragma: no cover - deliberately defensive
            _setup_logging().exception("hook_failed handler=%s error=%s", handler.__name__, exc.__class__.__name__)
            return None

    return wrapper


def _on_session_start(*args: Any, **kwargs: Any) -> None:
    _write_event(
        event_type="agent.session.started",
        source_kind="sensor",
        trust_level="sensor_observation",
        severity="informational",
        title="Hermes session started with Skynet-EDR telemetry plugin",
        attributes=_session_attributes(args, kwargs),
    )


def _on_session_end(*args: Any, **kwargs: Any) -> None:
    _write_event(
        event_type="agent.session.ended",
        source_kind="sensor",
        trust_level="sensor_observation",
        severity="informational",
        title="Hermes session ended with Skynet-EDR telemetry plugin",
        attributes=_session_attributes(args, kwargs),
    )


def _pre_llm_call(*args: Any, **kwargs: Any) -> None:
    attributes: dict[str, Any] = {
        "hook": "pre_llm_call",
        "content_omitted": True,
        "argument_count": len(args),
        "keyword_count": len(kwargs),
    }
    count = _estimate_message_count(args, kwargs)
    if count is not None:
        attributes["message_count"] = count
    _write_event(
        event_type="agent.llm.call.requested",
        source_kind="sensor",
        trust_level="sensor_observation",
        severity="informational",
        title="Hermes LLM call requested",
        attributes=attributes,
    )


def _pre_tool_call(*args: Any, **kwargs: Any) -> None:
    tool_name, params = _extract_tool_call(args, kwargs)
    params_text = _safe_json(params)
    indicators = _classify_tool(tool_name, params_text)
    artifact = _artifact_for_tool(tool_name, params, params_text, "agent_action")
    attrs: dict[str, Any] = {
        "hook": "pre_tool_call",
        "tool_name": tool_name,
        "network_indicator": indicators["network_indicator"],
        "direct_ip": indicators["direct_ip"],
        "delivery_indicator": indicators["delivery_indicator"],
        "sensitive_access": indicators["sensitive_access"],
        "params_length": len(params_text),
    }
    replacement = _redaction_replacement(params_text)
    redacted: list[dict[str, str]] = []
    if replacement:
        attrs["params_preview"] = replacement
        redacted.append(_redacted_field("attributes.params_preview", replacement))
    else:
        attrs["params_preview"] = "[OMITTED:tool_params]"
    if indicators["command_class"]:
        attrs["command_class"] = indicators["command_class"]
    if indicators["source_kind"] == "mcp_tool":
        event_type = "agent.mcp.tool.requested"
    elif indicators["direct_ip"]:
        event_type = "agent.network.egress"
    else:
        event_type = "agent.tool.requested"
    _write_event(
        event_type=event_type,
        source_kind=indicators["source_kind"],
        trust_level="agent_action",
        severity="high"
        if indicators["network_indicator"] or indicators["delivery_indicator"] or indicators["sensitive_access"]
        else "low",
        title=f"Hermes tool requested: {tool_name}",
        attributes=attrs,
        artifact=artifact,
        redacted_fields=redacted,
    )


def _post_tool_call(*args: Any, **kwargs: Any) -> None:
    tool_name, params, result = _extract_post_tool_call(args, kwargs)
    result_text = _stringify(result)
    params_text = _safe_json(params)
    indicators = _classify_tool(tool_name, params_text)
    artifact = _artifact_for_tool(tool_name, params, params_text, "tool_output")
    malware_signature = _malware_signature(result_text)
    injection = bool(_PROMPT_INJECTION_RE.search(result_text))
    attrs: dict[str, Any] = {
        "hook": "post_tool_call",
        "tool_name": tool_name,
        "result_omitted": True,
        "result_length": len(result_text),
        "network_indicator": indicators["network_indicator"],
        "direct_ip": indicators["direct_ip"],
        "delivery_indicator": indicators["delivery_indicator"],
        "sensitive_access": indicators["sensitive_access"],
        "prompt_injection_indicator": injection,
        "malware_indicator": malware_signature is not None,
    }
    if malware_signature:
        attrs["malware_signature"] = malware_signature
        attrs["rule_id"] = "EDR-MALWARE-001"
    _write_event(
        event_type="agent.tool.completed",
        source_kind=indicators["source_kind"],
        trust_level="tool_output",
        severity="high" if malware_signature or injection else "informational",
        title=f"Hermes tool completed: {tool_name}",
        attributes=attrs,
        artifact=artifact,
    )
    if injection:
        _write_event(
            event_type="agent.content.ingested",
            source_kind="mcp_tool",
            trust_level="untrusted_content",
            severity="medium",
            title="Untrusted Hermes tool output contains prompt-injection instructions",
            artifact=artifact,
            attributes={
                "hook": "post_tool_call",
                "tool_name": tool_name,
                "content_omitted": True,
                "content_length": len(result_text),
                "instruction_authority": False,
                "contains_instructional_attack": True,
                "expected_disposition": "treat_as_data",
                "rule_id": "EDR-PI-001",
            },
        )


def _write_event(
    *,
    event_type: str,
    source_kind: str,
    trust_level: str,
    severity: str,
    title: str,
    attributes: dict[str, Any],
    artifact: dict[str, Any] | None = None,
    redacted_fields: list[dict[str, str]] | None = None,
) -> None:
    if not _enabled():
        return
    now = _now_ms()
    event_id = _event_id(event_type, now, attributes)
    redacted_fields = redacted_fields or []
    event = {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "event_type": event_type,
        "observed_at_unix_ms": now,
        "received_at_unix_ms": now,
        "severity": severity,
        "source": {"kind": source_kind, "sensor": "skynet-edr-hermes-plugin", "integration": "hermes"},
        "provenance": {
            "producer": "hermes-agent",
            "collector": "skynet-edr-hermes-plugin",
            "tenant": _tenant(),
            "source_event_id": event_id,
            "trace_id": _trace_id(),
            "span_id": event_id,
            "parent_span_id": None,
        },
        "trust_level": trust_level,
        "title": title,
        "details": None,
        "attributes": _json_safe_attributes(attributes),
        "redaction": {
            "contains_sensitive_data": bool(redacted_fields),
            "redacted_fields": redacted_fields,
        },
    }
    if artifact is not None:
        event["artifact"] = artifact
    line = json.dumps(event, separators=(",", ":"), sort_keys=True)
    _ensure_worker()
    try:
        _event_queue.put_nowait(line)
    except queue.Full:
        with _lock:
            _transport_counters["queue_drops"] += 1


def _ensure_worker() -> None:
    global _worker_started, _worker_thread
    if _worker_started:
        return
    with _worker_lock:
        if _worker_started:
            return
        _worker_thread = threading.Thread(
            target=_transport_worker, name="skynet-edr-forwarder", daemon=True
        )
        _worker_thread.start()
        _worker_started = True


def _transport_worker() -> None:
    _send_health_report()
    idle_ticks = 0
    while not _worker_stop.is_set():
        try:
            line = _event_queue.get(timeout=0.05)
        except queue.Empty:
            idle_ticks += 1
            if idle_ticks >= 20:
                _replay_fallback(max_records=16)
                _report_transport_counters()
                _send_health_report()
                idle_ticks = 0
            continue
        idle_ticks = 0
        try:
            _replay_fallback(max_records=4)
            if _fallback_has_pending():
                _append_fallback(line)
            else:
                status = _send_frame(line)
                if status not in {"persisted", "duplicate", "collision", "rejected_permanent"}:
                    _append_fallback(line)
        finally:
            _event_queue.task_done()
            _report_transport_counters()
            _send_health_report()


def _report_transport_counters() -> None:
    global _last_reported_transport_counters
    with _lock:
        snapshot = dict(_transport_counters)
        if snapshot == _last_reported_transport_counters or not any(snapshot.values()):
            return
        _last_reported_transport_counters = snapshot
    try:
        _setup_logging().warning(
            "transport_counters queue_drops=%d socket_failures=%d fallback_full=%d fallback_records=%d",
            snapshot["queue_drops"],
            snapshot["socket_failures"],
            snapshot["fallback_full"],
            snapshot["fallback_records"],
        )
    except OSError:
        pass


def _send_frame(line: str) -> str:
    payload = line.encode("utf-8")
    if not payload or len(payload) > MAX_INGEST_FRAME_BYTES:
        return "rejected_permanent"
    try:
        request = json.loads(line)
        event_id = request["event_id"]
        if not isinstance(event_id, str) or not event_id:
            return "rejected_permanent"
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return "rejected_permanent"
    socket_path = os.environ.get("SKYNET_EDR_INGEST_SOCKET", DEFAULT_INGEST_SOCKET)
    timeout = min(2.0, max(0.01, _safe_positive_int_env("SKYNET_EDR_SOCKET_TIMEOUT_MS", 250) / 1000))
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(socket_path)
            client.sendall(len(payload).to_bytes(4, "big") + payload)
            ack = bytearray()
            while len(ack) <= 4096:
                chunk = client.recv(min(1024, 4097 - len(ack)))
                if not chunk:
                    break
                ack.extend(chunk)
                if b"\n" in chunk:
                    break
        if len(ack) > 4096 or not ack.endswith(b"\n") or ack.count(b"\n") != 1:
            return "retry_later"
        response = json.loads(bytes(ack[:-1]))
        status = response.get("status")
        if (
            response.get("version") == 1
            and response.get("event_id") == event_id
            and status in {"persisted", "duplicate", "collision", "rejected_permanent"}
        ):
            return status
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    with _lock:
        _transport_counters["socket_failures"] += 1
    return "retry_later"


def _send_health_report() -> bool:
    path = _spool_path()
    checkpoint_path = _checkpoint_path()
    try:
        with _spool_state_lock():
            size = path.stat().st_size if path.exists() else 0
            try:
                checkpoint = min(_read_checkpoint(checkpoint_path), size)
            except (OSError, UnicodeDecodeError, ValueError):
                checkpoint = 0
            backlog = size - checkpoint
            backlog_age_ms = None
            if backlog > 0:
                backlog_age_ms = max(0, int((time.time() - path.stat().st_mtime) * 1000))
        with _lock:
            counters = dict(_transport_counters)
        # Cumulative counters remain visible for audit, but current transport health must
        # recover after a transient failure once the durable backlog is fully drained.
        degraded = backlog > 0
        payload = json.dumps(
            {
                "version": 2,
                "message_type": "producer_health",
                "runtime_role": _runtime_role(),
                "instance_id": _runtime_instance_id(),
                "checkpoint_bytes": checkpoint,
                "backlog_bytes": backlog,
                "backlog_age_ms": backlog_age_ms,
                "events_dropped_total": counters["queue_drops"] + counters["fallback_full"],
                "events_malformed_total": 0,
                "transport_state": "degraded" if degraded else "available",
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if not payload or len(payload) > 4096:
            return False
        socket_path = os.environ.get("SKYNET_EDR_INGEST_SOCKET", DEFAULT_INGEST_SOCKET)
        timeout = min(
            2.0,
            max(0.01, _safe_positive_int_env("SKYNET_EDR_SOCKET_TIMEOUT_MS", 250) / 1000),
        )
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(socket_path)
            client.sendall(len(payload).to_bytes(4, "big") + payload)
            ack = bytearray()
            while len(ack) <= 4096:
                chunk = client.recv(min(1024, 4097 - len(ack)))
                if not chunk:
                    break
                ack.extend(chunk)
                if b"\n" in chunk:
                    break
        if len(ack) > 4096 or not ack.endswith(b"\n") or ack.count(b"\n") != 1:
            return False
        response = json.loads(bytes(ack[:-1]))
        return response.get("version") == 1 and response.get("status") == "health_recorded"
    except (OSError, ValueError, json.JSONDecodeError):
        return False


def _append_fallback(line: str) -> bool:
    encoded_bytes = len(line.encode("utf-8")) + 1
    if encoded_bytes > MAX_INGEST_FRAME_BYTES + 1:
        return False
    path = _spool_path()
    _ensure_private_dir(path.parent)
    configured_cap = _safe_positive_int_env("SKYNET_EDR_FALLBACK_MAX_BYTES", DEFAULT_FALLBACK_MAX_BYTES)
    cap = min(configured_cap, MAX_FALLBACK_MAX_BYTES)
    with _spool_state_lock():
        try:
            current_size = path.stat().st_size if path.exists() else 0
            try:
                checkpoint = min(_read_checkpoint(_checkpoint_path()), current_size)
            except (OSError, UnicodeDecodeError, ValueError):
                checkpoint = 0
            pending_size = current_size - checkpoint
            if pending_size + encoded_bytes > cap:
                with _lock:
                    _transport_counters["fallback_full"] += 1
                return False
            if checkpoint > 0 and current_size + encoded_bytes > cap:
                _compact_fallback_prefix(path, checkpoint)
            with _open_private_append(path) as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            _fsync_parent(path)
            with _lock:
                _transport_counters["fallback_records"] += 1
            return True
        except OSError:
            return False


def _replay_fallback(*, max_records: int) -> int:
    path = _spool_path()
    with _spool_state_lock():
        if not path.exists():
            return 0
        checkpoint = _checkpoint_path()
        try:
            offset = _read_checkpoint(checkpoint)
            with _open_private_read(path) as handle:
                size = os.fstat(handle.fileno()).st_size
                if offset > size:
                    offset = 0
                    _write_checkpoint(checkpoint, 0)
                handle.seek(offset)
                advanced = 0
                for _ in range(max_records):
                    line = handle.readline(MAX_INGEST_FRAME_BYTES + 2)
                    if not line or not line.endswith(b"\n") or len(line) > MAX_INGEST_FRAME_BYTES + 1:
                        break
                    status = _send_frame(line[:-1].decode("utf-8"))
                    if status not in {"persisted", "duplicate", "collision", "rejected_permanent"}:
                        break
                    offset = handle.tell()
                    _write_checkpoint(checkpoint, offset)
                    advanced += 1
                return advanced
        except (OSError, UnicodeDecodeError, ValueError):
            return 0


def _fallback_has_pending() -> bool:
    path = _spool_path()
    with _spool_state_lock():
        try:
            with _open_private_read(path) as handle:
                size = os.fstat(handle.fileno()).st_size
            return _read_checkpoint(_checkpoint_path()) < size
        except (OSError, ValueError):
            return path.exists()


def _setup_logging() -> logging.Logger:
    global _logger
    if _logger is not None:
        return _logger
    with _logger_lock:
        if _logger is not None:
            return _logger
        logger = logging.getLogger("skynet_edr_hermes_plugin")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if not logger.handlers:
            log_path = _log_path()
            _ensure_private_dir(log_path.parent)
            _rotate_log_if_needed(log_path)
            handler = logging.StreamHandler(_open_private_append(log_path))
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            logger.addHandler(handler)
        _logger = logger
        return logger


def _enabled() -> bool:
    return os.environ.get("SKYNET_EDR_HERMES_PLUGIN_ENABLED", "1").lower() not in {"0", "false", "no", "off"}


def _runtime_role() -> str:
    """Return only a fixed Hermes runtime role; hostile labels become unknown."""
    configured = os.environ.get("HERMES_RUNTIME_ROLE", "unknown")
    return configured if configured in {"gateway", "dashboard", "worker", "unknown"} else "unknown"


def _runtime_instance_id() -> str:
    """Return a bounded non-sensitive process instance identifier."""
    configured = os.environ.get("SKYNET_EDR_RUNTIME_INSTANCE")
    if configured and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", configured):
        return configured
    return _runtime_instance_fallback


def _state_dir() -> Path:
    configured = os.environ.get("SKYNET_EDR_STATE_DIR")
    if configured:
        return Path(configured).expanduser()
    base = os.environ.get("XDG_STATE_HOME")
    if base:
        return Path(base).expanduser() / "skynet-edr" / "hermes"
    return Path.home() / ".local" / "state" / "skynet-edr" / "hermes"


def _spool_path() -> Path:
    return Path(os.environ.get("SKYNET_EDR_SPOOL_PATH", str(_state_dir() / "events-v1.jsonl"))).expanduser()


def _checkpoint_path() -> Path:
    return Path(
        os.environ.get("SKYNET_EDR_CHECKPOINT_PATH", str(_state_dir() / "events-v1.offset"))
    ).expanduser()


def _log_path() -> Path:
    return Path(os.environ.get("SKYNET_EDR_LOG_PATH", str(_state_dir() / "skynet-edr-plugin.log"))).expanduser()


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise OSError("refusing unsafe private state directory")
        os.fchmod(fd, stat.S_IRWXU)
    finally:
        os.close(fd)


@contextmanager
def _spool_state_lock():
    if fcntl is None:
        raise OSError("process-shared fallback locking is unavailable")
    spool = _spool_path()
    path = spool.with_name(f".{spool.name}.lock")
    _ensure_private_dir(path.parent)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise OSError("refusing unsafe fallback lock target")
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _fsync_parent(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path.parent, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _open_private_append(path: Path):
    flags = (
        os.O_APPEND
        | os.O_CREAT
        | os.O_WRONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("refusing non-regular private append target")
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        os.close(fd)
        raise
    return os.fdopen(fd, "a", encoding="utf-8")


def _open_private_read(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("refusing non-regular private replay target")
        return os.fdopen(fd, "rb")
    except OSError:
        os.close(fd)
        raise


def _read_checkpoint(path: Path) -> int:
    try:
        with _open_private_read(path) as handle:
            raw = handle.read(65)
    except FileNotFoundError:
        return 0
    if len(raw) > 64:
        raise ValueError("checkpoint is oversized")
    value = raw.decode("ascii").strip()
    offset = int(value)
    if offset < 0:
        raise ValueError("negative checkpoint")
    return offset


def _write_checkpoint(path: Path, offset: int) -> None:
    _ensure_private_dir(path.parent)
    temporary = path.with_name(
        f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}"
    )
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(str(offset))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_parent(path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def _compact_fallback_prefix(path: Path, offset: int) -> None:
    temporary = path.with_name(
        f".{path.name}.compact-{os.getpid()}-{threading.get_ident()}"
    )
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    output_fd = os.open(temporary, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with _open_private_read(path) as source, os.fdopen(output_fd, "wb") as output:
            source.seek(offset)
            while chunk := source.read(65_536):
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        # Reset first: a crash before replacement can only cause safe duplicate replay.
        _write_checkpoint(_checkpoint_path(), 0)
        os.replace(temporary, path)
        _fsync_parent(path)
    except BaseException:
        try:
            os.close(output_fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def _rotate_log_if_needed(path: Path) -> None:
    try:
        max_bytes = _safe_positive_int_env("SKYNET_EDR_MAX_LOG_BYTES", DEFAULT_MAX_LOG_BYTES)
        if path.exists() and path.stat().st_size > max_bytes:
            path.replace(path.with_suffix(path.suffix + ".1"))
    except OSError:
        return


def _safe_positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    if value <= 0:
        return default
    return value


def _now_ms() -> int:
    return int(time.time() * 1000)


def _event_id(event_type: str, now: int, attributes: dict[str, Any]) -> str:
    global _counter
    with _lock:
        _counter += 1
        counter = _counter
    digest = hashlib.sha256(
        f"{event_type}|{now}|{counter}|{os.getpid()}|{attributes.get('tool_name', '')}".encode()
    ).hexdigest()[:16]
    return f"evt_hermes_plugin_{now}_{counter}_{digest}"


def _tenant() -> str:
    return os.environ.get("SKYNET_EDR_TENANT", "local-hermes")


def _trace_id() -> str:
    return os.environ.get("HERMES_SESSION_ID") or os.environ.get("HERMES_SESSION") or _session_trace_id


def _session_attributes(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    return {"plugin_version": PLUGIN_VERSION, "argument_count": len(args), "keyword_count": len(kwargs)}


def _estimate_message_count(args: tuple[Any, ...], kwargs: dict[str, Any]) -> int | None:
    for value in list(args) + list(kwargs.values()):
        if isinstance(value, list):
            return len(value)
        if isinstance(value, dict) and isinstance(value.get("messages"), list):
            return len(value["messages"])
    return None


def _extract_tool_call(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[str, Any]:
    tool_name = kwargs.get("tool_name") or kwargs.get("name")
    params = kwargs.get("params") or kwargs.get("arguments") or kwargs.get("args")
    if tool_name is None and args:
        tool_name = args[0]
    if params is None and len(args) > 1:
        params = args[1]
    return str(tool_name or "unknown_tool"), params if params is not None else {}


def _extract_post_tool_call(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[str, Any, Any]:
    tool_name, params = _extract_tool_call(args, kwargs)
    result = kwargs.get("result") or kwargs.get("output")
    if result is None and len(args) > 2:
        result = args[2]
    return tool_name, params, result


def _is_delivery_tool(lower_tool_name: str) -> bool:
    segments = [segment for segment in re.split(r"[.:/]+", lower_tool_name) if segment]
    return lower_tool_name in _DELIVERY_TOOLS or bool(segments and segments[-1] in _DELIVERY_TOOLS)


def _classify_tool(tool_name: str, params_text: str) -> dict[str, Any]:
    lower = tool_name.lower()
    network = bool(_NETWORK_RE.search(params_text))
    delivery = _is_delivery_tool(lower)
    sensitive = bool(_LOCAL_CONTEXT_RE.search(params_text) or _SECRET_RE.search(params_text))
    if lower in _FILE_TOOLS:
        source = "file"
    elif lower in _PROCESS_TOOLS:
        source = "process"
    elif delivery:
        source = "messaging"
    else:
        source = "mcp_tool"
    return {
        "source_kind": source,
        "network_indicator": network,
        "direct_ip": network and _contains_direct_ipv4_destination(params_text),
        "delivery_indicator": delivery,
        "sensitive_access": sensitive,
        "command_class": "network_egress" if network else None,
    }


def _artifact_for_tool(tool_name: str, params: Any, params_text: str, trust_level: str) -> dict[str, Any]:
    kind = _artifact_kind(tool_name, params_text)
    label = {
        "email": "Email content",
        "url": "URL content",
        "git_repository": "Git repository",
        "code": "Code content",
        "file": "File content",
        "message": "Message content",
        "mcp": "MCP content",
        "terminal": "Terminal output",
        "unknown": "Unclassified artifact",
    }[kind]
    return {
        "kind": kind,
        "provider": _ARTIFACT_PROVIDER_BY_KIND.get(kind),
        "display_label": label,
        "locator_hash": _locator_hash(kind, params, params_text),
        "trust_level": trust_level,
    }


def _artifact_kind(tool_name: str, params_text: str) -> str:
    lower = tool_name.lower()
    segments = [segment for segment in re.split(r"[.:/]+", lower) if segment]
    leaf = segments[-1] if segments else lower
    if leaf in {"gmail", "himalaya", "email"}:
        return "email"
    if leaf in _BROWSER_TOOLS or lower.startswith("browser") or leaf in {"web_search", "web_extract"}:
        return "url"
    if "github" in lower or leaf in {"git", "gh"} or "git_repository" in params_text.lower():
        return "git_repository"
    if leaf in _CODE_TOOLS:
        return "code"
    if leaf in _FILE_TOOLS:
        return "file"
    if leaf in _MESSAGE_TOOLS:
        return "message"
    if leaf in _PROCESS_TOOLS:
        return "terminal"
    if "." in tool_name or ":" in tool_name:
        return "mcp"
    return "unknown"


def _locator_hash(kind: str, params: Any, params_text: str) -> str | None:
    locator: str | None = None
    if kind == "url":
        locator = _safe_url_locator(params, params_text)
    elif kind == "git_repository":
        locator = _safe_git_locator(params, params_text)
    if locator is None:
        return None
    return "sha256:" + hashlib.sha256(locator.encode("utf-8")).hexdigest()


def _safe_url_locator(params: Any, params_text: str) -> str | None:
    candidates: list[str] = []
    if isinstance(params, dict):
        for key in ("url", "uri"):
            value = params.get(key)
            if isinstance(value, str):
                candidates.append(value)
    candidates.extend(_URL_RE.findall(params_text))
    for candidate in candidates:
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            continue
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        try:
            parsed_port = parsed.port
        except ValueError:
            continue
        host = _canonical_url_host(parsed)
        if host is None:
            continue
        port = _canonical_port(parsed.scheme.lower(), parsed_port)
        path = _canonical_url_path(parsed.path)
        return f"{parsed.scheme.lower()}://{host}{port}{path}"
    return None



def _canonical_url_host(parsed: Any) -> str | None:
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    if netloc.startswith("["):
        end = netloc.find("]")
        if end < 0:
            return None
        raw_address = netloc[1:end]
        remainder = netloc[end + 1 :]
        if remainder and not remainder.startswith(":"):
            return None
        zone = None
        address = raw_address
        if "%25" in raw_address:
            address, zone = raw_address.split("%25", 1)
            if not zone:
                return None
        elif "%" in raw_address:
            return None
        try:
            canonical = ipaddress.IPv6Address(address).compressed
        except ValueError:
            return None
        if zone is not None:
            canonical = f"{canonical}%25{zone}"
        return f"[{canonical}]"
    host = parsed.hostname
    if host is None or ":" in host:
        return None
    return host.lower()

def _canonical_port(scheme: str, port: int | None) -> str:
    if port is None:
        return ""
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return ""
    return f":{port}"


def _canonical_url_path(path: str) -> str:
    normalized = _decode_unreserved_and_uppercase_escapes(path or "/")
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return _remove_dot_segments(normalized)


def _decode_unreserved_and_uppercase_escapes(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "%" and index + 2 < len(value) and all(c in "0123456789abcdefABCDEF" for c in value[index + 1:index + 3]):
            hex_value = value[index + 1:index + 3]
            decoded = chr(int(hex_value, 16))
            if decoded.isascii() and (decoded.isalnum() or decoded in "-._~"):
                output.append(decoded)
            else:
                output.append("%" + hex_value.upper())
            index += 3
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _remove_dot_segments(path: str) -> str:
    input_buffer = path
    output = ""
    while input_buffer:
        if input_buffer.startswith("../"):
            input_buffer = input_buffer[3:]
            continue
        if input_buffer.startswith("./"):
            input_buffer = input_buffer[2:]
            continue
        if input_buffer.startswith("/./"):
            input_buffer = "/" + input_buffer[3:]
            continue
        if input_buffer == "/.":
            input_buffer = "/"
            continue
        if input_buffer.startswith("/../"):
            input_buffer = "/" + input_buffer[4:]
            output = _remove_last_path_segment(output)
            continue
        if input_buffer == "/..":
            input_buffer = "/"
            output = _remove_last_path_segment(output)
            continue
        if input_buffer in (".", ".."):
            input_buffer = ""
            continue
        if input_buffer.startswith("/"):
            next_slash = input_buffer.find("/", 1)
            if next_slash < 0:
                output += input_buffer
                input_buffer = ""
            else:
                output += input_buffer[:next_slash]
                input_buffer = input_buffer[next_slash:]
            continue
        next_slash = input_buffer.find("/")
        if next_slash < 0:
            output += input_buffer
            input_buffer = ""
        else:
            output += input_buffer[:next_slash]
            input_buffer = input_buffer[next_slash:]
    if not output.startswith("/"):
        output = "/" + output
    return output or "/"


def _remove_last_path_segment(path: str) -> str:
    if not path:
        return ""
    slash = path.rfind("/")
    if slash <= 0:
        return ""
    return path[:slash]


def _safe_git_locator(params: Any, params_text: str) -> str | None:
    candidates: list[str] = []
    if isinstance(params, dict):
        for key in ("repository", "repo", "remote", "url"):
            value = params.get(key)
            if isinstance(value, str):
                candidates.append(value)
    candidates.extend(_GITHUB_FALLBACK_RE.findall(params_text))
    for candidate in candidates:
        if _is_github_git_locator(candidate):
            return "github.com/repository"
    return None


def _is_github_git_locator(candidate: str) -> bool:
    locator = candidate.strip().rstrip(",;)}]")
    if _is_github_url_locator(locator):
        return True
    if _GITHUB_SCP_RE.fullmatch(locator):
        return True
    return bool(_GITHUB_BARE_RE.fullmatch(locator))


def _is_github_url_locator(locator: str) -> bool:
    try:
        parsed = urlsplit(locator)
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"https", "ssh"}:
        return False
    try:
        parsed.port
    except ValueError:
        return False
    return parsed.hostname == "github.com"


def _contains_direct_ipv4_destination(text: str) -> bool:
    for url in _URL_RE.findall(text):
        try:
            hostname = urlsplit(url).hostname
        except ValueError:
            continue
        if _is_ipv4_literal(hostname):
            return True
    for pattern in (_DEV_TCP_DESTINATION_RE, _SIMPLE_DIRECT_IPV4_DESTINATION_RE):
        if any(_is_ipv4_literal(candidate) for candidate in pattern.findall(text)):
            return True
    return False


def _is_ipv4_literal(candidate: str | None) -> bool:
    if candidate is None:
        return False
    try:
        return isinstance(ipaddress.ip_address(candidate), ipaddress.IPv4Address)
    except ValueError:
        return False


def _malware_signature(text: str) -> str | None:
    match = _MALWARE_TEST_RE.search(text)
    if not match:
        return None
    value = match.group(1).lower()
    if "eicar" in value:
        return "eicar_test_string"
    return "skynet_fake_malware_test_string"


def _redaction_replacement(text: str) -> str | None:
    if _SECRET_RE.search(text):
        return "[REDACTED:secret]"
    if _LOCAL_CONTEXT_RE.search(text):
        return "[REDACTED:local_context]"
    return None


def _redacted_field(path: str, replacement: str) -> dict[str, str]:
    reason = "secret" if replacement == "[REDACTED:secret]" else "local_context"
    return {"path": path, "reason": reason, "replacement": replacement}


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    return _safe_json(value)


def _truncate(value: str) -> str:
    max_chars = _safe_positive_int_env("SKYNET_EDR_MAX_FIELD_CHARS", DEFAULT_MAX_FIELD_CHARS)
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "...[truncated]"


def _json_safe_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in attributes.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            safe[key] = value
        elif isinstance(value, (list, dict)):
            safe[key] = json.loads(_safe_json(value))
        else:
            safe[key] = str(value)
    return safe
