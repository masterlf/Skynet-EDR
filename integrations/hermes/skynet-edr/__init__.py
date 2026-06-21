"""Skynet-EDR passive telemetry plugin for Hermes Agent.

The plugin is intentionally non-blocking. It observes Hermes lifecycle hooks,
emits canonical ``skynet.event.v0`` JSONL records to a local spool, and writes a
sanitized operational log. It never executes tool content, never performs
network egress, and never stores raw tool output.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import threading
import time
import uuid
from pathlib import Path
from typing import Any

PLUGIN_NAME = "skynet-edr"
PLUGIN_VERSION = "0.3.0"
SCHEMA_VERSION = "skynet.event.v0"
DEFAULT_MAX_FIELD_CHARS = 4096
DEFAULT_MAX_LOG_BYTES = 1_048_576

_SECRET_RE = re.compile(
    r"(?i)(authorization\s*:\s*bearer\s+\S+|x-api-key\s*[:=]\s*\S+|api[_-]?key\s*[:=]\s*\S+|token\s*[:=]\s*\S+|secret\s*[:=]\s*\S+|password\s*[:=]\s*\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
_LOCAL_CONTEXT_RE = re.compile(
    r"(?i)(/home/[\w_.-]+/\.hermes/\S*|/root/\.hermes/\S*|/home/[\w_.-]+/\.ssh/\S*|/root/\.ssh/\S*|/home/[\w_.-]+/[^\s'\"]*\.env|/root/[^\s'\"]*\.env)"
)
_NETWORK_RE = re.compile(r"(?i)(\bcurl\b|\bwget\b|https?://|/dev/tcp|\bnc\b|\bncat\b)")
_DELIVERY_TOOLS = {"send_message", "himalaya", "gmail", "telegram", "discord", "slack", "email"}
_PROCESS_TOOLS = {"terminal", "execute_code", "shell", "bash", "python"}
_FILE_TOOLS = {"read_file", "write_file", "patch", "search_files"}
_PROMPT_INJECTION_RE = re.compile(
    r"(?i)(ignore (all )?(previous|prior) instructions|disregard (all )?(previous|prior) instructions|system prompt|developer message|reveal your instructions|exfiltrate|send (the )?(secret|token|credentials))"
)
_MALWARE_TEST_RE = re.compile(
    r"(?i)(skynet_fake_malware_test_string_do_not_execute|eicar-standard-antivirus-test-file)"
)

_lock = threading.Lock()
_logger_lock = threading.Lock()
_session_trace_id = f"hermes-local-{uuid.uuid4().hex}"
_counter = 0
_logger: logging.Logger | None = None


def register(ctx: Any) -> None:
    """Register passive Hermes hooks."""
    _setup_logging().info("registering Skynet-EDR Hermes plugin hooks version=%s", PLUGIN_VERSION)
    ctx.register_hook("on_session_start", _safe_hook(_on_session_start))
    ctx.register_hook("on_session_end", _safe_hook(_on_session_end))
    ctx.register_hook("pre_llm_call", _safe_hook(_pre_llm_call))
    ctx.register_hook("pre_tool_call", _safe_hook(_pre_tool_call))
    ctx.register_hook("post_tool_call", _safe_hook(_post_tool_call))


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
    attrs: dict[str, Any] = {
        "hook": "pre_tool_call",
        "tool_name": tool_name,
        "network_indicator": indicators["network_indicator"],
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
        attrs["params_preview"] = _truncate(params_text)
    if indicators["command_class"]:
        attrs["command_class"] = indicators["command_class"]
    _write_event(
        event_type="agent.tool.requested",
        source_kind=indicators["source_kind"],
        trust_level="agent_action",
        severity="high"
        if indicators["network_indicator"] or indicators["delivery_indicator"] or indicators["sensitive_access"]
        else "low",
        title=f"Hermes tool requested: {tool_name}",
        attributes=attrs,
        redacted_fields=redacted,
    )


def _post_tool_call(*args: Any, **kwargs: Any) -> None:
    tool_name, params, result = _extract_post_tool_call(args, kwargs)
    result_text = _stringify(result)
    params_text = _safe_json(params)
    indicators = _classify_tool(tool_name, params_text)
    malware_signature = _malware_signature(result_text)
    injection = bool(_PROMPT_INJECTION_RE.search(result_text))
    attrs: dict[str, Any] = {
        "hook": "post_tool_call",
        "tool_name": tool_name,
        "result_omitted": True,
        "result_length": len(result_text),
        "network_indicator": indicators["network_indicator"],
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
    )
    if injection:
        _write_event(
            event_type="agent.content.ingested",
            source_kind="mcp_tool",
            trust_level="untrusted_content",
            severity="medium",
            title="Untrusted Hermes tool output contains prompt-injection instructions",
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
    line = json.dumps(event, separators=(",", ":"), sort_keys=True)
    spool = _spool_path()
    _ensure_private_dir(spool.parent)
    with _lock:
        with _open_private_append(spool) as handle:
            handle.write(line + "\n")
    _setup_logging().info("wrote_event event_id=%s event_type=%s severity=%s", event_id, event_type, severity)


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


def _state_dir() -> Path:
    configured = os.environ.get("SKYNET_EDR_STATE_DIR")
    if configured:
        return Path(configured).expanduser()
    base = os.environ.get("XDG_STATE_HOME")
    if base:
        return Path(base).expanduser() / "skynet-edr" / "hermes"
    return Path.home() / ".local" / "state" / "skynet-edr" / "hermes"


def _spool_path() -> Path:
    return Path(os.environ.get("SKYNET_EDR_SPOOL_PATH", str(_state_dir() / "events.jsonl"))).expanduser()


def _log_path() -> Path:
    return Path(os.environ.get("SKYNET_EDR_LOG_PATH", str(_state_dir() / "skynet-edr-plugin.log"))).expanduser()


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(stat.S_IRWXU)
    except OSError:
        pass


def _open_private_append(path: Path):
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, stat.S_IRUSR | stat.S_IWUSR)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        os.close(fd)
        raise
    return os.fdopen(fd, "a", encoding="utf-8")


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
        "delivery_indicator": delivery,
        "sensitive_access": sensitive,
        "command_class": "network_egress" if network else None,
    }


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
