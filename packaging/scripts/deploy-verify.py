#!/usr/bin/env python3
"""Read-only, fail-closed DEB/systemd deployment verifier for Skynet-EDR."""

from __future__ import annotations

import argparse
import contextlib
import grp
import json
import os
import pwd
import signal
import stat
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping

PATH_CONTRACT = (
    ("/etc/skynet-edr", "directory", "root", "skynet-edr", "0750"),
    ("/etc/skynet-edr/rules.d", "directory", "root", "skynet-edr", "0750"),
    ("/etc/skynet-edr/agents.d", "directory", "root", "skynet-edr", "0750"),
    ("/etc/skynet-edr/config.toml", "regular", "root", "skynet-edr", "0640"),
    ("/var/lib/skynet-edr", "directory", "skynet-edr", "skynet-edr", "0750"),
    ("/var/log/skynet-edr", "directory", "skynet-edr", "skynet-edr", "0750"),
    ("/var/cache/skynet-edr", "directory", "skynet-edr", "skynet-edr", "0750"),
    ("/run/skynet-edr", "directory", "skynet-edr", "skynet-edr", "0750"),
    ("/run/skynet-edr-ingest", "directory", "skynet-edr", "skynet-edr-ingest", "0750"),
    ("/usr/bin/skynet-edr", "regular", "root", "root", "0755"),
    ("/usr/bin/skynet-edr-daemon", "regular", "root", "root", "0755"),
    ("/usr/libexec/skynet-edr/deploy-verify", "regular", "root", "root", "0755"),
    ("/usr/lib/systemd/system/skynet-edr.service", "regular", "root", "root", "0644"),
    ("/usr/lib/sysusers.d/skynet-edr.conf", "regular", "root", "root", "0644"),
    ("/usr/lib/tmpfiles.d/skynet-edr.conf", "regular", "root", "root", "0644"),
)
ACCESS_CONTRACT = (
    ("/etc/skynet-edr", "rx"),
    ("/etc/skynet-edr/config.toml", "r"),
    ("/var/lib/skynet-edr", "rwx"),
    ("/var/log/skynet-edr", "rwx"),
    ("/var/cache/skynet-edr", "rwx"),
    ("/run/skynet-edr", "rwx"),
    ("/run/skynet-edr-ingest", "rwx"),
)
API_PATHS = (
    "/api/status",
    "/api/v1/risks?limit=1&offset=0",
    "/api/v1/rules",
)
MAX_API_RESPONSE_BYTES = 65_536
API_TIMEOUT_SECONDS = 3.0


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_api_opener():
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirectHandler(),
    )


@contextlib.contextmanager
def request_deadline(seconds: float):
    if seconds <= 0:
        raise ValueError("request deadline must be positive")
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("request deadline requires the main thread")
    if signal.getitimer(signal.ITIMER_REAL)[0] > 0:
        raise RuntimeError("request deadline cannot replace an active timer")

    def timeout_handler(_signum, _frame):
        raise TimeoutError("HTTP request exceeded total deadline")

    previous_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def parse_port(value: str) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise ValueError("port must contain only ASCII decimal digits")
    port = int(value)
    if port < 1 or port > 65_535:
        raise ValueError("port must be between 1 and 65535")
    return port


def verify_path_records(records: Mapping[str, Mapping[str, str]]) -> list[str]:
    errors: list[str] = []
    for path, object_type, owner, group, mode in PATH_CONTRACT:
        observed = records.get(path)
        if observed is None:
            errors.append(f"{path}: missing")
            continue
        if observed.get("type") != object_type:
            errors.append(
                f"{path}: expected {object_type}, observed {observed.get('type')}"
            )
        actual = f"{observed.get('owner')}:{observed.get('group')} {observed.get('mode')}"
        expected = f"{owner}:{group} {mode}"
        if actual != expected:
            errors.append(f"{path}: expected {expected}, observed {actual}")
    return errors


def verify_access_observations(observations: Mapping[tuple[str, str], bool]) -> list[str]:
    errors: list[str] = []
    for path, permissions in ACCESS_CONTRACT:
        for permission in permissions:
            if observations.get((path, permission)) is not True:
                errors.append(f"skynet-edr lacks {permission} access to {path}")
    return errors


def verify_api_documents(documents: Mapping[str, Any], expected_version: str) -> list[str]:
    errors: list[str] = []
    for path in API_PATHS:
        if not isinstance(documents.get(path), dict):
            errors.append(f"{path}: missing HTTP 200 JSON document")
    status_doc = documents.get("/api/status")
    if isinstance(status_doc, dict):
        if status_doc.get("version") != expected_version:
            errors.append("/api/status: version mismatch")
        ingestion = status_doc.get("ingestion")
        state = ingestion.get("state") if isinstance(ingestion, dict) else None
        if state not in ("healthy", "disabled"):
            errors.append("/api/status: ingestion state must be healthy or disabled")
    risks = documents.get("/api/v1/risks?limit=1&offset=0")
    if isinstance(risks, dict):
        if risks.get("schema_version") != "skynet.risk.v1":
            errors.append("/api/v1/risks: schema_version mismatch")
        if risks.get("read_only") is not True:
            errors.append("/api/v1/risks: read_only must be true")
    rules = documents.get("/api/v1/rules")
    if isinstance(rules, dict):
        if rules.get("schema_version") != "skynet.rules.v1":
            errors.append("/api/v1/rules: schema_version mismatch")
        if rules.get("read_only") is not True:
            errors.append("/api/v1/rules: read_only must be true")
        if rules.get("compiled_active") is not True:
            errors.append("/api/v1/rules: compiled_active must be true")
    return errors


def collect_path_records() -> tuple[dict[str, dict[str, str]], list[str]]:
    records: dict[str, dict[str, str]] = {}
    errors: list[str] = []
    for path, _, _, _, _ in PATH_CONTRACT:
        try:
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode):
                errors.append(f"{path}: symlink is not permitted")
                continue
            if stat.S_ISREG(metadata.st_mode):
                object_type = "regular"
            elif stat.S_ISDIR(metadata.st_mode):
                object_type = "directory"
            elif stat.S_ISFIFO(metadata.st_mode):
                object_type = "fifo"
            elif stat.S_ISCHR(metadata.st_mode) or stat.S_ISBLK(metadata.st_mode):
                object_type = "device"
            elif stat.S_ISSOCK(metadata.st_mode):
                object_type = "socket"
            else:
                object_type = "unknown"
            if object_type not in ("regular", "directory"):
                errors.append(f"{path}: unsupported object type: {object_type}")
                continue
            records[path] = {
                "type": object_type,
                "owner": pwd.getpwuid(metadata.st_uid).pw_name,
                "group": grp.getgrgid(metadata.st_gid).gr_name,
                "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            }
        except (OSError, KeyError) as error:
            errors.append(f"{path}: inspection failed: {error}")
    return records, errors


def collect_access_observations() -> tuple[dict[tuple[str, str], bool], list[str]]:
    observations: dict[tuple[str, str], bool] = {}
    errors: list[str] = []
    if os.geteuid() != 0:
        return observations, ["service-user access checks require root"]
    for path, permissions in ACCESS_CONTRACT:
        for permission in permissions:
            try:
                result = subprocess.run(
                    ["runuser", "-u", "skynet-edr", "--", "test", f"-{permission}", path],
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                errors.append(f"access probe failed for {path} ({permission}): {error}")
                return observations, errors
            observations[(path, permission)] = result.returncode == 0
            if result.returncode not in (0, 1):
                errors.append(f"access probe failed for {path} ({permission}): exit {result.returncode}")
    return observations, errors


def collect_api_documents(port: int, opener=None) -> tuple[dict[str, Any], list[str]]:
    documents: dict[str, Any] = {}
    errors: list[str] = []
    if type(port) is not int or port < 1 or port > 65_535:
        return documents, ["invalid loopback API port"]
    if opener is None:
        opener = build_api_opener()
    for path in API_PATHS:
        expected_url = f"http://127.0.0.1:{port}{path}"
        try:
            request = urllib.request.Request(expected_url, method="GET")
            with request_deadline(API_TIMEOUT_SECONDS):
                with opener.open(request, timeout=API_TIMEOUT_SECONDS) as response:
                    if response.status != 200:
                        errors.append(
                            f"{path}: expected HTTP 200, observed {response.status}"
                        )
                        continue
                    if response.geturl() != expected_url:
                        errors.append(f"{path}: final URL mismatch")
                        continue
                    if response.headers.get_content_type() != "application/json":
                        errors.append(f"{path}: Content-Type must be application/json")
                        continue
                    body = response.read(MAX_API_RESPONSE_BYTES + 1)
                    if len(body) > MAX_API_RESPONSE_BYTES:
                        errors.append(
                            f"{path}: response exceeds {MAX_API_RESPONSE_BYTES} bytes"
                        )
                        continue
                    documents[path] = json.loads(body.decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError, UnicodeError) as error:
            errors.append(f"{path}: request failed: {error}")
    return documents, errors


def verify_service_identity() -> list[str]:
    errors: list[str] = []
    values: dict[str, str] = {}
    for property_name in ("User", "MainPID"):
        result = subprocess.run(
            ["systemctl", "show", "skynet-edr.service", f"--property={property_name}", "--value"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return [f"could not read systemd {property_name}"]
        values[property_name] = result.stdout.strip()
    user = values["User"]
    pid_text = values["MainPID"]
    if user != "skynet-edr":
        errors.append(f"systemd service user is {user!r}, expected 'skynet-edr'")
    try:
        pid = int(pid_text)
        expected_uid = pwd.getpwnam("skynet-edr").pw_uid
        status_lines = Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines()
        uid_line = next(line for line in status_lines if line.startswith("Uid:"))
        real_uid = int(uid_line.split()[1])
        if pid <= 1 or real_uid != expected_uid:
            errors.append(f"service process identity mismatch: pid={pid} uid={real_uid}")
        if not os.path.samefile(f"/proc/{pid}/exe", "/usr/bin/skynet-edr-daemon"):
            errors.append("running service executable is not the installed daemon")
    except (OSError, KeyError, StopIteration, ValueError) as error:
        errors.append(f"could not verify service process identity: {error}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--port", type=parse_port, default=8787)
    args = parser.parse_args()

    records, errors = collect_path_records()
    errors.extend(verify_path_records(records))
    observations, access_errors = collect_access_observations()
    errors.extend(access_errors)
    errors.extend(verify_access_observations(observations))
    errors.extend(verify_service_identity())
    documents, api_errors = collect_api_documents(args.port)
    errors.extend(api_errors)
    errors.extend(verify_api_documents(documents, args.expected_version))

    report = {"status": "FAIL" if errors else "PASS", "errors": errors}
    print(json.dumps(report, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
