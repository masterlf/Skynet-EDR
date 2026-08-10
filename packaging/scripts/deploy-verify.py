#!/usr/bin/env python3
"""Read-only, fail-closed DEB/systemd deployment verifier for Skynet-EDR."""

from __future__ import annotations

import argparse
import base64
import contextlib
import grp
import hashlib
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

PLUGIN_ROOT = Path("/usr/share/skynet-edr/hermes-plugin/skynet-edr")
PLUGIN_MANIFEST = PLUGIN_ROOT.parent / "manifest.json"
PLUGIN_FILES = (
    "plugin.yaml", "__init__.py", "README.md", "dashboard/manifest.json",
    "dashboard/plugin.js", "dashboard/plugin_api.py", "desktop/plugin.js",
)
PLUGIN_DIRECTORIES = {
    "": {"plugin.yaml", "__init__.py", "README.md", "dashboard", "desktop"},
    "dashboard": {"manifest.json", "plugin.js", "plugin_api.py"},
    "desktop": {"plugin.js"},
}
MAX_PLUGIN_FILE_BYTES = 2_097_152

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


def verify_version_identity(
    expected_product_version: str,
    expected_deb_version: str,
    installed_deb_version: str,
    cli_version: str,
    daemon_version: str,
) -> list[str]:
    errors: list[str] = []
    if installed_deb_version != expected_deb_version:
        errors.append("dpkg package version mismatch")
    if cli_version.strip() != f"skynet-edr {expected_product_version}":
        errors.append("CLI version mismatch")
    if daemon_version.strip() != f"skynet-edr-daemon {expected_product_version}":
        errors.append("daemon version mismatch")
    return errors


def verify_plugin_manifest(manifest: Any, files: Mapping[str, bytes], expected_version: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "payload_version", "generation", "files"}:
        return ["Hermes plugin manifest schema mismatch"]
    if manifest.get("schema") != 1 or manifest.get("payload_version") != expected_version:
        errors.append("Hermes plugin manifest version mismatch")
    records = manifest.get("files")
    if not isinstance(records, dict) or set(records) != set(PLUGIN_FILES):
        return errors + ["Hermes plugin manifest file allowlist mismatch"]
    if set(files) != set(PLUGIN_FILES):
        errors.append("installed Hermes plugin file allowlist mismatch")
    for relative in PLUGIN_FILES:
        record = records.get(relative)
        data = files.get(relative)
        if not isinstance(record, dict) or set(record) != {"sha256", "size", "mode", "owner"}:
            errors.append(f"{relative}: manifest record mismatch")
            continue
        if record.get("mode") != 0o644 or record.get("owner") != 0:
            errors.append(f"{relative}: manifest metadata mismatch")
        if not isinstance(data, bytes):
            errors.append(f"{relative}: installed bytes missing")
            continue
        if record.get("size") != len(data):
            errors.append(f"{relative}: size mismatch")
        if record.get("sha256") != hashlib.sha256(data).hexdigest():
            errors.append(f"{relative}: sha256 mismatch")
    generation = hashlib.sha256(
        json.dumps(records, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    if manifest.get("generation") != generation:
        errors.append("Hermes plugin manifest generation mismatch")
    dashboard_bytes = files.get("dashboard/manifest.json")
    bundle = files.get("dashboard/plugin.js")
    if isinstance(dashboard_bytes, bytes) and isinstance(bundle, bytes):
        try:
            dashboard = json.loads(dashboard_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            errors.append("dashboard manifest is not valid UTF-8 JSON")
        else:
            sri = "sha384-" + base64.b64encode(hashlib.sha384(bundle).digest()).decode("ascii")
            if dashboard.get("version") != expected_version:
                errors.append("dashboard manifest version mismatch")
            if dashboard.get("integrity") != sri:
                errors.append("dashboard bundle integrity mismatch")
    return errors


def verify_loaded_generation(status_document: Any, expected_generation: str) -> list[str]:
    ingestion = status_document.get("ingestion") if isinstance(status_document, dict) else None
    if isinstance(ingestion, dict) and ingestion.get("state") == "disabled":
        return []
    sources = ingestion.get("sources") if isinstance(ingestion, dict) else None
    if not isinstance(sources, list):
        return ["/api/status: loaded Hermes plugin generation unavailable"]
    generations = {
        source.get("plugin_generation") for source in sources
        if isinstance(source, dict) and source.get("protocol_version") == 3
    }
    return [] if generations == {expected_generation} else ["/api/status: loaded Hermes plugin generation mismatch"]


def collect_version_identity() -> tuple[tuple[str, str, str] | None, list[str]]:
    commands = (
        ("dpkg", ["dpkg-query", "-W", "-f=${Version}", "skynet-edr"]),
        ("CLI", ["/usr/bin/skynet-edr", "--version"]),
        ("daemon", ["/usr/bin/skynet-edr-daemon", "--version"]),
    )
    values: list[str] = []
    for label, command in commands:
        try:
            result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return None, [f"could not read {label} version"]
        if result.returncode != 0 or not result.stdout.strip():
            return None, [f"could not read {label} version"]
        values.append(result.stdout.strip())
    return (values[0], values[1], values[2]), []


def _open_absolute_directory(
    path: Path,
    label: str,
    errors: list[str],
    allowed_owners: frozenset[int] = frozenset({0}),
) -> int | None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    if not path.is_absolute() or ".." in path.parts:
        errors.append(f"{label}: installed directory inspection failed")
        return None
    descriptor: int | None = None
    try:
        descriptor = os.open("/", flags)
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            info = os.fstat(child)
            writable = bool(info.st_mode & 0o022)
            trusted_sticky = bool(info.st_mode & stat.S_ISVTX) and info.st_uid == 0
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in allowed_owners
                    or (writable and not trusted_sticky)):
                os.close(child)
                raise OSError("unsafe directory component")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        errors.append(f"{label}: installed directory inspection failed")
        return None


def _open_child_directory(
    parent_fd: int,
    name: str,
    label: str,
    errors: list[str],
    expected_owner: int = 0,
    expected_group: int = 0,
) -> int | None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        info = os.fstat(descriptor)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_owner
                or info.st_gid != expected_group
                or stat.S_IMODE(info.st_mode) != 0o755):
            errors.append(f"{label}: installed directory metadata mismatch")
        return descriptor
    except OSError:
        errors.append(f"{label}: installed directory inspection failed")
        return None


def _read_regular_file(
    parent_fd: int,
    name: str,
    label: str,
    errors: list[str],
    expected_owner: int = 0,
    expected_group: int = 0,
) -> bytes | None:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    except OSError:
        errors.append(f"{label}: installed file inspection failed")
        return None
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != expected_owner or before.st_gid != expected_group
                or stat.S_IMODE(before.st_mode) != 0o644):
            errors.append(f"{label}: installed metadata mismatch")
            return None
        chunks: list[bytes] = []
        length = 0
        while True:
            chunk = os.read(descriptor, min(65_536, MAX_PLUGIN_FILE_BYTES + 1 - length))
            if not chunk:
                break
            length += len(chunk)
            if length > MAX_PLUGIN_FILE_BYTES:
                errors.append(f"{label}: installed file too large")
                return None
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                                  value.st_gid, value.st_nlink, value.st_size)
        if identity(before) != identity(after) or length != after.st_size:
            errors.append(f"{label}: installed file changed during inspection")
            return None
        return b"".join(chunks)
    except OSError:
        errors.append(f"{label}: installed file inspection failed")
        return None
    finally:
        os.close(descriptor)


def collect_plugin_payload(
    plugin_root: Path | None = None,
    manifest_path: Path | None = None,
    expected_owner: int = 0,
    expected_group: int = 0,
    allowed_ancestor_owners: frozenset[int] = frozenset({0}),
) -> tuple[dict[str, Any] | None, dict[str, bytes], list[str]]:
    root = PLUGIN_ROOT if plugin_root is None else plugin_root
    manifest_file = PLUGIN_MANIFEST if manifest_path is None else manifest_path
    errors: list[str] = []
    files: dict[str, bytes] = {}
    parent_fd = _open_absolute_directory(
        manifest_file.parent,
        "Hermes plugin payload root",
        errors,
        allowed_ancestor_owners,
    )
    if parent_fd is None:
        return None, files, errors
    plugin_fd: int | None = None
    children: dict[str, int] = {}
    manifest: dict[str, Any] | None = None
    try:
        try:
            if set(os.listdir(parent_fd)) != {manifest_file.name, root.name}:
                errors.append("installed Hermes plugin payload allowlist mismatch")
        except OSError:
            errors.append("installed Hermes plugin payload enumeration failed")
        manifest_bytes = _read_regular_file(
            parent_fd,
            manifest_file.name,
            manifest_file.name,
            errors,
            expected_owner,
            expected_group,
        )
        if manifest_bytes is not None:
            try:
                candidate = json.loads(manifest_bytes.decode("ascii"))
                manifest = candidate if isinstance(candidate, dict) else None
            except (UnicodeError, json.JSONDecodeError):
                pass
            if manifest is None:
                errors.append("could not read Hermes plugin manifest")
        plugin_fd = _open_child_directory(
            parent_fd,
            root.name,
            "Hermes plugin",
            errors,
            expected_owner,
            expected_group,
        )
        if plugin_fd is None:
            return manifest, files, errors
        try:
            if set(os.listdir(plugin_fd)) != PLUGIN_DIRECTORIES[""]:
                errors.append("installed Hermes plugin file allowlist mismatch")
        except OSError:
            errors.append("installed Hermes plugin enumeration failed")
        for directory in ("dashboard", "desktop"):
            child = _open_child_directory(
                plugin_fd,
                directory,
                directory,
                errors,
                expected_owner,
                expected_group,
            )
            if child is not None:
                children[directory] = child
                try:
                    if set(os.listdir(child)) != PLUGIN_DIRECTORIES[directory]:
                        errors.append(f"{directory}: installed file allowlist mismatch")
                except OSError:
                    errors.append(f"{directory}: installed directory enumeration failed")
        for relative in PLUGIN_FILES:
            if "/" in relative:
                directory, name = relative.split("/", 1)
                descriptor = children.get(directory)
                if descriptor is None:
                    continue
            else:
                descriptor, name = plugin_fd, relative
            data = _read_regular_file(
                descriptor,
                name,
                relative,
                errors,
                expected_owner,
                expected_group,
            )
            if data is not None:
                files[relative] = data
    finally:
        for descriptor in children.values():
            os.close(descriptor)
        if plugin_fd is not None:
            os.close(plugin_fd)
        os.close(parent_fd)
    return manifest, files, errors


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
    parser.add_argument("--expected-product-version", required=True)
    parser.add_argument("--expected-deb-version", required=True)
    parser.add_argument("--hermes-plugin-root", type=Path)
    parser.add_argument("--hermes-plugin-uid", type=int)
    parser.add_argument("--hermes-plugin-gid", type=int)
    parser.add_argument("--port", type=parse_port, default=8787)
    args = parser.parse_args()
    copied_identity = (args.hermes_plugin_uid, args.hermes_plugin_gid)
    if args.hermes_plugin_root is not None and (
        None in copied_identity or any(value < 0 for value in copied_identity if value is not None)
    ):
        parser.error("--hermes-plugin-root requires non-negative --hermes-plugin-uid and --hermes-plugin-gid")
    if args.hermes_plugin_root is None and copied_identity != (None, None):
        parser.error("copied plugin UID/GID require --hermes-plugin-root")

    records, errors = collect_path_records()
    errors.extend(verify_path_records(records))
    versions, version_errors = collect_version_identity()
    errors.extend(version_errors)
    if versions is not None:
        errors.extend(verify_version_identity(
            args.expected_product_version, args.expected_deb_version, *versions
        ))
    manifest, plugin_files, plugin_errors = collect_plugin_payload()
    errors.extend(plugin_errors)
    errors.extend(verify_plugin_manifest(manifest, plugin_files, args.expected_product_version))
    if args.hermes_plugin_root is not None:
        copied_manifest, copied_files, copied_errors = collect_plugin_payload(
            args.hermes_plugin_root,
            args.hermes_plugin_root.parent / "manifest.json",
            args.hermes_plugin_uid,
            args.hermes_plugin_gid,
            frozenset({0, args.hermes_plugin_uid}),
        )
        errors.extend(copied_errors)
        errors.extend(verify_plugin_manifest(
            copied_manifest, copied_files, args.expected_product_version
        ))
        if copied_manifest != manifest or copied_files != plugin_files:
            errors.append("HERMES_HOME plugin bytes differ from package payload")
    observations, access_errors = collect_access_observations()
    errors.extend(access_errors)
    errors.extend(verify_access_observations(observations))
    errors.extend(verify_service_identity())
    documents, api_errors = collect_api_documents(args.port)
    errors.extend(api_errors)
    errors.extend(verify_api_documents(documents, args.expected_product_version))
    if isinstance(manifest, dict) and isinstance(manifest.get("generation"), str):
        errors.extend(verify_loaded_generation(
            documents.get("/api/status"), manifest["generation"]
        ))

    report = {"status": "FAIL" if errors else "PASS", "errors": errors}
    print(json.dumps(report, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
