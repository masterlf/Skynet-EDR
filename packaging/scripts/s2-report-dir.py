#!/usr/bin/env python3
"""Race-resistant private S2 report staging, sealing, and publication."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
import sys
from pathlib import Path
from typing import NoReturn

SENSITIVE_PREFIXES = ("/etc", "/proc", "/sys", "/dev", "/boot", "/root/.ssh", "/root/.gnupg")
ALLOWED_FILES = {"manifest.json", "summary.json", "metrics.tsv"}
MAX_REPORT_FILE_BYTES = 1_000_000


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def checked_parent(output: Path) -> tuple[int, str]:
    raw = str(output)
    if not output.is_absolute() or raw == "/" or any(raw == item or raw.startswith(item + "/") for item in SENSITIVE_PREFIXES):
        fail("unsafe output path")
    if output.name in {"", ".", ".."}:
        fail("unsafe output name")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in output.parent.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            info = os.fstat(descriptor)
            if info.st_uid not in {0, os.geteuid()}:
                fail("output ancestor is not owned by effective uid")
            if info.st_mode & 0o022:
                fail("output ancestor is group/other writable")
        try:
            os.stat(output.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail("output destination already exists")
        return descriptor, output.name
    except BaseException:
        os.close(descriptor)
        raise


def prepare(output: Path) -> None:
    parent_fd, final_name = checked_parent(output)
    try:
        stage_name = f".skynet-s2-stage-{secrets.token_hex(12)}"
        os.mkdir(stage_name, mode=0o700, dir_fd=parent_fd)
        stage_info = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
        parent_info = os.fstat(parent_fd)
        token = {
            "stage": str(output.parent / stage_name),
            "stage_name": stage_name,
            "stage_dev": stage_info.st_dev,
            "stage_ino": stage_info.st_ino,
            "parent_dev": parent_info.st_dev,
            "parent_ino": parent_info.st_ino,
            "final_name": final_name,
        }
        print(json.dumps(token, sort_keys=True))
    finally:
        os.close(parent_fd)


def check(output: Path) -> None:
    parent_fd, _ = checked_parent(output)
    os.close(parent_fd)


def decode_token(raw: str) -> dict[str, object]:
    try:
        token = json.loads(raw)
    except json.JSONDecodeError as error:
        fail(f"invalid report identity token: {error}")
    required = {"stage", "stage_name", "stage_dev", "stage_ino", "parent_dev", "parent_ino", "final_name"}
    if not isinstance(token, dict) or set(token) != required:
        fail("invalid report identity token shape")
    return token


def verify_stage(output: Path, token: dict[str, object]) -> tuple[int, os.stat_result]:
    parent_fd, final_name = checked_parent(output)
    parent_info = os.fstat(parent_fd)
    if (parent_info.st_dev, parent_info.st_ino) != (token["parent_dev"], token["parent_ino"]):
        os.close(parent_fd)
        fail("output parent identity drift")
    if final_name != token["final_name"]:
        os.close(parent_fd)
        fail("output name identity drift")
    try:
        stage_info = os.stat(str(token["stage_name"]), dir_fd=parent_fd, follow_symlinks=False)
    except BaseException:
        os.close(parent_fd)
        raise
    if not stat.S_ISDIR(stage_info.st_mode) or (stage_info.st_dev, stage_info.st_ino) != (token["stage_dev"], token["stage_ino"]):
        os.close(parent_fd)
        fail("report stage identity drift")
    if stage_info.st_uid != os.geteuid() or stat.S_IMODE(stage_info.st_mode) != 0o700:
        os.close(parent_fd)
        fail("report stage ownership or mode drift")
    return parent_fd, stage_info


def forbidden_literals() -> set[bytes]:
    values = {
        os.environ.get("S2_VALIDATION_FAKE_SECRET", ""),
        os.environ.get("S2_VALIDATION_HOSTILE_DIAGNOSTIC", ""),
        "S2_FAKE_HONEYTOKEN_EXFIL_7Q9X",
        "S2_FAKE_HONEYTOKEN_MSG_4M2P",
    }
    fixture = Path(__file__).resolve().parents[2] / "crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json"
    manifest = json.loads(fixture.read_text(encoding="utf-8"))
    values.update(
        marker
        for case in manifest["cases"]
        for marker in case.get("forbidden_markers", [])
    )
    return {value.encode() for value in values if value}


def seal(stage: Path) -> None:
    expected = ALLOWED_FILES | {f"logs/{name}.log" for name in (
        "docs", "packaging", "fmt", "clippy", "rust-workspace", "hermes-python",
        "producer-corpus", "dashboard-node", "desktop-node", "corpus", "runtime-canary"
    )}
    actual = {str(path.relative_to(stage)) for path in stage.rglob("*") if path.is_file()}
    if actual != expected:
        fail("unexpected or missing report file")
    forbidden = forbidden_literals()
    for relative in sorted(actual):
        path = stage / relative
        data = path.read_bytes()
        if len(data) > MAX_REPORT_FILE_BYTES:
            fail("report file byte ceiling exceeded")
        if any(literal in data for literal in forbidden):
            fail("forbidden literal in report")
        os.chmod(path, 0o600, follow_symlinks=False)
    checksums = []
    for relative in sorted(actual):
        digest = hashlib.sha256((stage / relative).read_bytes()).hexdigest()
        checksums.append(f"{digest}  {relative}\n")
    sums = stage / "SHA256SUMS"
    sums.write_text("".join(checksums), encoding="ascii")
    os.chmod(sums, 0o600)


def publish(output: Path, token: dict[str, object]) -> None:
    parent_fd, _ = verify_stage(output, token)
    try:
        stage = Path(str(token["stage"]))
        if not (stage / "SHA256SUMS").is_file():
            fail("report is not safely sealed")
        os.rename(str(token["stage_name"]), str(token["final_name"]), src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        final_info = os.stat(str(token["final_name"]), dir_fd=parent_fd, follow_symlinks=False)
        if (final_info.st_dev, final_info.st_ino) != (token["stage_dev"], token["stage_ino"]):
            fail("published report identity drift")
    finally:
        os.close(parent_fd)


def abort(output: Path, token: dict[str, object]) -> None:
    parent_fd, _ = verify_stage(output, token)
    try:
        shutil.rmtree(Path(str(token["stage"])))
    finally:
        os.close(parent_fd)


def main() -> None:
    if len(sys.argv) < 3:
        fail("usage: s2-report-dir.py check|prepare OUTPUT | seal STAGE | publish|abort OUTPUT TOKEN")
    command = sys.argv[1]
    if command == "check" and len(sys.argv) == 3:
        check(Path(sys.argv[2]))
    elif command == "prepare" and len(sys.argv) == 3:
        prepare(Path(sys.argv[2]))
    elif command == "seal" and len(sys.argv) == 3:
        seal(Path(sys.argv[2]))
    elif command == "publish" and len(sys.argv) == 4:
        publish(Path(sys.argv[2]), decode_token(sys.argv[3]))
    elif command == "abort" and len(sys.argv) == 4:
        abort(Path(sys.argv[2]), decode_token(sys.argv[3]))
    else:
        fail("invalid report helper command")


if __name__ == "__main__":
    main()
