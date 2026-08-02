#!/usr/bin/env python3
"""Private S2 report staging, sealing, and publication helpers.

The caller must provide an isolated parent without a malicious concurrent
same-effective-UID writer; see docs/M4A_VALIDATION.md.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
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


def create_stage(output: Path) -> tuple[int, int, dict[str, object]]:
    parent_fd, final_name = checked_parent(output)
    try:
        stage_name = f".skynet-s2-stage-{secrets.token_hex(12)}"
        os.mkdir(stage_name, mode=0o700, dir_fd=parent_fd)
        stage_fd = os.open(
            stage_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        stage_info = os.fstat(stage_fd)
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
        return parent_fd, stage_fd, token
    except BaseException:
        os.close(parent_fd)
        raise


def prepare(output: Path) -> None:
    parent_fd, stage_fd, token = create_stage(output)
    try:
        print(json.dumps(token, sort_keys=True))
    finally:
        os.close(stage_fd)
        os.close(parent_fd)


def exec_with_stage(output: Path, command: list[str]) -> NoReturn:
    if not command:
        fail("missing validator command")
    parent_fd, stage_fd, token = create_stage(output)
    os.set_inheritable(parent_fd, True)
    os.set_inheritable(stage_fd, True)
    environment = os.environ.copy()
    environment.update(
        {
            "S2_REPORT_PARENT_FD": str(parent_fd),
            "S2_REPORT_STAGE_FD": str(stage_fd),
            "S2_REPORT_STAGE": f"/proc/self/fd/{stage_fd}",
            "S2_REPORT_TOKEN": json.dumps(token, sort_keys=True),
        }
    )
    os.execvpe(command[0], command, environment)


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


def retained_fds(output: Path, token: dict[str, object]) -> tuple[int, int]:
    try:
        parent_fd = int(os.environ["S2_REPORT_PARENT_FD"])
        stage_fd = int(os.environ["S2_REPORT_STAGE_FD"])
    except (KeyError, ValueError):
        fail("missing retained report descriptors")
    parent_info = os.fstat(parent_fd)
    stage_info = os.fstat(stage_fd)
    if (parent_info.st_dev, parent_info.st_ino) != (
        token["parent_dev"],
        token["parent_ino"],
    ):
        fail("retained output parent identity drift")
    if (stage_info.st_dev, stage_info.st_ino) != (
        token["stage_dev"],
        token["stage_ino"],
    ):
        fail("retained report stage identity drift")
    if (
        not stat.S_ISDIR(stage_info.st_mode)
        or stage_info.st_uid != os.geteuid()
        or stat.S_IMODE(stage_info.st_mode) != 0o700
    ):
        fail("retained report stage ownership or mode drift")
    if output.name != token["final_name"]:
        fail("output name identity drift")
    entry = os.stat(
        str(token["stage_name"]), dir_fd=parent_fd, follow_symlinks=False
    )
    if not stat.S_ISDIR(entry.st_mode) or (entry.st_dev, entry.st_ino) != (
        stage_info.st_dev,
        stage_info.st_ino,
    ):
        fail("report stage identity drift")
    return parent_fd, stage_fd


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


def read_regular(stage_fd: int, relative: str) -> bytes:
    descriptor = os.open(relative, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=stage_fd)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        os.close(descriptor)
        fail("report entry is not an owned regular file")
    with os.fdopen(descriptor, "rb", closefd=True) as stream:
        data = stream.read(MAX_REPORT_FILE_BYTES + 1)
    if len(data) > MAX_REPORT_FILE_BYTES:
        fail("report file byte ceiling exceeded")
    return data


def seal_fd(output: Path, token: dict[str, object]) -> None:
    _, stage_fd = retained_fds(output, token)
    expected_logs = {
        f"{name}.log"
        for name in (
            "docs", "packaging", "fmt", "clippy", "rust-workspace", "hermes-python",
            "producer-corpus", "dashboard-node", "desktop-node", "corpus", "runtime-canary",
        )
    }
    if set(os.listdir(stage_fd)) != ALLOWED_FILES | {"logs"}:
        fail("unexpected or missing report entry")
    logs_fd = os.open(
        "logs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stage_fd
    )
    try:
        if set(os.listdir(logs_fd)) != expected_logs:
            fail("unexpected or missing report log")
    finally:
        os.close(logs_fd)
    relative_files = sorted(ALLOWED_FILES | {f"logs/{name}" for name in expected_logs})
    forbidden = forbidden_literals()
    checksums = []
    for relative in relative_files:
        data = read_regular(stage_fd, relative)
        if any(literal in data for literal in forbidden):
            fail("forbidden literal in report")
        os.chmod(relative, 0o600, dir_fd=stage_fd, follow_symlinks=False)
        checksums.append(f"{hashlib.sha256(data).hexdigest()}  {relative}\n")
    sums_fd = os.open(
        "SHA256SUMS",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=stage_fd,
    )
    with os.fdopen(sums_fd, "w", encoding="ascii", closefd=True) as stream:
        stream.write("".join(checksums))


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


def publish_fd(output: Path, token: dict[str, object]) -> None:
    parent_fd, stage_fd = retained_fds(output, token)
    seal_info = os.stat("SHA256SUMS", dir_fd=stage_fd, follow_symlinks=False)
    if not stat.S_ISREG(seal_info.st_mode):
        fail("report is not safely sealed")
    try:
        os.stat(str(token["final_name"]), dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        fail("output destination already exists")
    os.rename(
        str(token["stage_name"]),
        str(token["final_name"]),
        src_dir_fd=parent_fd,
        dst_dir_fd=parent_fd,
    )
    final_info = os.stat(
        str(token["final_name"]), dir_fd=parent_fd, follow_symlinks=False
    )
    if (final_info.st_dev, final_info.st_ino) != (
        token["stage_dev"],
        token["stage_ino"],
    ):
        fail("published report identity drift")


def remove_tree_fd(directory_fd: int) -> None:
    for name in os.listdir(directory_fd):
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                remove_tree_fd(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)


def abort_fd(output: Path, token: dict[str, object]) -> None:
    parent_fd, stage_fd = retained_fds(output, token)
    remove_tree_fd(stage_fd)
    os.rmdir(str(token["stage_name"]), dir_fd=parent_fd)


def abort(output: Path, token: dict[str, object]) -> None:
    parent_fd, _ = verify_stage(output, token)
    try:
        stage_fd = os.open(
            str(token["stage_name"]),
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            remove_tree_fd(stage_fd)
        finally:
            os.close(stage_fd)
        os.rmdir(str(token["stage_name"]), dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def main() -> None:
    if len(sys.argv) < 3:
        fail("usage: s2-report-dir.py check|prepare|exec|seal|seal-fd|publish|publish-fd|abort|abort-fd ...")
    command = sys.argv[1]
    if command == "check" and len(sys.argv) == 3:
        check(Path(sys.argv[2]))
    elif command == "prepare" and len(sys.argv) == 3:
        prepare(Path(sys.argv[2]))
    elif command == "exec" and len(sys.argv) >= 4:
        exec_with_stage(Path(sys.argv[2]), sys.argv[3:])
    elif command == "seal" and len(sys.argv) == 3:
        seal(Path(sys.argv[2]))
    elif command == "seal-fd" and len(sys.argv) == 4:
        seal_fd(Path(sys.argv[2]), decode_token(sys.argv[3]))
    elif command == "publish" and len(sys.argv) == 4:
        publish(Path(sys.argv[2]), decode_token(sys.argv[3]))
    elif command == "publish-fd" and len(sys.argv) == 4:
        publish_fd(Path(sys.argv[2]), decode_token(sys.argv[3]))
    elif command == "abort" and len(sys.argv) == 4:
        abort(Path(sys.argv[2]), decode_token(sys.argv[3]))
    elif command == "abort-fd" and len(sys.argv) == 4:
        abort_fd(Path(sys.argv[2]), decode_token(sys.argv[3]))
    else:
        fail("invalid report helper command")


if __name__ == "__main__":
    main()
