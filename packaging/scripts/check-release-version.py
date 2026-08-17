#!/usr/bin/env python3
"""Fail closed when release version surfaces disagree."""

from __future__ import annotations

import argparse
import ast
import dis
import json
import re
import tomllib
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEPENDENCY_TABLES = ("dependencies", "build-dependencies", "dev-dependencies")
UNSAFE_PYTHON_NAMESPACE_NAMES = {
    "__builtins__",
    "compile",
    "delattr",
    "eval",
    "exec",
    "globals",
    "locals",
    "setattr",
    "vars",
}
SEMVER_NUMERIC_IDENTIFIER = r"(?:0|[1-9][0-9]*)"
SEMVER_PRERELEASE_IDENTIFIER = (
    r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
)
CANONICAL_RELEASE_VERSION_PATTERN = (
    rf"{SEMVER_NUMERIC_IDENTIFIER}\."
    rf"{SEMVER_NUMERIC_IDENTIFIER}\."
    rf"{SEMVER_NUMERIC_IDENTIFIER}"
    rf"(?:-{SEMVER_PRERELEASE_IDENTIFIER}(?:\.{SEMVER_PRERELEASE_IDENTIFIER})*)?"
)
CURRENT_RELEASE_KIND_PATTERN = r"(prerelease|pre-1\.0 stable SemVer evaluation release)"
CURRENT_RELEASE_KIND_AUTHORITIES = {
    "docs/INSTALL.md": (
        rf"^Skynet-EDR is currently .* The installable {CURRENT_RELEASE_KIND_PATTERN} has ",
    ),
    "docs/README.md": (
        rf"^\| Check what this {CURRENT_RELEASE_KIND_PATTERN} actually supports \|",
    ),
    "docs/MVP_SUPPORT_MATRIX.md": (
        rf"^Skynet-EDR is a passive, local-first, Linux `x86_64`/`amd64` {CURRENT_RELEASE_KIND_PATTERN}\.",
        rf"^Published checksums provide integrity checking, but this {CURRENT_RELEASE_KIND_PATTERN} has ",
    ),
    "docs/ROADMAP.md": (
        rf"^The release remains passive and is published as a {CURRENT_RELEASE_KIND_PATTERN}\.",
    ),
}


def is_canonical_release_version(value: object) -> bool:
    """Return whether a value is canonical SemVer without build metadata."""
    return type(value) is str and re.fullmatch(CANONICAL_RELEASE_VERSION_PATTERN, value) is not None


def native_package_version(product_version: str) -> str:
    """Map canonical product SemVer to the exact native DEB/RPM identity."""
    release, separator, prerelease = product_version.partition("-")
    return f"{release}~{prerelease}" if separator else release


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require_current_release_kind(expected: str) -> None:
    """Require current release authorities to agree with the SemVer release kind."""
    required_kind = "prerelease" if "-" in expected else "pre-1.0 stable SemVer evaluation release"
    for path, patterns in CURRENT_RELEASE_KIND_AUTHORITIES.items():
        document = text(path)
        for pattern in patterns:
            observed = re.findall(pattern, document, flags=re.MULTILINE)
            if observed != [required_kind]:
                release_kind = "prerelease" if "-" in expected else "stable current release"
                raise SystemExit(f"{path} misstates the {release_kind} kind")


def require_unique_yaml_scalar(path: str, value_pattern: str, label: str) -> str:
    authorities: list[str] = []
    for line_number, line in enumerate(text(path).splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#") or line.startswith(" "):
            continue
        mapping = re.fullmatch(r"([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*)", line)
        if mapping is not None:
            key, value = mapping.groups()
        else:
            quoted_version = re.fullmatch(r'''["']version["']\s*:\s*(.*)''', line)
            if quoted_version is None:
                raise SystemExit(
                    f"unsupported root YAML syntax in {path}:{line_number}"
                )
            key, value = "version", quoted_version.group(1)
        if key == "version":
            authorities.append(value)
    if not authorities:
        raise SystemExit(f"missing {label} in {path}")
    if len(authorities) != 1:
        raise SystemExit(f"duplicate {label} in {path}")
    match = re.fullmatch(value_pattern, authorities[0])
    if match is None:
        raise SystemExit(f"invalid {label} in {path}")
    return match.group(1)


def reject_unsafe_python_namespace_mutation(
    module: ast.Module,
    path: str,
    name: str,
    label: str,
) -> None:
    """Reject bounded dynamic surfaces that can obscure a module authority."""
    for node in ast.walk(module):
        unsafe = (
            isinstance(node, ast.Name)
            and node.id in UNSAFE_PYTHON_NAMESPACE_NAMES
        ) or (
            isinstance(node, ast.Import)
            and any(alias.name == "builtins" for alias in node.names)
        ) or (
            isinstance(node, ast.ImportFrom) and node.module == "builtins"
        ) or (
            isinstance(node, ast.Attribute)
            and (
                node.attr == "__dict__"
                or (
                    node.attr == name
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                )
                or (
                    node.attr in UNSAFE_PYTHON_NAMESPACE_NAMES - {"compile"}
                )
                or (
                    node.attr == "compile"
                    and not (
                        isinstance(node.value, ast.Name) and node.value.id == "re"
                    )
                )
            )
        )
        if unsafe:
            line_number = getattr(node, "lineno", "unknown")
            raise SystemExit(
                f"unsafe {label} namespace mutation surface in {path}:{line_number}"
            )


def python_string_assignment(path: str, name: str, label: str) -> str:
    try:
        module = ast.parse(text(path), filename=path)
    except SyntaxError as error:
        raise SystemExit(f"invalid Python in {path}: {error.msg}") from error
    reject_unsafe_python_namespace_mutation(module, path, name, label)
    direct_assignments = [
        statement
        for statement in module.body
        if isinstance(statement, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Name) and target.id == name
            for target in (
                statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            )
        )
    ]
    bindings = []
    pending_code = [(compile(module, path, "exec"), True)]
    while pending_code:
        code, is_module = pending_code.pop()
        binding_operations = {"STORE_GLOBAL", "DELETE_GLOBAL"}
        if is_module:
            binding_operations.update({"STORE_NAME", "DELETE_NAME"})
        bindings.extend(
            instruction
            for instruction in dis.get_instructions(code)
            if instruction.opname in binding_operations and instruction.argval == name
        )
        pending_code.extend(
            (constant, False)
            for constant in code.co_consts
            if isinstance(constant, types.CodeType)
        )
    if not bindings:
        raise SystemExit(f"missing {label} in {path}")
    if len(bindings) != 1 or len(direct_assignments) != 1:
        raise SystemExit(f"duplicate {label} in {path}")
    value = direct_assignments[0].value
    if not isinstance(value, ast.Constant) or type(value.value) is not str:
        raise SystemExit(f"invalid {label} in {path}")
    return value.value


def reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def dependency_tables(manifest: dict, manifest_label: str):
    for table_name in DEPENDENCY_TABLES:
        table = manifest.get(table_name, {})
        if type(table) is not dict:
            raise SystemExit(f"invalid {manifest_label} {table_name} table")
        yield table_name, table

    targets = manifest.get("target", {})
    if type(targets) is not dict:
        raise SystemExit(f"invalid {manifest_label} target table")
    for target_name, target in targets.items():
        if type(target) is not dict:
            raise SystemExit(f"invalid {manifest_label} target {target_name!r}")
        for table_name in DEPENDENCY_TABLES:
            table = target.get(table_name, {})
            if type(table) is not dict:
                raise SystemExit(
                    f"invalid {manifest_label} target.{target_name}.{table_name} table"
                )
            yield f"target.{target_name}.{table_name}", table


def dependency_version(
    dependency_name: str,
    specification: object,
    context: str,
    workspace_versions: dict[str, str],
) -> tuple[str, str] | None:
    package_name = dependency_name
    if type(specification) is dict and "package" in specification:
        package_name = specification["package"]
        if type(package_name) is not str:
            raise SystemExit(f"invalid package name for dependency {context}")
    package_name = package_name.replace("_", "-")
    if not package_name.startswith("skynet-edr-"):
        return None

    if type(specification) is str:
        return package_name, specification
    if type(specification) is not dict:
        raise SystemExit(f"invalid internal dependency declaration: {context}")

    if specification.get("workspace") is True:
        if "version" in specification:
            raise SystemExit(f"ambiguous workspace dependency declaration: {context}")
        try:
            return package_name, workspace_versions[dependency_name]
        except KeyError as error:
            raise SystemExit(
                f"missing workspace version for internal dependency: {context}"
            ) from error

    version = specification.get("version")
    if type(version) is not str:
        raise SystemExit(f"missing version for internal dependency: {context}")
    return package_name, version


def manifest_package_version(
    package: dict,
    workspace_version: str,
    context: str,
) -> str:
    version = package.get("version")
    if type(version) is str:
        return version
    if type(version) is dict and version == {"workspace": True}:
        return workspace_version
    raise SystemExit(f"invalid package version declaration: {context}")


def resolved_manifest_path(root: Path, candidate: Path, context: str) -> Path:
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise SystemExit(f"Cargo manifest escapes repository: {context}") from error
    if not resolved.is_file() or resolved.name != "Cargo.toml":
        raise SystemExit(f"invalid Cargo manifest path: {context}")
    return resolved


def local_dependency_manifest(
    root: Path,
    manifest_path: Path,
    dependency_name: str,
    specification: object,
    context: str,
) -> Path | None:
    if type(specification) is not dict or "path" not in specification:
        return None
    dependency_path = specification["path"]
    if type(dependency_path) is not str or not dependency_path:
        raise SystemExit(f"invalid local dependency path: {context}")
    return resolved_manifest_path(
        root,
        manifest_path.parent / dependency_path / "Cargo.toml",
        f"{context} ({dependency_name})",
    )


def workspace_manifests(root: Path, cargo: dict) -> list[tuple[Path, dict]]:
    root_manifest = resolved_manifest_path(root, root / "Cargo.toml", "workspace root")
    members = cargo["workspace"].get("members", [])
    if type(members) is not list or not members:
        raise SystemExit("workspace members must be a non-empty list")

    pending = [root_manifest]
    for member in members:
        if type(member) is not str:
            raise SystemExit(f"unsupported workspace member path: {member!r}")
        member_path = Path(member)
        if (
            member_path.is_absolute()
            or ".." in member_path.parts
            or any(character in member for character in "*?[")
        ):
            raise SystemExit(f"unsupported workspace member path: {member!r}")
        pending.append(
            resolved_manifest_path(
                root,
                root / member_path / "Cargo.toml",
                f"workspace member {member!r}",
            )
        )

    manifests: list[tuple[Path, dict]] = []
    seen: set[Path] = set()
    while pending:
        manifest_path = pending.pop()
        if manifest_path in seen:
            continue
        seen.add(manifest_path)
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        manifests.append((manifest_path, manifest))

        package = manifest.get("package")
        if package is not None:
            if type(package) is not dict or type(package.get("name")) is not str:
                raise SystemExit(f"invalid package table in {manifest_path}")
            for table_name, table in dependency_tables(manifest, str(manifest_path)):
                for dependency_name, specification in table.items():
                    dependency_manifest = local_dependency_manifest(
                        root,
                        manifest_path,
                        dependency_name,
                        specification,
                        f"{package['name']} {table_name}",
                    )
                    if dependency_manifest is not None:
                        pending.append(dependency_manifest)

        if manifest_path == root_manifest:
            workspace_dependencies = cargo["workspace"].get("dependencies", {})
            if type(workspace_dependencies) is not dict:
                raise SystemExit("invalid workspace dependencies table")
            for dependency_name, specification in workspace_dependencies.items():
                dependency_manifest = local_dependency_manifest(
                    root,
                    manifest_path,
                    dependency_name,
                    specification,
                    "workspace.dependencies",
                )
                if dependency_manifest is not None:
                    pending.append(dependency_manifest)

    return manifests


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-product", help="canonical product SemVer required by the release tag")
    parser.add_argument("--expected-deb", help="exact native Debian package version")
    args = parser.parse_args()

    root_manifest = resolved_manifest_path(ROOT, ROOT / "Cargo.toml", "workspace root")
    cargo = tomllib.loads(root_manifest.read_text(encoding="utf-8"))
    workspace_version = cargo["workspace"]["package"]["version"]
    expected = workspace_version if args.expected_product is None else args.expected_product
    if not is_canonical_release_version(expected):
        raise SystemExit(f"invalid release version: {expected!r}")
    deb_default = require_unique_yaml_scalar(
        "packaging/nfpm.yaml",
        r"\$\{SKYNET_EDR_DEB_VERSION:-([^}]+)\}",
        "nFPM DEB default version",
    )
    expected_deb = deb_default if args.expected_deb is None else args.expected_deb
    if type(expected_deb) is not str or expected_deb != native_package_version(expected):
        raise SystemExit(f"invalid Debian package version: {expected_deb!r}")

    observed = {
        "Cargo.toml workspace": workspace_version,

        "Hermes plugin Python": python_string_assignment(
            "integrations/hermes/skynet-edr/__init__.py",
            "PLUGIN_VERSION",
            "Hermes plugin version",
        ),
        "Hermes enrollment payload": python_string_assignment(
            "packaging/scripts/skynet-edr-hermes-enroll.py",
            "PAYLOAD_VERSION",
            "Hermes enrollment payload version",
        ),
        "Hermes plugin manifest": require_unique_yaml_scalar(
            "integrations/hermes/skynet-edr/plugin.yaml",
            r'"([^"]+)"',
            "Hermes plugin manifest version",
        ),
        "dashboard manifest": json.loads(
            text("integrations/hermes/skynet-edr/dashboard/manifest.json"),
            object_pairs_hook=reject_duplicate_json_keys,
        )["version"],
    }

    workspace_versions: dict[str, str] = {}
    workspace_dependencies = cargo["workspace"].get("dependencies", {})
    if type(workspace_dependencies) is not dict:
        raise SystemExit("invalid workspace dependencies table")
    for dependency_name, specification in workspace_dependencies.items():
        resolved = dependency_version(
            dependency_name,
            specification,
            f"workspace.dependencies {dependency_name}",
            {},
        )
        if resolved is not None:
            package_name, version = resolved
            workspace_versions[dependency_name] = version
            label = f"workspace.dependencies {dependency_name}"
            if package_name != dependency_name:
                label = f"{label} package {package_name}"
            observed[label] = version

    seen_crates: set[str] = set()
    internal_manifest_crates: set[str] = set()
    for manifest_path, manifest in workspace_manifests(ROOT, cargo):
        package = manifest.get("package")
        if package is None:
            continue
        crate = package["name"].replace("_", "-")
        if crate in seen_crates:
            raise SystemExit(f"duplicate workspace package name: {crate}")
        seen_crates.add(crate)
        if crate.startswith("skynet-edr-"):
            internal_manifest_crates.add(crate)
            observed[f"{crate} package version"] = manifest_package_version(
                package,
                workspace_version,
                str(manifest_path),
            )
        for table_name, table in dependency_tables(manifest, str(manifest_path)):
            for dependency_name, specification in table.items():
                context = f"{crate} {table_name} {dependency_name}"
                resolved = dependency_version(
                    dependency_name,
                    specification,
                    context,
                    workspace_versions,
                )
                if resolved is not None:
                    package_name, version = resolved
                    label = context
                    if package_name != dependency_name:
                        label = f"{label} package {package_name}"
                    observed[label] = version

    lock = tomllib.loads(text("Cargo.lock"))
    internal_lock_entries: dict[str, list[str]] = {}
    for index, package in enumerate(lock["package"]):
        package_name = package["name"].replace("_", "-")
        if package_name.startswith("skynet-edr-"):
            version = package["version"]
            if type(version) is not str:
                raise SystemExit(f"invalid Cargo.lock version for {package_name}")
            internal_lock_entries.setdefault(package_name, []).append(version)
            observed[f"Cargo.lock {package_name} entry {index}"] = version

    duplicate_lock_entries = sorted(
        name for name, versions in internal_lock_entries.items() if len(versions) != 1
    )
    if duplicate_lock_entries:
        raise SystemExit(
            "duplicate internal Cargo.lock entries: " + ", ".join(duplicate_lock_entries)
        )
    missing_lock_entries = sorted(internal_manifest_crates - internal_lock_entries.keys())
    if missing_lock_entries:
        raise SystemExit(
            "internal packages missing from Cargo.lock: " + ", ".join(missing_lock_entries)
        )
    unexpected_lock_entries = sorted(
        internal_lock_entries.keys() - internal_manifest_crates
    )
    if unexpected_lock_entries:
        raise SystemExit(
            "unexpected internal packages in Cargo.lock: "
            + ", ".join(unexpected_lock_entries)
        )

    mismatches = {
        label: version for label, version in observed.items() if version != expected
    }
    if mismatches:
        details = ", ".join(
            f"{label}={version}" for label, version in sorted(mismatches.items())
        )
        raise SystemExit(f"release version mismatch; expected {expected}: {details}")
    if deb_default != expected_deb:
        raise SystemExit(
            f"Debian package version mismatch; expected {expected_deb}: nFPM DEB default={deb_default}"
        )

    release_note = ROOT / "docs" / "releases" / f"v{expected}.md"
    if not release_note.is_file():
        raise SystemExit(f"missing reviewed release notes: {release_note.relative_to(ROOT)}")

    required_docs = {
        "README.md": (f"docs/releases/v{expected}.md",),
        "docs/ROADMAP.md": (f"Current milestone: v{expected}",),
        "docs/INSTALL.md": (
            f"skynet-edr_{expected}_amd64.deb",
            f"DEB and RPM report `{expected_deb}`",
            f"Arch reports `{expected.replace('-', '.', 1)}-1`",
        ),
        "docs/HERMES_ENROLLMENT.md": (
            f"Skynet-EDR plugin `{expected}`",
        ),
        "CHANGELOG.md": (f"## {expected} -",),
    }
    for path, markers in required_docs.items():
        document = text(path)
        if any(marker not in document for marker in markers):
            raise SystemExit(f"{path} does not reference current release {expected}")

    require_current_release_kind(expected)

    stale_current_state_claims = {
        "docs/HERMES_EVENT_INGESTION.md": (
            "live v0.4 integrations should emit `skynet.event.v0` events directly where possible.",
            "Ingestion is offline/read-only: it parses trace files and does not intercept live agent execution.",
            "Canonical live JSONL spool ingestion:",
            "Daemon startup can poll the same canonical spool when `[spool]` is enabled in the daemon config:",
            "The current end-to-end MVP has two built-in correlation rules:",
        ),
    }
    for path, stale_claims in stale_current_state_claims.items():
        document = text(path)
        if any(stale_claim in document for stale_claim in stale_claims):
            raise SystemExit(f"{path} contains a stale current-state claim")

    release_description = (
        "prerelease" if "-" in expected else "stable SemVer evaluation release"
    )
    release_table_kind = "prerelease" if "-" in expected else "stable SemVer"
    authoritative_doc_versions = {
        "SECURITY.md": (
            rf"^Skynet-EDR v({CANONICAL_RELEASE_VERSION_PATTERN}) is an installable {re.escape(release_description)}",
            rf"^\| `v({CANONICAL_RELEASE_VERSION_PATTERN})` {re.escape(release_table_kind)} \|",
        ),
        "docs/README.md": (
            rf"^Current documentation structure target: v({CANONICAL_RELEASE_VERSION_PATTERN})\.",
        ),
        "docs/ARCHITECTURE.md": (
            rf"ships in v({CANONICAL_RELEASE_VERSION_PATTERN})\.",
        ),
        "docs/CONCEPTS.md": (
            rf"^## Current v({CANONICAL_RELEASE_VERSION_PATTERN}) scope$",
        ),
        "docs/HERMES_PLUGIN_TELEMETRY.md": (
            rf"^Skynet-EDR v({CANONICAL_RELEASE_VERSION_PATTERN}) ships",
        ),
        "docs/HERMES_EVENT_INGESTION.md": (
            rf"^For v({CANONICAL_RELEASE_VERSION_PATTERN}), the supported ingestion paths are distinct:",
        ),
        "docs/INTEGRATIONS.md": (
            rf"^This page is the v({CANONICAL_RELEASE_VERSION_PATTERN}) integration index\.",
            rf"^\| Hermes plugin telemetry \| v({CANONICAL_RELEASE_VERSION_PATTERN}) live passive path \|",
        ),
        "docs/OPERATIONS.md": (
            rf"^This page is the v({CANONICAL_RELEASE_VERSION_PATTERN}) operator index ",
        ),
        "integrations/hermes/skynet-edr/README.md": (
            rf"^Passive Hermes Agent telemetry plugin for Skynet-EDR v({CANONICAL_RELEASE_VERSION_PATTERN})\.$",
            rf"^  v({CANONICAL_RELEASE_VERSION_PATTERN}) performs a bounded wait for its ordered terminal outcome\.$",
        ),
    }
    for path, patterns in authoritative_doc_versions.items():
        document = text(path)
        if any(re.findall(pattern, document, flags=re.MULTILINE) != [expected] for pattern in patterns):
            raise SystemExit(f"{path} does not reference current release {expected}")

    print(f"release version consistency passed: product={expected} deb={expected_deb}")


if __name__ == "__main__":
    main()
