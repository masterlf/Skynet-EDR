#!/usr/bin/env python3
"""Deterministic, offline threat-validation runner and contract checker."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json"
DEFAULT_MATRIX = ROOT / "docs/coverage/v0.6.0-beta.1.json"
DEFAULT_PUBLIC_MATRIX = ROOT / "docs/PROTECTION_MATRIX_v0.6.0-beta.1.md"
DEFAULT_OUTPUT = ROOT / "target/threat-validation/evidence.json"
MAX_MANIFEST_BYTES = 512 * 1024
MAX_MATRIX_BYTES = 128 * 1024
CATEGORIES = {"malicious", "benign", "hostile-malformed"}
OUTCOMES = {"detected", "not_detected", "rejected", "skipped"}
EXECUTIONS = {"replay", "hostile-parse", "skipped"}
MATRIX_STATUSES = {"DETECTED_AND_TESTED", "PARTIAL", "NOT_TESTED", "NOT_COVERED"}
TOP_LEVEL_FIELDS = {"cases", "compatibility", "corpus_notice", "live_rules", "schema_version", "suite_version"}
CASE_FIELDS = {
    "case_id", "category", "compatibility", "engine", "events", "evidence_strength",
    "execution", "expected_incident_count", "expected_match", "expected_outcome",
    "expected_severity", "forbidden_markers", "hostile_payload", "limitations",
    "producer_calls", "producer_path", "rule_id", "safe_synthetic",
}
MATRIX_FIELDS = {"boundary", "matrix_version", "rules", "schema_version"}
MATRIX_RULE_FIELDS = {"evidence", "id", "limitation", "scenario_ids", "status"}


class ContractError(ValueError):
    pass


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path, ceiling: int, label: str):
    try:
        size = path.stat().st_size
        if size > ceiling:
            raise ContractError(f"{label} exceeds byte ceiling")
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ContractError(f"invalid {label}: {error}") from error


def write_evidence(path: Path, evidence: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ContractError("evidence output must not be a symlink")
    payload = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as temporary:
            temporary_name = temporary.name
            os.fchmod(temporary.fileno(), 0o600)
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def exact_fields(value, allowed, label):
    if type(value) is not dict:
        raise ContractError(f"{label} must be an object")
    unknown = set(value) - allowed
    if unknown:
        raise ContractError(f"{label} has unknown fields: {', '.join(sorted(unknown))}")


def validate_manifest(path: Path):
    manifest = load_json(path, MAX_MANIFEST_BYTES, "manifest")
    exact_fields(manifest, TOP_LEVEL_FIELDS, "manifest")
    if set(manifest) != TOP_LEVEL_FIELDS:
        raise ContractError("manifest has missing top-level fields")
    if manifest.get("schema_version") != "skynet.threat-validation-manifest.v1":
        raise ContractError("unsupported manifest schema_version")
    if manifest.get("suite_version") != "0.6.0-beta.1":
        raise ContractError("unsupported suite_version")
    live_rules = manifest.get("live_rules")
    if type(live_rules) is not dict or not live_rules or not all(
        type(rule_id) is str and rule_id and severity in {"high", "critical"}
        for rule_id, severity in live_rules.items()
    ):
        raise ContractError("live_rules must be a non-empty rule severity object")
    cases = manifest.get("cases")
    if type(cases) is not list or not cases or len(cases) > 128:
        raise ContractError("cases must be a non-empty bounded array")
    ids = set()
    for index, case in enumerate(cases):
        label = f"case[{index}]"
        exact_fields(case, CASE_FIELDS, label)
        missing = CASE_FIELDS - {"hostile_payload"} - set(case)
        if missing:
            raise ContractError(f"{label} missing fields: {', '.join(sorted(missing))}")
        scenario_id = case["case_id"]
        if type(scenario_id) is not str or not scenario_id or scenario_id in ids:
            raise ContractError(f"invalid or duplicate case_id: {scenario_id!r}")
        ids.add(scenario_id)
        if case["category"] not in CATEGORIES:
            raise ContractError(f"{scenario_id}: unknown category")
        if case["expected_outcome"] not in OUTCOMES:
            raise ContractError(f"{scenario_id}: unknown expected_outcome")
        if case["execution"] not in EXECUTIONS:
            raise ContractError(f"{scenario_id}: unknown execution")
        if case["safe_synthetic"] is not True:
            raise ContractError(f"{scenario_id}: safe_synthetic must be true")
        if not all(type(case[field]) is str and case[field] for field in ("engine", "producer_path", "evidence_strength")):
            raise ContractError(f"{scenario_id}: invalid engine/producer/evidence metadata")
        if type(case["limitations"]) is not list or not case["limitations"] or not all(type(item) is str and item for item in case["limitations"]):
            raise ContractError(f"{scenario_id}: limitations must be non-empty strings")
        if case["execution"] == "skipped" and case["expected_outcome"] != "skipped":
            raise ContractError(f"{scenario_id}: skipped execution must expect skipped")
        if case["category"] == "hostile-malformed" and "hostile_payload" not in case:
            raise ContractError(f"{scenario_id}: hostile scenario lacks payload")
        if (
            type(case["expected_match"]) is not bool
            or type(case["expected_incident_count"]) is not int
        ):
            raise ContractError(f"{scenario_id}: incoherent expectation types")
        expected_tuple = (
            case["execution"], case["expected_outcome"],
            case["expected_match"], case["expected_incident_count"],
        )
        coherent_tuples = {
            "malicious": {("replay", "detected", True, 1)},
            "benign": {
                ("replay", "not_detected", False, 0),
                ("skipped", "skipped", False, 0),
            },
            "hostile-malformed": {("hostile-parse", "rejected", False, 0)},
        }
        if expected_tuple not in coherent_tuples[case["category"]]:
            raise ContractError(f"{scenario_id}: incoherent category/expectation tuple")
        expected_severity = case["expected_severity"]
        if case["category"] == "malicious":
            rule_id = case["rule_id"]
            if rule_id not in live_rules or expected_severity != live_rules[rule_id]:
                raise ContractError(f"{scenario_id}: incoherent malicious rule/severity")
        elif expected_severity is not None:
            raise ContractError(f"{scenario_id}: incoherent non-malicious severity")
        if case["execution"] == "replay" and (
            type(case["events"]) is not list or not case["events"]
            or type(case["producer_calls"]) is not list or not case["producer_calls"]
        ):
            raise ContractError(f"{scenario_id}: replay scenario lacks executable evidence")
    return manifest, ids


def validate_matrix(path: Path, manifest, scenario_ids):
    matrix = load_json(path, MAX_MATRIX_BYTES, "matrix")
    exact_fields(matrix, MATRIX_FIELDS, "matrix")
    if matrix.get("schema_version") != "skynet.protection-matrix.v1":
        raise ContractError("unsupported matrix schema_version")
    if matrix.get("matrix_version") != manifest["suite_version"]:
        raise ContractError("matrix/manifest version drift")
    if "No prevention" not in matrix.get("boundary", ""):
        raise ContractError("matrix must state passive/no-prevention boundary")
    rules = matrix.get("rules")
    if type(rules) is not list or not rules:
        raise ContractError("matrix rules must be a non-empty array")
    seen_rules = set()
    status_by_rule = {}
    links_by_rule = {}
    for index, rule in enumerate(rules):
        exact_fields(rule, MATRIX_RULE_FIELDS, f"matrix rule[{index}]")
        if set(rule) != MATRIX_RULE_FIELDS:
            raise ContractError(f"matrix rule[{index}] has missing fields")
        if rule["id"] in seen_rules:
            raise ContractError(f"duplicate matrix rule id: {rule['id']}")
        seen_rules.add(rule["id"])
        if rule["status"] not in MATRIX_STATUSES:
            raise ContractError(f"unknown matrix status: {rule['status']}")
        if type(rule["scenario_ids"]) is not list:
            raise ContractError("matrix scenario_ids must be an array")
        unknown = set(rule["scenario_ids"]) - scenario_ids
        if unknown:
            raise ContractError(f"matrix references unknown scenarios: {', '.join(sorted(unknown))}")
        status_by_rule[rule["id"]] = rule["status"]
        links_by_rule[rule["id"]] = set(rule["scenario_ids"])
    expected_by_rule = {}
    authoritative_by_rule = {}
    for case in manifest["cases"]:
        matrix_id = case["rule_id"]
        if matrix_id is None and case["category"] == "hostile-malformed":
            matrix_id = "HOSTILE-MALFORMED"
        if type(matrix_id) is not str or not matrix_id:
            raise ContractError(f"scenario lacks matrix attribution: {case['case_id']}")
        expected_by_rule.setdefault(matrix_id, set()).add(case["case_id"])
        if case["execution"] != "skipped" and case["expected_outcome"] in {"detected", "rejected"}:
            authoritative_by_rule.setdefault(matrix_id, set()).add(case["case_id"])
    for rule_id in set(expected_by_rule) | set(links_by_rule):
        if links_by_rule.get(rule_id, set()) != expected_by_rule.get(rule_id, set()):
            raise ContractError(f"matrix scenario attribution drift: {rule_id}")
    for rule_id, status in status_by_rule.items():
        if status == "DETECTED_AND_TESTED" and not authoritative_by_rule.get(rule_id):
            raise ContractError(
                f"DETECTED_AND_TESTED rule lacks authoritative executed scenario evidence: {rule_id}"
            )
    for rule_id in manifest["live_rules"]:
        if status_by_rule.get(rule_id) != "DETECTED_AND_TESTED":
            raise ContractError(f"live rule matrix drift: {rule_id}")
    for case in manifest["cases"]:
        if case["execution"] == "skipped" and status_by_rule.get(case["rule_id"]) != "NOT_COVERED":
            raise ContractError(f"skipped scenario matrix drift: {case['case_id']}")
    return matrix


def render_public_matrix(matrix: dict) -> str:
    manifest_link = "../crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json"
    lines = [
        f"# Skynet-EDR v{matrix['matrix_version']} protection matrix",
        "",
        "Generated from `docs/coverage/v0.6.0-beta.1.json`; direct edits fail the suite contract check.",
        "",
        matrix["boundary"],
        "",
        "| Surface | Status | Scenario evidence | Evidence | Limitation |",
        "|---|---|---|---|---|",
    ]
    for rule in matrix["rules"]:
        scenarios = ", ".join(
            f"[`{scenario_id}`]({manifest_link})" for scenario_id in rule["scenario_ids"]
        ) or "—"
        cells = [rule["id"], rule["status"], scenarios, rule["evidence"], rule["limitation"]]
        lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
    lines.extend([
        "",
        "`DETECTED_AND_TESTED` is bounded fixture evidence, not a universal security guarantee. "
        "`PARTIAL`, `NOT_TESTED`, and `NOT_COVERED` must not be presented as shipped protection.",
        "",
        "Generate deterministic evidence with `python3 packaging/scripts/threat-validation.py`; "
        "the default output is `target/threat-validation/evidence.json`.",
        "",
    ])
    return "\n".join(lines)


def validate_public_matrix(path: Path, matrix: dict) -> None:
    try:
        if path.stat().st_size > MAX_MATRIX_BYTES:
            raise ContractError("public matrix exceeds byte ceiling")
        document = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ContractError(f"invalid public matrix: {error}") from error
    if document != render_public_matrix(matrix):
        raise ContractError("public protection matrix drift")


def run_check(name, command):
    env = os.environ.copy()
    env.update({"CARGO_NET_OFFLINE": "true", "PYTHONDONTWRITEBYTECODE": "1"})
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
    if result.returncode:
        diagnostic = (result.stdout + "\n" + result.stderr)[-4000:]
        print(f"{name} failed:\n{diagnostic}", file=sys.stderr)
    return {"name": name, "status": "pass" if result.returncode == 0 else "fail", "exit_code": result.returncode}


def evidence_document(
    manifest_path, matrix_path, public_matrix_path, manifest, selected, mode, checks
):
    check_failed = any(check["status"] == "fail" for check in checks)
    results = []
    for case in sorted(selected, key=lambda item: item["case_id"]):
        if mode == "validate-only":
            status = "not_tested"
        elif check_failed:
            status = "failed" if case["execution"] != "skipped" else "skipped"
        elif case["execution"] == "skipped":
            status = "skipped"
        else:
            status = "passed"
        results.append({
            "category": case["category"], "engine": case["engine"],
            "expected_outcome": case["expected_outcome"], "producer_path": case["producer_path"],
            "rule_id": case["rule_id"], "scenario_id": case["case_id"], "status": status,
        })
    if mode == "validate-only":
        status = "not_tested"
    elif check_failed:
        status = "fail"
    else:
        status = "pass"
    return {
        "checks": checks,
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "matrix_sha256": hashlib.sha256(matrix_path.read_bytes()).hexdigest(),
        "mode": mode,
        "public_matrix_sha256": hashlib.sha256(public_matrix_path.read_bytes()).hexdigest(),
        "results": results,
        "schema_version": "skynet.threat-validation-evidence.v1",
        "status": status,
        "suite_version": manifest["suite_version"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--public-matrix", type=Path, default=DEFAULT_PUBLIC_MATRIX)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--scenario", action="append", default=[])
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    try:
        if not args.validate_only and args.manifest.absolute() != DEFAULT_MANIFEST.absolute():
            raise ContractError("custom manifest requires --validate-only")
        if not args.validate_only and args.matrix.absolute() != DEFAULT_MATRIX.absolute():
            raise ContractError("custom matrix requires --validate-only")
        if not args.validate_only and args.public_matrix.absolute() != DEFAULT_PUBLIC_MATRIX.absolute():
            raise ContractError("custom public matrix requires --validate-only")
        manifest, scenario_ids = validate_manifest(args.manifest)
        matrix = validate_matrix(args.matrix, manifest, scenario_ids)
        validate_public_matrix(args.public_matrix, matrix)
        unknown = set(args.scenario) - scenario_ids
        if unknown:
            raise ContractError(f"unknown scenario: {', '.join(sorted(unknown))}")
        selected = [case for case in manifest["cases"] if not args.scenario or case["case_id"] in args.scenario]
        checks = []
        mode = "validate-only" if args.validate_only else "executed"
        if not args.validate_only:
            checks.append(run_check("engine-corpus", ["cargo", "test", "-p", "skynet-edr-core", "--test", "detection_corpus", "--all-features", "--offline"]))
            checks.append(run_check("producer-corpus", ["python3", "-m", "unittest", "integrations/hermes/tests/test_detection_corpus.py"]))
        evidence = evidence_document(
            args.manifest, args.matrix, args.public_matrix, manifest, selected, mode, checks
        )
        write_evidence(args.output, evidence)
        counts = {status: sum(result["status"] == status for result in evidence["results"]) for status in ("passed", "failed", "skipped", "not_tested")}
        print(f"Threat Validation Suite {manifest['suite_version']}: {evidence['status'].upper()} " + " ".join(f"{key.upper()}={value}" for key, value in counts.items() if value))
        return 0 if evidence["status"] in {"pass", "not_tested"} else 1
    except ContractError as error:
        print(f"threat validation contract error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
