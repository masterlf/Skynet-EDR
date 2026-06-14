//! Documentation safety gates for Linux lab and privileged sensor workflows.
//!
//! Phase 9 is intentionally manual until Frederic provides disposable VM details.
//! These tests prevent the lab plan from drifting into real credentials, automatic
//! destructive execution, or unbounded network egress.

use std::fs;

const LAB_DOC: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/LINUX_LAB_TESTING.md"
);

#[test]
fn linux_lab_plan_is_manual_disposable_and_non_production() {
    let doc = fs::read_to_string(LAB_DOC).expect("Linux lab test plan exists");
    let lower = doc.to_ascii_lowercase();

    for required in [
        "manual workflow only",
        "disposable vm",
        "non-production",
        "frederic-provided vm details",
        "no automatic privileged sensor execution",
    ] {
        assert!(
            lower.contains(required),
            "lab plan must contain safety marker: {required}"
        );
    }
}

#[test]
fn linux_lab_plan_uses_fake_honeytokens_and_controlled_sink() {
    let doc = fs::read_to_string(LAB_DOC).expect("Linux lab test plan exists");
    let lower = doc.to_ascii_lowercase();

    for required in [
        "fake honeytokens only",
        "skynet-edr-fake-token",
        "controlled sink",
        "127.0.0.1",
        "no real secrets",
    ] {
        assert!(
            lower.contains(required),
            "lab plan must contain containment marker: {required}"
        );
    }
}

#[test]
fn linux_lab_plan_blocks_until_vm_details_are_known() {
    let doc = fs::read_to_string(LAB_DOC).expect("Linux lab test plan exists");
    let lower = doc.to_ascii_lowercase();

    for required in [
        "blocked inputs",
        "os distribution and version",
        "root or sudo availability",
        "snapshot or rollback mechanism",
        "egress policy",
    ] {
        assert!(
            lower.contains(required),
            "lab plan must list VM input: {required}"
        );
    }
}
