//! Daemon smoke tests for the passive, non-privileged skeleton.

use std::process::Command;

#[test]
fn daemon_status_is_passive_and_non_privileged() {
    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr-daemon"))
        .arg("status")
        .output()
        .expect("skynet-edr-daemon binary should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("Skynet-EDR daemon status"));
    assert!(stdout.contains("mode=passive"));
    assert!(stdout.contains("sensors=not-started"));
}

#[test]
fn daemon_prints_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr-daemon"))
        .arg("--help")
        .output()
        .expect("skynet-edr-daemon binary should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("status"));
}
