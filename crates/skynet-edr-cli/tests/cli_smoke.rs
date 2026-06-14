use std::process::Command;

#[test]
fn cli_status_reports_product_and_default_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .arg("status")
        .output()
        .expect("skynet-edr binary should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("Skynet-EDR"));
    assert!(stdout.contains("mode=passive"));
}

#[test]
fn cli_defaults_to_status_when_no_command_is_supplied() {
    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .output()
        .expect("skynet-edr binary should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("mode=passive"));
}

#[test]
fn cli_prints_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .arg("--help")
        .output()
        .expect("skynet-edr binary should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("status"));
}

#[test]
fn cli_prints_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .arg("--version")
        .output()
        .expect("skynet-edr binary should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.starts_with("skynet-edr "));
}

#[test]
fn cli_rejects_unknown_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .arg("definitely-not-a-command")
        .output()
        .expect("skynet-edr binary should run");

    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("unknown command"));
}

#[test]
fn cli_rejects_trailing_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["status", "unexpected"])
        .output()
        .expect("skynet-edr binary should run");

    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("unexpected argument"));
}
