//! Daemon smoke tests for the passive, non-privileged skeleton.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn daemon() -> Command {
    Command::new(env!("CARGO_BIN_EXE_skynet-edr-daemon"))
}

fn temp_config_dir(test_name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "skynet-edr-daemon-{test_name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("temporary config directory should be created");
    path
}

fn write_config(dir: &Path, content: &str) -> PathBuf {
    let path = dir.join("config.toml");
    fs::write(&path, content).expect("config fixture should be written");
    path
}

#[test]
fn daemon_status_is_passive_and_non_privileged() {
    let output = daemon()
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
fn daemon_prints_help_with_run_command() {
    let output = daemon()
        .arg("--help")
        .output()
        .expect("skynet-edr-daemon binary should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("status"));
    assert!(stdout.contains("run --config <path>"));
}

#[test]
fn daemon_run_starts_passive_service_path_without_privileged_sensors() {
    let dir = temp_config_dir("run-starts-passive");
    let config = write_config(
        &dir,
        r#"
mode = "passive"
data_dir = "/var/lib/skynet-edr"
log_dir = "/var/log/skynet-edr"

[http_api]
enabled = true
bind = "127.0.0.1:8787"
read_only = true

[sensors]
linux_privileged = false
"#,
    );

    let output = daemon()
        .arg("run")
        .arg("--config")
        .arg(config)
        .env("SKYNET_EDR_DAEMON_EXIT_AFTER_STARTUP", "1")
        .output()
        .expect("skynet-edr-daemon binary should run");

    assert!(
        output.status.success(),
        "run should succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("daemon run: mode=passive"));
    assert!(stdout.contains("http_api=127.0.0.1:8787"));
    assert!(stdout.contains("sensors=not-started"));
    assert!(stdout.contains("privileged_sensors=disabled"));
}

#[test]
fn daemon_run_accepts_packaged_baseline_config() {
    let config = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging/config/config.toml")
        .canonicalize()
        .expect("packaged baseline config should exist");

    let output = daemon()
        .arg("run")
        .arg("--config")
        .arg(config)
        .env("SKYNET_EDR_DAEMON_EXIT_AFTER_STARTUP", "1")
        .output()
        .expect("skynet-edr-daemon binary should run");

    assert!(
        output.status.success(),
        "packaged config should be accepted: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn daemon_run_requires_config_path() {
    let output = daemon()
        .arg("run")
        .output()
        .expect("skynet-edr-daemon binary should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("run requires --config <path>"));
}

#[test]
fn daemon_run_rejects_missing_config_file() {
    let output = daemon()
        .arg("run")
        .arg("--config")
        .arg("/definitely/missing/skynet-edr/config.toml")
        .output()
        .expect("skynet-edr-daemon binary should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("failed to read daemon config"));
}

#[test]
fn daemon_run_rejects_privileged_sensor_config() {
    let dir = temp_config_dir("rejects-privileged");
    let config = write_config(
        &dir,
        r#"
mode = "passive"

[http_api]
enabled = true
bind = "127.0.0.1:8787"
read_only = true

[sensors]
linux_privileged = true
"#,
    );

    let output = daemon()
        .arg("run")
        .arg("--config")
        .arg(config)
        .output()
        .expect("skynet-edr-daemon binary should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("privileged Linux sensors are not supported"));
}

#[test]
fn daemon_run_rejects_non_loopback_or_mutating_api_config() {
    let dir = temp_config_dir("rejects-api");
    let config = write_config(
        &dir,
        r#"
mode = "passive"

[http_api]
enabled = true
bind = "0.0.0.0:8787"
read_only = false

[sensors]
linux_privileged = false
"#,
    );

    let output = daemon()
        .arg("run")
        .arg("--config")
        .arg(config)
        .output()
        .expect("skynet-edr-daemon binary should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("HTTP API bind address must be loopback"));
    assert!(stderr.contains("HTTP API must remain read-only"));
}
