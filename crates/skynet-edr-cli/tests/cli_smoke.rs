//! CLI smoke tests for the initial operator-facing command surface.

use std::{fs, net::TcpListener, path::PathBuf, process::Command};

fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "skynet-edr-doctor-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    ));
    path
}

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

#[test]
fn cli_help_lists_doctor() {
    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .arg("--help")
        .output()
        .expect("skynet-edr binary should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("doctor"));
}

#[test]
fn doctor_accepts_packaged_config_store_and_loopback_api_without_rules_or_agents_dirs() {
    let root = temp_path("ready");
    let config_path = root.join("etc/skynet-edr/config.toml");
    let db_path = root.join("var/lib/skynet-edr/skynet-edr.sqlite");
    let spool_path = root.join("var/lib/skynet-edr/events.jsonl");
    fs::create_dir_all(config_path.parent().expect("config parent")).expect("config dir");
    fs::create_dir_all(db_path.parent().expect("db parent")).expect("data dir");
    fs::write(
        &config_path,
        "mode = \"passive\"\ndata_dir = \"/var/lib/skynet-edr\"\nlog_dir = \"/var/log/skynet-edr\"\n[http_api]\nenabled = true\nbind = \"127.0.0.1:0\"\nread_only = true\n[redaction]\nredact_before_storage = true\nredact_before_logs = true\nredact_before_api = true\n[sensors]\nlinux_privileged = false\n[network]\noutbound_alerting_enabled = false\n[spool]\nenabled = true\npath = \"/packaged/spool/path-not-used-when-explicit-option-is-set\"\n",
    )
    .expect("config written");
    fs::write(&spool_path, "").expect("spool written");
    let init = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["store", "init", "--db"])
        .arg(&db_path)
        .output()
        .expect("store init runs");
    assert!(init.status.success());
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
    let api = listener.local_addr().expect("listener addr").to_string();

    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .arg("doctor")
        .arg("--config")
        .arg(&config_path)
        .arg("--db")
        .arg(&db_path)
        .arg("--spool")
        .arg(&spool_path)
        .arg("--api")
        .arg(api)
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    for check in ["install", "config", "store", "readiness"] {
        assert!(
            stdout.contains(&format!("{check}: ok")),
            "missing {check}: {stdout}"
        );
    }
    assert!(stdout.contains("doctor: ok"));
    assert!(!stdout.contains("rules.d"));
    assert!(!stdout.contains("agents.d"));

    fs::remove_dir_all(root).expect("temporary tree removed");
}

#[test]
fn doctor_fails_closed_for_non_loopback_api_without_connecting_or_leaking_config_values() {
    let root = temp_path("non-loopback");
    let config_path = root.join("etc/skynet-edr/config.toml");
    let db_path = root.join("var/lib/skynet-edr/skynet-edr.sqlite");
    fs::create_dir_all(config_path.parent().expect("config parent")).expect("config dir");
    fs::create_dir_all(db_path.parent().expect("db parent")).expect("data dir");
    fs::write(
        &config_path,
        "mode = \"passive\"\napi_token = \"super-secret-token\"\nlog_dir = \"/home/alice/skynet\"\n[http_api]\nenabled = true\nbind = \"192.0.2.10:8787\"\nread_only = true\n[redaction]\nredact_before_storage = true\nredact_before_logs = true\nredact_before_api = true\n[sensors]\nlinux_privileged = false\n[network]\noutbound_alerting_enabled = false\n",
    )
    .expect("config written");
    let init = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["store", "init", "--db"])
        .arg(&db_path)
        .output()
        .expect("store init runs");
    assert!(init.status.success());

    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .arg("doctor")
        .arg("--config")
        .arg(&config_path)
        .arg("--db")
        .arg(&db_path)
        .arg("--api")
        .arg("192.0.2.10:8787")
        .output()
        .expect("doctor runs");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("config: fail"));
    assert!(stdout.contains("readiness: fail"));
    assert!(stdout.contains("loopback"));
    assert!(!stdout.contains("super-secret-token"));
    assert!(!stdout.contains("/home/alice"));
    assert!(!stdout.contains("[REDACTED:"));

    fs::remove_dir_all(root).expect("temporary tree removed");
}

#[test]
fn doctor_rejects_guard_mode_and_mutable_posture_without_leaking_config_excerpt() {
    let root = temp_path("unsafe-posture");
    let config_path = root.join("etc/skynet-edr/config.toml");
    let db_path = root.join("var/lib/skynet-edr/skynet-edr.sqlite");
    fs::create_dir_all(config_path.parent().expect("config parent")).expect("config dir");
    fs::create_dir_all(db_path.parent().expect("db parent")).expect("data dir");
    fs::write(
        &config_path,
        "mode = \"guard\"\napi_token = \"doctor-secret-token\"\nlog_dir = \"/home/alice/skynet\"\n[http_api]\nenabled = true\nbind = \"127.0.0.1:8787\"\nread_only = false\n[redaction]\nredact_before_storage = false\nredact_before_logs = true\nredact_before_api = true\n[sensors]\nlinux_privileged = true\n[network]\noutbound_alerting_enabled = true\n",
    )
    .expect("config written");
    let init = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["store", "init", "--db"])
        .arg(&db_path)
        .output()
        .expect("store init runs");
    assert!(init.status.success());

    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .arg("doctor")
        .arg("--config")
        .arg(&config_path)
        .arg("--db")
        .arg(&db_path)
        .output()
        .expect("doctor runs");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("mode must be passive"));
    assert!(stdout.contains("read-only"));
    assert!(stdout.contains("redaction before storage"));
    assert!(stdout.contains("privileged Linux sensors"));
    assert!(stdout.contains("outbound alerting"));
    assert!(!stdout.contains("doctor-secret-token"));
    assert!(!stdout.contains("/home/alice"));
    assert!(!stdout.contains("[REDACTED:"));

    fs::remove_dir_all(root).expect("temporary tree removed");
}

#[test]
fn doctor_uses_configured_loopback_api_and_configured_spool_for_readiness() {
    let root = temp_path("configured-readiness");
    let config_path = root.join("etc/skynet-edr/config.toml");
    let db_path = root.join("var/lib/skynet-edr/skynet-edr.sqlite");
    let spool_path = root.join("var/lib/skynet-edr/configured-events.jsonl");
    fs::create_dir_all(config_path.parent().expect("config parent")).expect("config dir");
    fs::create_dir_all(db_path.parent().expect("db parent")).expect("data dir");
    fs::write(&spool_path, "").expect("configured spool written");
    fs::write(
        &config_path,
        format!(
            "mode = \"passive\"\n[http_api]\nenabled = true\nbind = \"127.0.0.1:9\"\nread_only = true\n[redaction]\nredact_before_storage = true\nredact_before_logs = true\nredact_before_api = true\n[sensors]\nlinux_privileged = false\n[network]\noutbound_alerting_enabled = false\n[spool]\nenabled = true\npath = \"{}\"\n",
            spool_path.display()
        ),
    )
    .expect("config written");
    let init = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["store", "init", "--db"])
        .arg(&db_path)
        .output()
        .expect("store init runs");
    assert!(init.status.success());

    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .arg("doctor")
        .arg("--config")
        .arg(&config_path)
        .arg("--db")
        .arg(&db_path)
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("readiness: ok"));

    fs::remove_dir_all(root).expect("temporary tree removed");
}
