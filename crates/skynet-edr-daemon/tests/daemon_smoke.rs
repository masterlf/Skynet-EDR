//! Daemon smoke tests for the passive, non-privileged skeleton.

use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
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

fn wait_for_http_status(port: u16) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_error = String::new();

    while Instant::now() < deadline {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(mut stream) => {
                stream
                    .write_all(
                        b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                    )
                    .expect("status request is written");
                let mut response = String::new();
                stream
                    .read_to_string(&mut response)
                    .expect("status response is read");
                return response;
            }
            Err(error) => {
                last_error = error.to_string();
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    panic!("HTTP status endpoint did not become reachable: {last_error}");
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn daemon_run_serves_loopback_http_api_when_enabled() {
    let dir = temp_config_dir("run-serves-http");
    let db_path = dir.join("events.sqlite");
    let port = 18_787 + (std::process::id() % 1_000) as u16;
    let config = write_config(
        &dir,
        &format!(
            r#"
mode = "passive"

[http_api]
enabled = true
bind = "127.0.0.1:{port}"
read_only = true

[sensors]
linux_privileged = false

[spool]
enabled = true
db = "{}"
path = "{}"
checkpoint = "{}"
"#,
            db_path.display(),
            dir.join("empty-spool.jsonl").display(),
            dir.join("spool.offset").display()
        ),
    );
    fs::write(dir.join("empty-spool.jsonl"), "").expect("empty spool is written");

    let mut child = daemon()
        .arg("run")
        .arg("--config")
        .arg(config)
        .spawn()
        .expect("daemon should start");

    let response = wait_for_http_status(port);
    terminate_child(&mut child);

    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("application/json"));
    assert!(response.contains("\"read_only\":true"));
    assert!(response.contains("\"product\":\"Skynet-EDR\""));
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
fn daemon_run_ingests_configured_canonical_spool_once_on_startup() {
    let dir = temp_config_dir("run-ingests-spool");
    let db_path = dir.join("events.sqlite");
    let spool_path = dir.join("events.jsonl");
    let checkpoint_path = dir.join("events.offset");
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "../../skynet-edr-core/tests/fixtures/canonical_event_v0.json"
    ))
    .expect("canonical fixture JSON");
    value["event_id"] = serde_json::json!("evt_daemon_spool_1");
    value["title"] = serde_json::json!("Daemon spool canonical event");
    let event = serde_json::to_string(&value).expect("fixture serializes");
    fs::write(&spool_path, format!("{event}\nmalformed\n")).expect("spool fixture written");
    let config = write_config(
        &dir,
        &format!(
            r#"
mode = "passive"

[http_api]
enabled = true
bind = "127.0.0.1:8787"
read_only = true

[sensors]
linux_privileged = false

[spool]
enabled = true
db = "{}"
path = "{}"
checkpoint = "{}"
"#,
            db_path.display(),
            spool_path.display(),
            checkpoint_path.display()
        ),
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
    assert!(stdout.contains("spool ingestion: ingested=1 dropped=1 duplicates=0"));
    assert!(fs::read_to_string(&checkpoint_path).is_ok());
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
