//! CLI tests for redaction-safe diagnostics collection.

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "skynet-edr-diagnostics-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    ));
    path
}

const INCIDENT_JSON: &str = r#"{
  "id": "inc_diag_1",
  "created_at_unix_ms": 1781440123000,
  "updated_at_unix_ms": 1781440124000,
  "status": "open",
  "severity": "high",
  "title": "Diagnostic fixture incident",
  "summary": "Synthetic incident for diagnostics count verification.",
  "source": {
    "kind": "mcp_tool",
    "sensor": "diagnostics-test",
    "integration": "hermes"
  },
  "events": [
    {
      "id": "evt_diag_1",
      "observed_at_unix_ms": 1781440123000,
      "severity": "high",
      "source": {
        "kind": "mcp_tool",
        "sensor": "diagnostics-test",
        "integration": "hermes"
      },
      "title": "Diagnostic fixture event",
      "details": "password=raw-event-secret",
      "attributes": {
        "path": "/home/alice/.ssh/id_rsa"
      },
      "redaction": {
        "contains_sensitive_data": false,
        "redacted_fields": []
      }
    }
  ],
  "redaction": {
    "contains_sensitive_data": false,
    "redacted_fields": []
  }
}"#;

#[test]
fn cli_help_lists_diagnostics_collect() {
    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .arg("--help")
        .output()
        .expect("skynet-edr binary should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("diagnostics collect"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn diagnostics_collect_writes_private_redacted_bundle_without_raw_events_by_default() {
    let bundle_dir = temp_path("bundle");
    let db_path = temp_path("store.sqlite");
    let incident_path = temp_path("incident.json");
    let config_path = temp_path("config.toml");
    let log_path = temp_path("skynet-edr.log");
    let status_path = temp_path("service-status.txt");

    fs::write(&incident_path, INCIDENT_JSON).expect("fixture incident is written");
    fs::write(
        &config_path,
        "mode = \"passive\"\napi_token = \"config-secret-value\"\nlog_dir = \"/home/alice/skynet-logs\"\n[http_api]\nenabled = true\nbind = \"127.0.0.1:8787\"\nread_only = true\n",
    )
    .expect("fixture config is written");
    fs::write(
        &log_path,
        "INFO started\nWARN authorization: Bearer log-secret-value path=/home/alice/.ssh/id_rsa\n",
    )
    .expect("fixture log is written");
    fs::write(
        &status_path,
        "skynet-edr.service active api_key=status-secret-value home=/home/alice\n",
    )
    .expect("fixture service status is written");

    let ingest = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "ingest", "--db"])
        .arg(&db_path)
        .arg("--incident-json")
        .arg(&incident_path)
        .output()
        .expect("events ingest runs");
    assert!(ingest.status.success());

    let collect = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["diagnostics", "collect", "--output"])
        .arg(&bundle_dir)
        .arg("--config")
        .arg(&config_path)
        .arg("--db")
        .arg(&db_path)
        .arg("--log-file")
        .arg(&log_path)
        .arg("--service-status-file")
        .arg(&status_path)
        .output()
        .expect("diagnostics collect runs");
    assert!(
        collect.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&collect.stderr)
    );

    let stdout = String::from_utf8(collect.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("diagnostics bundle written:"));
    assert_eq!(
        fs::metadata(&bundle_dir)
            .expect("bundle metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    let manifest_path = bundle_dir.join("manifest.json");
    let manifest = fs::read_to_string(&manifest_path).expect("manifest exists");
    assert!(manifest.contains("\"raw_events_included\": false"));
    assert!(manifest.contains("versions.txt"));

    let config_summary =
        fs::read_to_string(bundle_dir.join("config-summary.toml")).expect("config summary exists");
    assert!(config_summary.contains("mode"));
    assert!(!config_summary.contains("config-secret-value"));
    assert!(!config_summary.contains("/home/alice"));
    assert!(config_summary.contains("[REDACTED:secret]"));
    assert!(config_summary.contains("[REDACTED:local_context]"));

    let logs = fs::read_to_string(bundle_dir.join("recent-logs.txt")).expect("logs exist");
    assert!(!logs.contains("log-secret-value"));
    assert!(!logs.contains("/home/alice"));
    assert!(logs.contains("[REDACTED:secret]"));

    let service_status =
        fs::read_to_string(bundle_dir.join("service-status.txt")).expect("service status exists");
    assert!(!service_status.contains("status-secret-value"));
    assert!(!service_status.contains("/home/alice"));

    let storage_status =
        fs::read_to_string(bundle_dir.join("storage-status.json")).expect("storage status exists");
    assert!(storage_status.contains("\"event_count\": 1"));
    assert!(storage_status.contains("\"incident_count\": 1"));
    assert!(!storage_status.contains("evt_diag_1"));
    assert!(!bundle_dir.join("events.jsonl").exists());

    for entry in fs::read_dir(&bundle_dir).expect("bundle entries") {
        let entry = entry.expect("bundle entry");
        if entry.file_type().expect("entry type").is_file() {
            assert_eq!(
                entry
                    .metadata()
                    .expect("entry metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "file should be 0600: {}",
                entry.path().display()
            );
        }
    }

    fs::remove_dir_all(bundle_dir).expect("temporary bundle is removed");
    let _ = fs::remove_file(&db_path);
    let _ = fs::remove_file(format!("{}-wal", db_path.display()));
    let _ = fs::remove_file(format!("{}-shm", db_path.display()));
    for path in [incident_path, config_path, log_path, status_path] {
        fs::remove_file(path).expect("temporary fixture is removed");
    }
}

#[test]
fn diagnostics_collect_does_not_create_missing_database() {
    let bundle_dir = temp_path("missing-db");
    let db_path = temp_path("missing.sqlite");

    let collect = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["diagnostics", "collect", "--output"])
        .arg(&bundle_dir)
        .arg("--db")
        .arg(&db_path)
        .output()
        .expect("diagnostics collect runs");
    assert!(
        collect.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&collect.stderr)
    );

    assert!(
        !db_path.exists(),
        "diagnostics must not create a missing DB"
    );
    let storage_status =
        fs::read_to_string(bundle_dir.join("storage-status.json")).expect("storage status exists");
    assert!(storage_status.contains("\"store_present\": false"));

    fs::remove_dir_all(bundle_dir).expect("temporary bundle is removed");
}
