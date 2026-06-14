//! CLI tests for local storage commands.

use std::{fs, path::PathBuf, process::Command};

fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "skynet-edr-cli-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    ));
    path
}

const INCIDENT_JSON: &str = r#"{
  "id": "inc_cli_1",
  "created_at_unix_ms": 1781440123000,
  "updated_at_unix_ms": 1781440124000,
  "status": "open",
  "severity": "high",
  "title": "Suspicious MCP tool chain",
  "summary": "Shell-capable MCP tool requires triage.",
  "source": {
    "kind": "mcp_tool",
    "sensor": "cli-test",
    "integration": "hermes"
  },
  "events": [
    {
      "id": "evt_cli_1",
      "observed_at_unix_ms": 1781440123000,
      "severity": "high",
      "source": {
        "kind": "mcp_tool",
        "sensor": "cli-test",
        "integration": "hermes"
      },
      "title": "MCP shell invocation",
      "details": null,
      "attributes": {
        "tool": "shell"
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
fn cli_help_lists_local_storage_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .arg("--help")
        .output()
        .expect("skynet-edr binary should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("store init"));
    assert!(stdout.contains("events ingest"));
    assert!(stdout.contains("incidents list"));
    assert!(stdout.contains("incidents show"));
    assert!(stdout.contains("incidents export"));
}

#[test]
fn cli_initializes_store_and_lists_imported_incident() {
    let db_path = temp_path("store.sqlite");
    let incident_path = temp_path("incident.json");
    fs::write(&incident_path, INCIDENT_JSON).expect("fixture incident is written");

    let init = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["store", "init", "--db"])
        .arg(&db_path)
        .output()
        .expect("store init runs");
    assert!(init.status.success());

    let ingest = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "ingest", "--db"])
        .arg(&db_path)
        .arg("--incident-json")
        .arg(&incident_path)
        .output()
        .expect("events ingest runs");
    assert!(ingest.status.success());

    let list = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["incidents", "list", "--db"])
        .arg(&db_path)
        .output()
        .expect("incidents list runs");
    assert!(list.status.success());
    let stdout = String::from_utf8(list.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("inc_cli_1"));
    assert!(stdout.contains("high"));
    assert!(stdout.contains("Suspicious MCP tool chain"));

    fs::remove_file(db_path).expect("temporary db is removed");
    fs::remove_file(incident_path).expect("temporary fixture is removed");
}

#[test]
fn cli_shows_and_exports_incident_jsonl() {
    let db_path = temp_path("show-export.sqlite");
    let incident_path = temp_path("show-export-incident.json");
    fs::write(&incident_path, INCIDENT_JSON).expect("fixture incident is written");

    let ingest = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "ingest", "--db"])
        .arg(&db_path)
        .arg("--incident-json")
        .arg(&incident_path)
        .output()
        .expect("events ingest runs");
    assert!(ingest.status.success());

    let show = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["incidents", "show", "inc_cli_1", "--db"])
        .arg(&db_path)
        .output()
        .expect("incidents show runs");
    assert!(show.status.success());
    let shown: serde_json::Value =
        serde_json::from_slice(&show.stdout).expect("show prints incident JSON");
    assert_eq!(shown["id"], "inc_cli_1");

    let export = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["incidents", "export", "--db"])
        .arg(&db_path)
        .args(["--format", "jsonl"])
        .output()
        .expect("incidents export runs");
    assert!(export.status.success());
    let stdout = String::from_utf8(export.stdout).expect("stdout should be UTF-8");
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1);
    let exported: serde_json::Value = serde_json::from_str(lines[0]).expect("export line is JSON");
    assert_eq!(exported["id"], "inc_cli_1");

    fs::remove_file(db_path).expect("temporary db is removed");
    fs::remove_file(incident_path).expect("temporary fixture is removed");
}
