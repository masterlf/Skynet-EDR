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
    assert!(stdout.contains("events ingest-hermes"));
    assert!(stdout.contains("events ingest-spool"));
    assert!(stdout.contains("events list"));
    assert!(stdout.contains("events show"));
    assert!(stdout.contains("events export"));
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
fn cli_ingests_hermes_trace_into_redacted_events_and_correlated_incident() {
    let db_path = temp_path("hermes-trace.sqlite");
    let trace_path = temp_path("hermes-trace.json");
    let trace_json =
        include_str!("../../skynet-edr-core/tests/fixtures/hermes_secret_egress_trace.json");
    fs::write(&trace_path, trace_json).expect("fixture trace is written");

    let ingest = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "ingest-hermes", "--db"])
        .arg(&db_path)
        .arg("--trace-json")
        .arg(&trace_path)
        .output()
        .expect("events ingest-hermes runs");
    assert!(ingest.status.success());
    let stdout = String::from_utf8(ingest.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("ingested 2 Hermes event(s), opened 1 incident(s)"));

    let list = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "list", "--db"])
        .arg(&db_path)
        .output()
        .expect("events list runs");
    assert!(list.status.success());
    let stdout = String::from_utf8(list.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("hermes:sess_secret_egress:1781519100000:file_access:0"));
    assert!(stdout.contains("hermes:sess_secret_egress:1781519130000:terminal:1"));

    let show = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args([
            "events",
            "show",
            "hermes:sess_secret_egress:1781519130000:terminal:1",
            "--db",
        ])
        .arg(&db_path)
        .output()
        .expect("events show runs");
    assert!(show.status.success());
    let shown = String::from_utf8(show.stdout).expect("stdout should be UTF-8");
    assert!(!shown.contains("fake-token-value"));
    assert!(!shown.contains("fake-output-secret"));
    assert!(!shown.contains("/root/.hermes/auth.json"));
    assert!(shown.contains("[REDACTED:secret]"));
    assert!(shown.contains("[REDACTED:local_context]"));

    let incident_show = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args([
            "incidents",
            "show",
            "inc:EDR-EXFIL-001:sess_secret_egress:1781519100000",
            "--db",
        ])
        .arg(&db_path)
        .output()
        .expect("incidents show runs");
    assert!(incident_show.status.success());
    let incident: serde_json::Value =
        serde_json::from_slice(&incident_show.stdout).expect("incident show prints JSON");
    assert_eq!(incident["severity"], "critical");
    assert_eq!(incident["status"], "open");
    assert_eq!(
        incident["events"].as_array().expect("events array").len(),
        2
    );
    let incident_json = String::from_utf8(incident_show.stdout).expect("stdout should be UTF-8");
    assert!(!incident_json.contains("/root/.hermes/auth.json"));
    assert!(!incident_json.contains("fake-output-secret"));
    assert!(incident_json.contains("EDR-EXFIL-001"));

    fs::remove_file(db_path).expect("temporary db is removed");
    fs::remove_file(trace_path).expect("temporary trace is removed");
}

#[test]
fn cli_ingests_canonical_jsonl_spool_with_checkpoint_accounting() {
    let db_path = temp_path("canonical-spool.sqlite");
    let spool_path = temp_path("canonical-spool.jsonl");
    let checkpoint_path = temp_path("canonical-spool.offset");
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "../../skynet-edr-core/tests/fixtures/canonical_event_v0.json"
    ))
    .expect("canonical fixture JSON");
    value["event_id"] = serde_json::json!("evt_cli_spool_1");
    value["title"] = serde_json::json!("CLI spool canonical event");
    let event = serde_json::to_string(&value).expect("fixture serializes");
    fs::write(&spool_path, format!("{event}\nnot-json\n")).expect("spool is written");

    let ingest = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "ingest-spool", "--db"])
        .arg(&db_path)
        .arg("--spool")
        .arg(&spool_path)
        .arg("--checkpoint")
        .arg(&checkpoint_path)
        .output()
        .expect("events ingest-spool runs");
    assert!(ingest.status.success());
    let stdout = String::from_utf8(ingest.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains(
        "ingested 1 canonical event(s), dropped 1 malformed event(s), skipped 0 duplicate event(s)"
    ));

    let replay = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "ingest-spool", "--db"])
        .arg(&db_path)
        .arg("--spool")
        .arg(&spool_path)
        .arg("--checkpoint")
        .arg(&checkpoint_path)
        .output()
        .expect("events ingest-spool replay runs");
    assert!(replay.status.success());
    let stdout = String::from_utf8(replay.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains(
        "ingested 0 canonical event(s), dropped 0 malformed event(s), skipped 0 duplicate event(s)"
    ));

    let show = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "show", "evt_cli_spool_1", "--db"])
        .arg(&db_path)
        .output()
        .expect("events show runs");
    assert!(show.status.success());
    let shown: serde_json::Value = serde_json::from_slice(&show.stdout).expect("show prints JSON");
    assert_eq!(shown["id"], "evt_cli_spool_1");
    assert_eq!(shown["attributes"]["event_type"], "agent.network.egress");
    assert_eq!(shown["attributes"]["schema_version"], "skynet.event.v0");

    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(spool_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn cli_lists_shows_and_exports_event_jsonl() {
    let db_path = temp_path("event-show-export.sqlite");
    let incident_path = temp_path("event-show-export-incident.json");
    fs::write(&incident_path, INCIDENT_JSON).expect("fixture incident is written");

    let ingest = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "ingest", "--db"])
        .arg(&db_path)
        .arg("--incident-json")
        .arg(&incident_path)
        .output()
        .expect("events ingest runs");
    assert!(ingest.status.success());

    let list = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "list", "--db"])
        .arg(&db_path)
        .output()
        .expect("events list runs");
    assert!(list.status.success());
    let stdout = String::from_utf8(list.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("evt_cli_1"));
    assert!(stdout.contains("high"));
    assert!(stdout.contains("MCP shell invocation"));

    let show = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "show", "evt_cli_1", "--db"])
        .arg(&db_path)
        .output()
        .expect("events show runs");
    assert!(show.status.success());
    let shown: serde_json::Value =
        serde_json::from_slice(&show.stdout).expect("show prints event JSON");
    assert_eq!(shown["id"], "evt_cli_1");

    let export = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "export", "--db"])
        .arg(&db_path)
        .args(["--format", "jsonl"])
        .output()
        .expect("events export runs");
    assert!(export.status.success());
    let stdout = String::from_utf8(export.stdout).expect("stdout should be UTF-8");
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1);
    let exported: serde_json::Value = serde_json::from_str(lines[0]).expect("export line is JSON");
    assert_eq!(exported["id"], "evt_cli_1");

    fs::remove_file(db_path).expect("temporary db is removed");
    fs::remove_file(incident_path).expect("temporary fixture is removed");
}

#[test]
fn cli_redacts_untrusted_incident_before_showing_or_exporting() {
    let db_path = temp_path("redacted-cli.sqlite");
    let incident_path = temp_path("redacted-cli-incident.json");
    let incident_json = INCIDENT_JSON
        .replace(
            "\"details\": null",
            "\"details\": \"password=super-secret\"",
        )
        .replace(
            "\"tool\": \"shell\"",
            "\"api_token\": \"sk_liv...oken\", \"path\": \"/home/alice/.ssh/id_rsa\"",
        );
    fs::write(&incident_path, incident_json).expect("fixture incident is written");

    let ingest = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "ingest", "--db"])
        .arg(&db_path)
        .arg("--incident-json")
        .arg(&incident_path)
        .output()
        .expect("events ingest runs");
    assert!(ingest.status.success());

    let event_show = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["events", "show", "evt_cli_1", "--db"])
        .arg(&db_path)
        .output()
        .expect("events show runs");
    assert!(event_show.status.success());
    let event_stdout = String::from_utf8(event_show.stdout).expect("stdout should be UTF-8");
    assert!(!event_stdout.contains("super-secret"));
    assert!(!event_stdout.contains("sk_liv...oken"));
    assert!(!event_stdout.contains("/home/alice"));
    assert!(event_stdout.contains("[REDACTED:secret]"));

    let incident_export = Command::new(env!("CARGO_BIN_EXE_skynet-edr"))
        .args(["incidents", "export", "--db"])
        .arg(&db_path)
        .args(["--format", "jsonl"])
        .output()
        .expect("incidents export runs");
    assert!(incident_export.status.success());
    let export_stdout = String::from_utf8(incident_export.stdout).expect("stdout should be UTF-8");
    assert!(!export_stdout.contains("super-secret"));
    assert!(!export_stdout.contains("sk_liv...oken"));
    assert!(!export_stdout.contains("/home/alice"));
    assert!(export_stdout.contains("[REDACTED:secret]"));

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
