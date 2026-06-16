//! Built-in attack simulation regression tests.

use skynet_edr_core::{run_secret_egress_attack_simulation, LocalStore, Severity};

const RAW_SECRET: &str = "FAKE_SKYNET_ATTACK_SIM_SECRET_DO_NOT_EXPOSE";
const RAW_SECRET_PATH: &str = "/home/attack-sim/.skynet/fake-secret.env";

#[test]
fn built_in_secret_egress_attack_sim_creates_redacted_critical_incident() {
    let db_path = temp_path("attack-sim-secret-egress.sqlite");
    let store = LocalStore::open(&db_path).expect("temporary local store opens");

    let summary =
        run_secret_egress_attack_simulation(&store).expect("attack simulation persists telemetry");

    assert_eq!(summary.event_count, 2);
    assert_eq!(summary.incident_count, 1);

    let events = store.list_events().expect("events list");
    assert_eq!(events.len(), 2);
    assert!(events
        .iter()
        .any(|event| event.id.as_str()
            == "hermes:attack_sim_secret_egress:1781519200000:file_access:0"));
    assert!(events.iter().any(
        |event| event.id.as_str() == "hermes:attack_sim_secret_egress:1781519230000:terminal:1"
    ));

    let incidents = store.list_incidents().expect("incidents list");
    assert_eq!(incidents.len(), 1);
    let incident = &incidents[0];
    assert_eq!(
        incident.id.as_str(),
        "inc:EDR-EXFIL-001:attack_sim_secret_egress:1781519200000"
    );
    assert_eq!(incident.severity, Severity::Critical);
    assert_eq!(incident.events.len(), 2);
    assert!(incident.redaction.contains_sensitive_data);

    let stored_json =
        serde_json::to_string(&(events, incidents)).expect("stored telemetry serializes");
    assert!(!stored_json.contains(RAW_SECRET));
    assert!(!stored_json.contains(RAW_SECRET_PATH));
    assert!(stored_json.contains("[REDACTED:secret]"));
    assert!(stored_json.contains("[REDACTED:local_context]"));

    std::fs::remove_file(db_path).expect("temporary db is removed");
}

#[test]
fn built_in_secret_egress_attack_sim_is_deterministic_and_idempotent() {
    let db_path = temp_path("attack-sim-secret-egress-idempotent.sqlite");
    let store = LocalStore::open(&db_path).expect("temporary local store opens");

    let first = run_secret_egress_attack_simulation(&store).expect("first simulation succeeds");
    let second = run_secret_egress_attack_simulation(&store).expect("second simulation succeeds");

    assert_eq!(first, second);
    assert_eq!(store.list_events().expect("events list").len(), 2);
    assert_eq!(store.list_incidents().expect("incidents list").len(), 1);

    std::fs::remove_file(db_path).expect("temporary db is removed");
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "skynet-edr-core-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    ));
    path
}
