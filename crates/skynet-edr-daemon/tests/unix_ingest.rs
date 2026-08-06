//! Linux `AF_UNIX` continuous-ingestion integration tests.

#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use skynet_edr_core::LocalStore;
use skynet_edr_daemon::{
    authenticate_ingest_peer, bind_ingest_listener, process_ingest_connection, IngestionHealth,
    ProducerRole, UnixIngestConfig,
};

const CANONICAL_EVENT: &str =
    include_str!("../../skynet-edr-core/tests/fixtures/canonical_event_v0.json");

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "skynet-edr-unix-ingest-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ))
}

fn config(socket_path: PathBuf, allowed_uids: Vec<u32>) -> UnixIngestConfig {
    UnixIngestConfig {
        socket_path,
        socket_gid: None,
        allowed_uids,
        allow_root: false,
        max_frame_bytes: 262_144,
        max_connections: 64,
        read_timeout: Duration::from_millis(100),
        write_timeout: Duration::from_millis(100),
        candidate_limit: 10_000,
        required_reported_roles: Vec::new(),
    }
}

fn health_report(version: u64, role: Option<&str>, instance_id: Option<&str>) -> serde_json::Value {
    let mut report = serde_json::json!({
        "version": version,
        "message_type": "producer_health",
        "checkpoint_bytes": 0,
        "backlog_bytes": 0,
        "backlog_age_ms": null,
        "events_dropped_total": 0,
        "events_malformed_total": 0,
        "transport_state": "available"
    });
    if let Some(role) = role {
        report["runtime_role"] = serde_json::json!(role);
    }
    if let Some(instance_id) = instance_id {
        report["instance_id"] = serde_json::json!(instance_id);
    }
    report
}

fn v3_health(role: &str, generation: &str, nonce: &str) -> serde_json::Value {
    serde_json::json!({
        "version": 3,
        "message_type": "producer_health",
        "runtime_role": role,
        "plugin_generation": generation,
        "runtime_instance_nonce": nonce,
        "checkpoint_bytes": 0,
        "backlog_bytes": 0,
        "backlog_age_ms": null,
        "events_dropped_total": 0,
        "events_malformed_total": 0,
        "transport_state": "available"
    })
}

fn v3_event(
    role: &str,
    generation: &str,
    nonce: &str,
    event: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "version": 3,
        "message_type": "canonical_event",
        "runtime_role": role,
        "plugin_generation": generation,
        "runtime_instance_nonce": nonce,
        "event": event
    })
}

fn v3_event_raw(event: &str) -> String {
    format!(
        r#"{{"version":3,"message_type":"canonical_event","runtime_role":"gateway","plugin_generation":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","runtime_instance_nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","event":{event}}}"#
    )
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut framed = u32::try_from(payload.len())
        .expect("test payload length fits")
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(payload);
    framed
}

#[allow(clippy::needless_pass_by_value)]
fn p1a_event(
    id: &str,
    event_type: &str,
    kind: &str,
    trust: &str,
    observed: u64,
    trace: &str,
    attributes: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": "skynet.event.v0",
        "event_id": id,
        "event_type": event_type,
        "observed_at_unix_ms": observed,
        "received_at_unix_ms": observed,
        "severity": "informational",
        "source": {"kind": kind, "sensor": "skynet-edr-hermes-plugin", "integration": "hermes"},
        "provenance": {
            "producer": "hermes-agent",
            "collector": "skynet-edr-hermes-plugin",
            "tenant": "FAKE_UNIX_TENANT",
            "source_event_id": id,
            "trace_id": trace,
            "span_id": id,
            "parent_span_id": null
        },
        "trust_level": trust,
        "title": "FAKE Unix P1a producer title",
        "details": null,
        "attributes": attributes,
        "redaction": {"contains_sensitive_data": false, "redacted_fields": []}
    })
}

fn p1a_request_attributes(tool: &str) -> serde_json::Value {
    serde_json::json!({
        "hook": "pre_tool_call",
        "tool_name": tool,
        "network_indicator": false,
        "direct_ip": false,
        "delivery_indicator": false,
        "sensitive_access": false,
        "params_length": 0,
        "params_preview": "[OMITTED:tool_params]"
    })
}

fn p1a_exchange(
    uid: u32,
    config: &UnixIngestConfig,
    db_path: &std::path::Path,
    event: &serde_json::Value,
) -> String {
    exchange(
        uid,
        config,
        db_path,
        &frame(&serde_json::to_vec(event).expect("event serializes")),
    )
}

fn exchange(
    uid: u32,
    config: &UnixIngestConfig,
    db_path: &std::path::Path,
    bytes: &[u8],
) -> String {
    let health = IngestionHealth::default();
    exchange_with_health(uid, config, db_path, bytes, &health)
}

fn exchange_with_health(
    uid: u32,
    config: &UnixIngestConfig,
    db_path: &std::path::Path,
    bytes: &[u8],
    health: &IngestionHealth,
) -> String {
    let (mut client, server) = UnixStream::pair().expect("stream pair opens");
    client.write_all(bytes).expect("request writes");
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("request completes");
    process_with_test_uid(server, uid, config, db_path, health);
    let mut ack = String::new();
    client.read_to_string(&mut ack).expect("ack reads");
    ack
}

fn process_with_test_uid(
    server: UnixStream,
    uid: u32,
    config: &UnixIngestConfig,
    db_path: &std::path::Path,
    health: &IngestionHealth,
) {
    let peer = authenticate_ingest_peer(&server).expect("peer identity captured once");
    let mut effective_config = config.clone();
    if config.allowed_uids.contains(&uid) {
        effective_config.allowed_uids = vec![peer.uid()];
        effective_config.allow_root = peer.uid() == 0;
    }
    process_ingest_connection(server, &peer, &effective_config, db_path, health)
        .expect("connection handled");
}

#[test]
fn authorized_frame_is_acked_only_after_atomic_visibility_and_replay_is_duplicate() {
    let db_path = temp_path("commit.sqlite");
    drop(LocalStore::open(&db_path).expect("startup migration succeeds"));
    let config = config(temp_path("commit.sock"), vec![1_234]);
    let mut event: serde_json::Value =
        serde_json::from_str(CANONICAL_EVENT).expect("fixture parses");
    event["event_id"] = serde_json::json!("evt_unix_ingest_commit");
    let payload = serde_json::to_vec(&event).expect("event serializes");

    let first = exchange(1_234, &config, &db_path, &frame(&payload));
    assert!(first.contains(r#""status":"persisted""#), "{first}");
    assert!(LocalStore::open_read_only(&db_path)
        .expect("store opens read-only")
        .get_event("evt_unix_ingest_commit")
        .expect("event lookup succeeds")
        .is_some());

    let replay = exchange(1_234, &config, &db_path, &frame(&payload));
    assert!(replay.contains(r#""status":"duplicate""#), "{replay}");
    assert_eq!(
        LocalStore::open_read_only(&db_path)
            .expect("store opens read-only")
            .count_ingest_receipts()
            .expect("receipt count"),
        1
    );
    let _ = fs::remove_file(db_path);
}

#[test]
fn repeated_frames_do_not_rerun_legacy_incident_normalization() {
    let db_path = temp_path("no-per-frame-migration.sqlite");
    drop(LocalStore::open(&db_path).expect("startup migration succeeds"));
    let raw = rusqlite::Connection::open(&db_path).expect("inspection connection opens");
    raw.execute(
        "INSERT INTO incidents (
            id, created_at_unix_ms, updated_at_unix_ms, status, severity, title, payload_json
         ) VALUES ('.', 1, 1, 'open', 'high', 'legacy', 'not-json')",
        [],
    )
    .expect("hostile legacy row inserted after startup migration");
    drop(raw);
    let config = config(temp_path("no-per-frame-migration.sock"), vec![1_234]);

    for index in 0..2 {
        let mut event: serde_json::Value =
            serde_json::from_str(CANONICAL_EVENT).expect("fixture parses");
        event["event_id"] = serde_json::json!(format!("evt_no_remigration_{index}"));
        let ack = exchange(
            1_234,
            &config,
            &db_path,
            &frame(&serde_json::to_vec(&event).expect("event serializes")),
        );
        assert!(ack.contains(r#""status":"persisted""#), "{ack}");
    }
    let raw = rusqlite::Connection::open(&db_path).expect("inspection connection reopens");
    assert_eq!(
        raw.query_row(
            "SELECT payload_json FROM incidents WHERE id = '.'",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("legacy row remains untouched"),
        "not-json"
    );

    let _ = fs::remove_file(db_path);
}

#[test]
fn collision_ack_is_explicit_only_after_durable_evidence() {
    const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FIRST_NONCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const COLLISION_NONCE: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let db_path = temp_path("collision.sqlite");
    drop(LocalStore::open(&db_path).expect("startup migration succeeds"));
    let config = config(temp_path("collision.sock"), vec![1_234, 2_345]);
    let mut event: serde_json::Value =
        serde_json::from_str(CANONICAL_EVENT).expect("fixture parses");
    event["event_id"] = serde_json::json!("evt_unix_collision");
    let first = v3_event("gateway", GENERATION, FIRST_NONCE, &event);
    let first_payload = serde_json::to_vec(&first).expect("event serializes");
    let health = IngestionHealth::default();
    assert!(
        exchange_with_health(1_234, &config, &db_path, &frame(&first_payload), &health,)
            .contains(r#""status":"persisted""#)
    );
    event["title"] = serde_json::json!("FAKE_COLLISION_PAYLOAD_MUST_NOT_PERSIST");
    let collision = v3_event("gateway", GENERATION, COLLISION_NONCE, &event);
    let collision_payload = serde_json::to_vec(&collision).expect("collision serializes");

    let ack = exchange_with_health(
        2_345,
        &config,
        &db_path,
        &frame(&collision_payload),
        &health,
    );
    assert!(ack.contains(r#""status":"collision""#), "{ack}");
    assert_eq!(
        LocalStore::open_read_only(&db_path)
            .expect("store opens read-only")
            .count_ingest_collisions()
            .expect("collision count"),
        1
    );
    let status = health.status_json(Duration::from_secs(30));
    let collision_source = status["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["runtime_instance_nonce"] == COLLISION_NONCE)
        .unwrap();
    assert!(collision_source["last_event_committed_at_unix_ms"].is_null());
    assert_eq!(collision_source["events_collision_total"], 1);
    let _ = fs::remove_file(db_path);
}

#[test]
fn unauthorized_peer_is_rejected_before_payload_read() {
    let db_path = temp_path("unauthorized.sqlite");
    let health = IngestionHealth::default();
    let config = config(temp_path("unauthorized.sock"), vec![1_234]);
    let (mut client, server) = UnixStream::pair().expect("stream pair opens");

    let started = Instant::now();
    process_with_test_uid(server, 9_999, &config, &db_path, &health);
    assert!(started.elapsed() < Duration::from_millis(50));
    assert_eq!(health.snapshot().connections_unauthorized_total, 1);
    assert!(client
        .write_all(&frame(b"hostile payload must not be read"))
        .is_err());
    assert!(!db_path.exists());
}

#[test]
fn zero_oversize_malformed_and_slow_frames_persist_nothing() {
    let db_path = temp_path("hostile.sqlite");
    let mut config = config(temp_path("hostile.sock"), vec![1_234]);
    config.max_frame_bytes = 32;

    let zero = exchange(1_234, &config, &db_path, &0_u32.to_be_bytes());
    assert!(zero.contains(r#""status":"rejected_permanent""#));
    let oversize = exchange(1_234, &config, &db_path, &33_u32.to_be_bytes());
    assert!(oversize.contains(r#""reason":"frame_size""#));
    let malformed = exchange(1_234, &config, &db_path, &frame(b"not-json"));
    assert!(malformed.contains(r#""reason":"invalid_event""#));

    let health = IngestionHealth::default();
    let (mut slow_client, slow_server) = UnixStream::pair().expect("stream pair opens");
    slow_client
        .write_all(&[0, 0])
        .expect("partial header writes");
    process_with_test_uid(slow_server, 1_234, &config, &db_path, &health);
    assert_eq!(health.snapshot().frames_timeout_total, 1);
    assert!(!db_path.exists());
}

#[test]
fn slow_drip_cannot_extend_the_absolute_frame_deadline() {
    let db_path = temp_path("slow-drip.sqlite");
    let health = IngestionHealth::default();
    let mut config = config(temp_path("slow-drip.sock"), vec![1_234]);
    config.read_timeout = Duration::from_millis(100);
    let (mut client, server) = UnixStream::pair().expect("stream pair opens");
    let started = Instant::now();
    let drip = thread::spawn(move || {
        for byte in frame(CANONICAL_EVENT.as_bytes()) {
            if client.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(60));
        }
    });

    process_with_test_uid(server, 1_234, &config, &db_path, &health);
    assert!(
        started.elapsed() < Duration::from_millis(350),
        "absolute deadline must not reset after each byte"
    );
    assert_eq!(health.snapshot().frames_timeout_total, 1);
    drip.join().expect("drip writer joins");
    assert!(!db_path.exists());
}

#[test]
fn socket_startup_rejects_symlink_and_regular_file_but_recovers_owned_stale_socket() {
    let root = temp_path("socket-safety");
    fs::create_dir_all(&root).expect("root created");
    let socket_path = root.join("ingest.sock");
    let target = root.join("target");
    fs::write(&target, "fake").expect("target created");
    std::os::unix::fs::symlink(&target, &socket_path).expect("symlink created");
    let config = config(socket_path.clone(), vec![1_234]);
    assert!(bind_ingest_listener(&config)
        .expect_err("symlink must fail closed")
        .to_string()
        .contains("symlink"));
    fs::remove_file(&socket_path).expect("symlink removed");
    fs::write(&socket_path, "fake").expect("regular file created");
    assert!(bind_ingest_listener(&config).is_err());
    fs::remove_file(&socket_path).expect("regular file removed");

    let stale = std::os::unix::net::UnixListener::bind(&socket_path).expect("stale socket binds");
    drop(stale);
    let listener = bind_ingest_listener(&config).expect("owned stale socket is replaced safely");
    assert!(socket_path.exists());
    drop(listener);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn published_socket_has_intended_mode_ownership_and_no_private_alias() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = temp_path("socket-publication");
    fs::create_dir_all(&root).expect("root created");
    let socket_path = root.join("ingest.sock");
    let mut config = config(socket_path.clone(), vec![1_234]);
    config.socket_gid = Some(nix::unistd::Gid::effective().as_raw());

    let listener = bind_ingest_listener(&config).expect("secured socket publishes");
    let metadata = fs::symlink_metadata(&socket_path).expect("published socket metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
    assert_eq!(metadata.uid(), nix::unistd::Uid::effective().as_raw());
    assert_eq!(metadata.gid(), nix::unistd::Gid::effective().as_raw());
    assert!(UnixStream::connect(&socket_path).is_ok());
    assert_eq!(
        fs::read_dir(&root)
            .expect("root reads")
            .collect::<Result<Vec<_>, _>>()
            .expect("entries read")
            .len(),
        1,
        "private publication socket must be removed"
    );

    drop(listener);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn accept_loop_drop_reasons_are_operator_visible() {
    let health = IngestionHealth::default();
    health.record_capacity_rejection();
    health.record_peer_credential_error();
    health.record_listener_error();
    let snapshot = health.snapshot();
    assert_eq!(snapshot.connections_capacity_rejected_total, 1);
    assert_eq!(snapshot.peer_credential_errors_total, 1);
    assert_eq!(snapshot.listener_errors_total, 1);
}

#[test]
fn authenticated_producer_health_is_source_aware_bounded_and_operator_safe() {
    let db_path = temp_path("health.sqlite");
    drop(LocalStore::open(&db_path).expect("startup migration succeeds"));
    let config = config(temp_path("health.sock"), vec![1_234]);
    let health = IngestionHealth::default();
    health.record_listener_started();
    let report = serde_json::json!({
        "version": 1,
        "message_type": "producer_health",
        "checkpoint_bytes": 128,
        "backlog_bytes": 64,
        "backlog_age_ms": 250,
        "events_dropped_total": 2,
        "events_malformed_total": 1,
        "transport_state": "available"
    });

    let ack = exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&report).expect("report serializes")),
        &health,
    );
    assert!(ack.contains(r#""status":"health_recorded""#), "{ack}");

    let mut event: serde_json::Value =
        serde_json::from_str(CANONICAL_EVENT).expect("fixture parses");
    event["event_id"] = serde_json::json!("evt_health_visibility");
    let event_frame = frame(&serde_json::to_vec(&event).expect("event serializes"));
    exchange_with_health(1_234, &config, &db_path, &event_frame, &health);
    let status = health.status_json(Duration::from_secs(30));
    assert_eq!(status["state"], "degraded");
    assert_eq!(status["listener_live"], true);
    assert_eq!(
        status["sources"][0]["authenticated_uid"],
        nix::unistd::Uid::effective().as_raw()
    );
    assert_eq!(status["sources"][0]["producer_checkpoint_bytes"], 128);
    assert_eq!(status["sources"][0]["backlog_bytes"], 64);
    assert_eq!(status["sources"][0]["backlog_age_ms"], 250);
    assert_eq!(status["sources"][0]["events_dropped_total"], 2);
    assert_eq!(status["sources"][0]["events_malformed_total"], 1);
    assert!(status["sources"][0]["last_event_received_at_unix_ms"].is_u64());
    assert!(status["sources"][0]["last_event_committed_at_unix_ms"].is_u64());
    assert_eq!(status["hook_event_state"], "fresh");
    let serialized = status.to_string();
    for forbidden in ["events-v1.jsonl", "FAKE_SECRET", "/root/", "command"] {
        assert!(!serialized.contains(forbidden));
    }

    thread::sleep(Duration::from_millis(2));
    let stale = health.status_json(Duration::ZERO);
    assert_eq!(stale["state"], "degraded");
    assert_eq!(stale["hook_event_state"], "stale");
    assert_eq!(stale["sources"][0]["transport_state"], "stale");

    let _ = fs::remove_file(db_path);
}

#[test]
fn live_listener_without_a_producer_report_does_not_claim_end_to_end_health() {
    let health = IngestionHealth::default();
    health.record_listener_started();

    let status = health.status_json(Duration::from_secs(30));

    assert_eq!(status["state"], "degraded");
    assert_eq!(status["listener_live"], true);
    assert_eq!(status["sources"], serde_json::json!([]));
}

#[test]
fn transient_degradation_recovers_after_health_window_without_resetting_counters() {
    let db_path = temp_path("health-recovery.sqlite");
    let config = config(temp_path("health-recovery.sock"), vec![1_234]);
    let health = IngestionHealth::default();
    health.record_listener_started();
    let report = serde_json::json!({
        "version": 1,
        "message_type": "producer_health",
        "checkpoint_bytes": 128,
        "backlog_bytes": 0,
        "backlog_age_ms": null,
        "events_dropped_total": 0,
        "events_malformed_total": 0,
        "transport_state": "available"
    });
    exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&report).expect("report serializes")),
        &health,
    );
    assert_eq!(
        health.status_json(Duration::from_secs(30))["state"],
        "healthy"
    );

    health.record_capacity_rejection();
    assert_eq!(
        health.status_json(Duration::from_secs(30))["state"],
        "degraded"
    );
    thread::sleep(Duration::from_millis(40));
    exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&report).expect("report serializes")),
        &health,
    );
    let recovered = health.status_json(Duration::from_millis(30));
    assert_eq!(recovered["state"], "healthy");
    assert_eq!(recovered["connections_capacity_rejected_total"], 1);
}

#[test]
fn hostile_health_report_is_rejected_without_label_or_payload_leakage() {
    let db_path = temp_path("hostile-health.sqlite");
    let config = config(temp_path("hostile-health.sock"), vec![1_234]);
    let health = IngestionHealth::default();
    let report = serde_json::json!({
        "version": 1,
        "message_type": "producer_health",
        "checkpoint_bytes": 0,
        "backlog_bytes": 0,
        "backlog_age_ms": null,
        "events_dropped_total": 0,
        "events_malformed_total": 0,
        "transport_state": "available",
        "path": "/root/FAKE_SECRET"
    });

    let ack = exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&report).expect("report serializes")),
        &health,
    );
    assert!(ack.contains(r#""reason":"invalid_health""#), "{ack}");
    assert!(!health
        .status_json(Duration::from_secs(30))
        .to_string()
        .contains("FAKE_SECRET"));
}

#[test]
fn same_uid_roles_and_instances_are_distinct_and_required_gateway_is_self_reported() {
    let db_path = temp_path("runtime-roles.sqlite");
    let config = config(temp_path("runtime-roles.sock"), vec![1_234]);
    let health = IngestionHealth::with_required_reported_roles(vec![ProducerRole::Gateway]);
    health.record_listener_started();

    for instance in ["dash-a1", "dash-a2"] {
        let dashboard = health_report(2, Some("dashboard"), Some(instance));
        exchange_with_health(
            1_234,
            &config,
            &db_path,
            &frame(&serde_json::to_vec(&dashboard).unwrap()),
            &health,
        );
    }
    let dashboard_only = health.status_json(Duration::from_secs(30));
    assert_eq!(dashboard_only["state"], "degraded");
    assert_eq!(
        dashboard_only["required_reported_roles"][0]["state"],
        "absent"
    );

    let gateway = health_report(2, Some("gateway"), Some("gate-a1"));
    exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&gateway).unwrap()),
        &health,
    );
    let enrolled = health.status_json(Duration::from_secs(30));
    assert_eq!(enrolled["state"], "healthy");
    assert_eq!(
        enrolled["role_identity_assurance"],
        "authorized_uid_self_reported"
    );
    assert_eq!(enrolled["required_reported_roles"][0]["state"], "fresh");
    assert_eq!(enrolled["sources"].as_array().unwrap().len(), 3);
    let source_ids = enrolled["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|source| source["source_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(source_ids.len(), 3);
}

#[test]
fn legacy_health_is_observable_but_cannot_satisfy_explicit_role() {
    let db_path = temp_path("legacy-role.sqlite");
    let config = config(temp_path("legacy-role.sock"), vec![1_234]);
    let health = IngestionHealth::with_required_reported_roles(vec![ProducerRole::Gateway]);
    health.record_listener_started();
    let legacy = health_report(1, None, None);
    let ack = exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&legacy).unwrap()),
        &health,
    );
    assert!(ack.contains(r#""status":"health_recorded""#), "{ack}");
    let status = health.status_json(Duration::from_secs(30));
    assert_eq!(status["state"], "degraded");
    assert_eq!(status["sources"][0]["runtime_role"], "legacy");
    assert_eq!(status["required_reported_roles"][0]["state"], "absent");
}

#[test]
fn v3_health_and_event_share_exact_source_and_only_persist_advances_commit_sequence() {
    const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NONCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const COLLISION_NONCE: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let db_path = temp_path("v3-attribution.sqlite");
    drop(LocalStore::open(&db_path).expect("schema initializes"));
    let config = config(temp_path("v3-attribution.sock"), vec![1_234]);
    let health = IngestionHealth::with_required_reported_roles(vec![ProducerRole::Gateway]);
    health.record_listener_started();
    let report = v3_health("gateway", GENERATION, NONCE);
    let health_ack = exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&report).unwrap()),
        &health,
    );
    assert!(health_ack.contains("health_recorded"), "{health_ack}");
    let health_only = health.status_json(Duration::from_secs(30));
    assert_eq!(health_only["sources"][0]["s3_eligible"], true);
    assert_eq!(health_only["sources"][0]["events_persisted_total"], 0);

    let mut event: serde_json::Value = serde_json::from_str(CANONICAL_EVENT).unwrap();
    event["event_id"] = serde_json::json!("evt_v3_exact_source");
    let envelope = v3_event("gateway", GENERATION, NONCE, &event);
    let persisted = exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&envelope).unwrap()),
        &health,
    );
    assert!(persisted.contains(r#""status":"persisted""#), "{persisted}");
    let duplicate = exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&envelope).unwrap()),
        &health,
    );
    assert!(duplicate.contains(r#""status":"duplicate""#), "{duplicate}");
    let collision_envelope = v3_event("gateway", GENERATION, COLLISION_NONCE, &event);
    let collision = exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&collision_envelope).unwrap()),
        &health,
    );
    assert!(collision.contains(r#""status":"collision""#), "{collision}");

    let status = health.status_json(Duration::from_secs(30));
    assert_eq!(status["sources"].as_array().unwrap().len(), 2);
    let source = status["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["runtime_instance_nonce"] == NONCE)
        .unwrap();
    assert_eq!(source["protocol_version"], 3);
    assert_eq!(source["s3_eligible"], true);
    assert_eq!(source["plugin_generation"], GENERATION);
    assert_eq!(source["runtime_instance_nonce"], NONCE);
    assert_eq!(source["events_persisted_total"], 1);
    assert_eq!(source["commit_sequence"], 1);
    assert_eq!(source["events_duplicate_total"], 1);
    assert_eq!(source["events_collision_total"], 0);
    assert!(source["kernel_peer_pid"].is_i64());
    assert!(source["kernel_peer_start_ticks"].is_u64());
    assert!(source["last_event_received_at_unix_ms"].is_u64());
    assert!(source["last_event_committed_at_unix_ms"].is_u64());
    let collision_source = status["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["runtime_instance_nonce"] == COLLISION_NONCE)
        .unwrap();
    assert_eq!(collision_source["events_persisted_total"], 0);
    assert_eq!(collision_source["commit_sequence"], 0);
    assert_eq!(collision_source["events_collision_total"], 1);
    let _ = fs::remove_file(db_path);
}

#[test]
fn v3_event_only_source_is_not_s3_eligible_before_exact_health() {
    const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NONCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let db_path = temp_path("v3-event-only.sqlite");
    drop(LocalStore::open(&db_path).expect("schema initializes"));
    let config = config(temp_path("v3-event-only.sock"), vec![1_234]);
    let health = IngestionHealth::default();
    let mut event: serde_json::Value = serde_json::from_str(CANONICAL_EVENT).unwrap();
    event["event_id"] = serde_json::json!("evt_v3_before_health");
    let envelope = v3_event("gateway", GENERATION, NONCE, &event);

    let ack = exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&envelope).unwrap()),
        &health,
    );

    assert!(ack.contains(r#""status":"persisted""#), "{ack}");
    let status = health.status_json(Duration::from_secs(30));
    assert_eq!(status["sources"][0]["s3_eligible"], false);
    assert!(status["sources"][0]["producer_reported_at_unix_ms"].is_null());
    assert_eq!(status["sources"][0]["events_persisted_total"], 1);
    let report = v3_health("gateway", GENERATION, NONCE);
    let health_ack = exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&report).unwrap()),
        &health,
    );
    assert!(health_ack.contains("health_recorded"), "{health_ack}");
    let eligible = health.status_json(Duration::from_secs(30));
    assert_eq!(eligible["sources"][0]["s3_eligible"], true);
    assert_eq!(eligible["sources"][0]["events_persisted_total"], 1);
    let _ = fs::remove_file(db_path);
}

#[test]
fn v3_valid_identity_with_invalid_nested_event_is_attributed_to_exact_source() {
    const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NONCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let db_path = temp_path("v3-invalid-nested.sqlite");
    let config = config(temp_path("v3-invalid-nested.sock"), vec![1_234]);
    let health = IngestionHealth::default();
    let envelope = v3_event(
        "gateway",
        GENERATION,
        NONCE,
        &serde_json::json!({"schema_version":"not-canonical"}),
    );

    let ack = exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&envelope).unwrap()),
        &health,
    );

    assert!(ack.contains(r#""reason":"invalid_event""#), "{ack}");
    let status = health.status_json(Duration::from_secs(30));
    assert_eq!(status["sources"].as_array().unwrap().len(), 1);
    assert_eq!(status["sources"][0]["runtime_role"], "gateway");
    assert_eq!(status["sources"][0]["plugin_generation"], GENERATION);
    assert_eq!(status["sources"][0]["runtime_instance_nonce"], NONCE);
    assert_eq!(status["sources"][0]["events_malformed_total"], 1);
    assert_eq!(
        status["sources"][0]["last_error_category"],
        "malformed_frame"
    );
    assert!(!db_path.exists());
}

#[test]
fn v3_rejects_duplicate_keys_throughout_raw_nested_events_without_persistence() {
    const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NONCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let cases = [
        (
            "event_id",
            r#""event_id": "evt_01HZCANONICAL","#,
            r#""event_id": "evt_duplicate", "event_id": "evt_01HZCANONICAL","#,
        ),
        (
            "attributes",
            r#""attributes": {"#,
            r#""attributes": {}, "attributes": {"#,
        ),
        (
            "attribute metadata",
            r#""direct_ip": true"#,
            r#""direct_ip": false, "direct_ip": true"#,
        ),
        (
            "redaction metadata",
            r#""contains_sensitive_data": true,"#,
            r#""contains_sensitive_data": false, "contains_sensitive_data": true,"#,
        ),
        (
            "redaction array metadata",
            r#""path": "attributes.token","#,
            r#""path": "attributes.command", "path": "attributes.token","#,
        ),
        (
            "numeric field",
            r#""observed_at_unix_ms": 1781560000000,"#,
            r#""observed_at_unix_ms": 1, "observed_at_unix_ms": 1781560000000,"#,
        ),
    ];

    for (name, original, duplicate) in cases {
        let event = CANONICAL_EVENT.replacen(original, duplicate, 1);
        assert_ne!(event, CANONICAL_EVENT, "{name} fixture mutation");
        let db_path = temp_path(&format!("v3-duplicate-{name}.sqlite"));
        let config = config(temp_path(&format!("v3-duplicate-{name}.sock")), vec![1_234]);
        let health = IngestionHealth::default();
        let report = v3_health("gateway", GENERATION, NONCE);
        let health_ack = exchange_with_health(
            1_234,
            &config,
            &db_path,
            &frame(&serde_json::to_vec(&report).unwrap()),
            &health,
        );
        assert!(
            health_ack.contains("health_recorded"),
            "{name}: {health_ack}"
        );

        let ack = exchange_with_health(
            1_234,
            &config,
            &db_path,
            &frame(v3_event_raw(&event).as_bytes()),
            &health,
        );

        assert!(
            ack.contains(r#""status":"rejected_permanent""#)
                && ack.contains(r#""reason":"invalid_event""#),
            "{name}: {ack}"
        );
        let status = health.status_json(Duration::from_secs(30));
        assert_eq!(status["sources"].as_array().unwrap().len(), 1, "{name}");
        assert_eq!(status["sources"][0]["runtime_role"], "gateway", "{name}");
        assert_eq!(
            status["sources"][0]["plugin_generation"], GENERATION,
            "{name}"
        );
        assert_eq!(
            status["sources"][0]["runtime_instance_nonce"], NONCE,
            "{name}"
        );
        assert_eq!(status["sources"][0]["events_persisted_total"], 0, "{name}");
        assert_eq!(status["sources"][0]["commit_sequence"], 0, "{name}");
        assert_eq!(status["sources"][0]["events_malformed_total"], 1, "{name}");
        assert!(!db_path.exists(), "{name}");
    }
}

#[test]
fn v3_rejects_duplicate_envelope_identity_fields_without_source_success() {
    const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NONCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let event = v3_event_raw(CANONICAL_EVENT);
    let event_cases = [
        event.replacen(
            r#""runtime_role":"gateway""#,
            r#""runtime_role":"gateway","runtime_role":"gateway""#,
            1,
        ),
        event.replacen(
            &format!(r#""plugin_generation":"{GENERATION}""#),
            &format!(r#""plugin_generation":"{GENERATION}","plugin_generation":"{GENERATION}""#),
            1,
        ),
        event.replacen(
            &format!(r#""runtime_instance_nonce":"{NONCE}""#),
            &format!(r#""runtime_instance_nonce":"{NONCE}","runtime_instance_nonce":"{NONCE}""#),
            1,
        ),
    ];
    let health = format!(
        r#"{{"version":3,"message_type":"producer_health","runtime_role":"gateway","plugin_generation":"{GENERATION}","runtime_instance_nonce":"{NONCE}","checkpoint_bytes":0,"backlog_bytes":0,"backlog_age_ms":null,"events_dropped_total":0,"events_malformed_total":0,"transport_state":"available"}}"#
    );
    let health_cases = [
        health.replacen(
            r#""runtime_role":"gateway""#,
            r#""runtime_role":"gateway","runtime_role":"gateway""#,
            1,
        ),
        health.replacen(
            &format!(r#""plugin_generation":"{GENERATION}""#),
            &format!(r#""plugin_generation":"{GENERATION}","plugin_generation":"{GENERATION}""#),
            1,
        ),
        health.replacen(
            &format!(r#""runtime_instance_nonce":"{NONCE}""#),
            &format!(r#""runtime_instance_nonce":"{NONCE}","runtime_instance_nonce":"{NONCE}""#),
            1,
        ),
    ];

    for (kind, cases, reason) in [
        ("event", event_cases.as_slice(), "invalid_event"),
        ("health", health_cases.as_slice(), "invalid_health"),
    ] {
        for (index, envelope) in cases.iter().enumerate() {
            let db_path = temp_path(&format!("v3-duplicate-{kind}-identity-{index}.sqlite"));
            let config = config(
                temp_path(&format!("v3-duplicate-{kind}-identity-{index}.sock")),
                vec![1_234],
            );
            let source_health = IngestionHealth::default();
            let ack = exchange_with_health(
                1_234,
                &config,
                &db_path,
                &frame(envelope.as_bytes()),
                &source_health,
            );
            assert!(
                ack.contains(r#""status":"rejected_permanent""#) && ack.contains(reason),
                "{kind} {index}: {ack}"
            );
            assert_eq!(source_health.snapshot().events_persisted_total, 0);
            assert!(
                source_health.status_json(Duration::from_secs(30))["sources"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|source| source["s3_eligible"] == false)
            );
            assert!(!db_path.exists(), "{kind} {index}");
        }
    }
}

#[test]
fn v3_rejects_noncanonical_or_reused_identity_and_unknown_fields_without_leakage() {
    const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NONCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let db_path = temp_path("v3-hostile.sqlite");
    let config = config(temp_path("v3-hostile.sock"), vec![1_234]);
    let health = IngestionHealth::default();
    let mut cases = vec![
        v3_health("gateway", "A", NONCE),
        v3_health("gateway", GENERATION, "b"),
        v3_health("gateway", GENERATION, GENERATION),
    ];
    let mut unknown = v3_health("gateway", GENERATION, NONCE);
    unknown["path"] = serde_json::json!("/root/FAKE_V3_SECRET");
    cases.push(unknown);
    for report in cases {
        let ack = exchange_with_health(
            1_234,
            &config,
            &db_path,
            &frame(&serde_json::to_vec(&report).unwrap()),
            &health,
        );
        assert!(ack.contains(r#""reason":"invalid_health""#), "{ack}");
    }
    let mut event: serde_json::Value = serde_json::from_str(CANONICAL_EVENT).unwrap();
    event["event_id"] = serde_json::json!("evt_v3_unknown_field");
    let mut envelope = v3_event("gateway", GENERATION, NONCE, &event);
    envelope["payload_path"] = serde_json::json!("/root/FAKE_V3_EVENT_SECRET");
    let ack = exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&envelope).unwrap()),
        &health,
    );
    assert!(ack.contains(r#""reason":"invalid_event""#), "{ack}");
    let serialized = health.status_json(Duration::from_secs(30)).to_string();
    assert!(!serialized.contains("FAKE_V3_SECRET"));
    assert!(!serialized.contains("FAKE_V3_EVENT_SECRET"));
    assert!(!db_path.exists());
}

#[test]
fn v1_v2_and_raw_sources_are_visible_but_explicitly_s3_ineligible() {
    let db_path = temp_path("legacy-eligibility.sqlite");
    drop(LocalStore::open(&db_path).expect("schema initializes"));
    let config = config(temp_path("legacy-eligibility.sock"), vec![1_234]);
    let health = IngestionHealth::default();
    for report in [
        health_report(1, None, None),
        health_report(2, Some("gateway"), Some("gateway-v2")),
    ] {
        exchange_with_health(
            1_234,
            &config,
            &db_path,
            &frame(&serde_json::to_vec(&report).unwrap()),
            &health,
        );
    }
    let mut event: serde_json::Value = serde_json::from_str(CANONICAL_EVENT).unwrap();
    event["event_id"] = serde_json::json!("evt_raw_legacy_visibility");
    exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&event).unwrap()),
        &health,
    );
    let status = health.status_json(Duration::from_secs(30));
    assert_eq!(status["sources"].as_array().unwrap().len(), 2);
    assert!(status["sources"]
        .as_array()
        .unwrap()
        .iter()
        .all(|source| source["s3_eligible"] == false));
    let _ = fs::remove_file(db_path);
}

#[test]
fn heartbeat_and_hook_event_freshness_are_separate_and_required_role_stales() {
    let db_path = temp_path("freshness.sqlite");
    let config = config(temp_path("freshness.sock"), vec![1_234]);
    let health = IngestionHealth::with_required_reported_roles(vec![ProducerRole::Gateway]);
    health.record_listener_started();
    let gateway = health_report(2, Some("gateway"), Some("gate-a1"));
    exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&gateway).unwrap()),
        &health,
    );
    let fresh = health.status_json(Duration::from_secs(30));
    assert_eq!(fresh["transport_heartbeat_state"], "fresh");
    assert_eq!(fresh["hook_event_state"], "not_observed");
    assert!(fresh["last_event_received_at_unix_ms"].is_null());
    thread::sleep(Duration::from_millis(2));
    let stale = health.status_json(Duration::ZERO);
    assert_eq!(stale["state"], "degraded");
    assert_eq!(stale["required_reported_roles"][0]["state"], "stale");
    assert_eq!(stale["transport_heartbeat_state"], "stale");
    assert_eq!(stale["hook_event_state"], "not_observed");
}

#[test]
fn hostile_v2_attribution_is_rejected_and_instances_remain_independent() {
    let db_path = temp_path("v2-bounds.sqlite");
    let config = config(temp_path("v2-bounds.sock"), vec![1_234]);
    let health = IngestionHealth::default();
    for invalid in [
        health_report(2, Some("gateway/../../secret"), Some("gate-a1")),
        health_report(2, Some("gateway"), Some("/proc/self/cmdline")),
        health_report(2, Some("other"), Some("safe-a1")),
    ] {
        let ack = exchange_with_health(
            1_234,
            &config,
            &db_path,
            &frame(&serde_json::to_vec(&invalid).unwrap()),
            &health,
        );
        assert!(ack.contains(r#""reason":"invalid_health""#), "{ack}");
    }
    for instance in ["gate-old", "gate-new"] {
        let report = health_report(2, Some("gateway"), Some(instance));
        exchange_with_health(
            1_234,
            &config,
            &db_path,
            &frame(&serde_json::to_vec(&report).unwrap()),
            &health,
        );
    }
    let status = health.status_json(Duration::from_secs(30));
    assert_eq!(status["sources"].as_array().unwrap().len(), 2);
    assert!(status.to_string().contains("gate-old"));
    assert!(status.to_string().contains("gate-new"));
    assert!(!status.to_string().contains("cmdline"));
}

#[test]
fn v3_source_cap_applies_to_exact_identities_and_existing_identity_can_refresh() {
    let db_path = temp_path("source-cap.sqlite");
    let config = config(temp_path("source-cap.sock"), vec![1_000]);
    let health = IngestionHealth::default();
    for index in 0..64 {
        let report = v3_health("worker", &format!("{index:064x}"), &"f".repeat(64));
        let ack = exchange_with_health(
            1_000,
            &config,
            &db_path,
            &frame(&serde_json::to_vec(&report).unwrap()),
            &health,
        );
        assert!(ack.contains(r#""status":"health_recorded""#), "{ack}");
    }
    let overflow = v3_health("gateway", &format!("{:064x}", 64), &"f".repeat(64));
    let rejected = exchange_with_health(
        1_000,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&overflow).unwrap()),
        &health,
    );
    assert!(
        rejected.contains(r#""reason":"source_capacity""#),
        "{rejected}"
    );

    let existing = v3_health("worker", &format!("{:064x}", 0), &"f".repeat(64));
    let accepted = exchange_with_health(
        1_000,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&existing).unwrap()),
        &health,
    );
    assert!(
        accepted.contains(r#""status":"health_recorded""#),
        "{accepted}"
    );
    assert_eq!(
        health.status_json(Duration::from_secs(30))["sources"]
            .as_array()
            .unwrap()
            .len(),
        64
    );
}

#[test]
fn stale_optional_instance_stays_visible_without_poisoning_fresh_required_gateway() {
    let db_path = temp_path("optional-stale.sqlite");
    let config = config(temp_path("optional-stale.sock"), vec![1_234]);
    let health = IngestionHealth::with_required_reported_roles_and_retention(
        vec![ProducerRole::Gateway],
        Duration::from_millis(50),
    );
    health.record_listener_started();
    let mut worker = health_report(2, Some("worker"), Some("worker-old"));
    worker["transport_state"] = serde_json::json!("degraded");
    worker["backlog_bytes"] = serde_json::json!(1);
    exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&worker).unwrap()),
        &health,
    );
    thread::sleep(Duration::from_millis(3));
    let gateway = health_report(2, Some("gateway"), Some("gateway-live"));
    exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&gateway).unwrap()),
        &health,
    );

    let status = health.status_json(Duration::from_millis(1));
    assert_eq!(status["state"], "healthy");
    assert_eq!(status["required_reported_roles"][0]["state"], "fresh");
    assert_eq!(status["sources"].as_array().unwrap().len(), 2);
    assert!(status["sources"]
        .as_array()
        .unwrap()
        .iter()
        .any(|source| source["transport_state"] == "stale"));
}

#[test]
fn stale_v3_identity_retention_evicts_before_capacity_is_consumed_forever() {
    let db_path = temp_path("source-eviction.sqlite");
    let config = config(temp_path("source-eviction.sock"), vec![1_234]);
    let health = IngestionHealth::with_required_reported_roles_and_retention(
        Vec::new(),
        Duration::from_millis(1),
    );
    let old = v3_health("worker", &"a".repeat(64), &"b".repeat(64));
    exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&old).unwrap()),
        &health,
    );
    thread::sleep(Duration::from_millis(3));
    let current = v3_health("worker", &"c".repeat(64), &"d".repeat(64));
    exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&current).unwrap()),
        &health,
    );

    let status = health.status_json(Duration::from_secs(30));
    assert_eq!(status["sources"].as_array().unwrap().len(), 1);
    assert_eq!(status["sources"][0]["plugin_generation"], "c".repeat(64));
}

#[test]
fn runtime_health_resets_while_persisted_store_survives_restart() {
    let db_path = temp_path("restart-health.sqlite");
    drop(LocalStore::open(&db_path).expect("store initializes"));
    let config = config(temp_path("restart-health.sock"), vec![1_234]);
    let health = IngestionHealth::default();
    let mut event: serde_json::Value = serde_json::from_str(CANONICAL_EVENT).unwrap();
    event["event_id"] = serde_json::json!("evt_restart_health");
    exchange_with_health(
        1_234,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&event).unwrap()),
        &health,
    );
    assert_eq!(health.snapshot().events_persisted_total, 1);
    let restarted = IngestionHealth::default();
    assert_eq!(restarted.snapshot().events_persisted_total, 0);
    assert!(
        restarted.status_json(Duration::from_secs(30))["last_event_committed_at_unix_ms"].is_null()
    );
    assert!(LocalStore::open_read_only(&db_path)
        .unwrap()
        .get_event("evt_restart_health")
        .unwrap()
        .is_some());
    let _ = fs::remove_file(db_path);
}

#[test]
fn daemon_config_starts_continuous_listener_without_opening_historical_spool() {
    let root = temp_path("daemon-live");
    fs::create_dir_all(&root).expect("root created");
    let socket_path = root.join("ingest.sock");
    let historical = root.join("events.jsonl");
    fs::write(&historical, "HISTORICAL_SENTINEL_MUST_NOT_BE_OPENED\n")
        .expect("historical sentinel written");
    let before = fs::metadata(&historical)
        .expect("historical metadata")
        .modified()
        .expect("historical mtime");
    let uid = nix::unistd::Uid::effective().as_raw();
    let allow_root = uid == 0;
    let allowed = if allow_root {
        String::new()
    } else {
        uid.to_string()
    };
    let config_path = root.join("config.toml");
    fs::write(
        &config_path,
        format!(
            r#"mode = "passive"
data_dir = "{}"

[http_api]
enabled = false
bind = "127.0.0.1:8787"
read_only = true

[sensors]
linux_privileged = false

[ingest]
enabled = true
socket = "{}"
allow_root = {}
allowed_uids = [{}]
max_frame_bytes = 262144
read_timeout_ms = 200
write_timeout_ms = 200
candidate_limit = 10000
"#,
            root.display(),
            socket_path.display(),
            allow_root,
            allowed
        ),
    )
    .expect("config written");
    let mut child = Command::new(env!("CARGO_BIN_EXE_skynet-edr-daemon"))
        .arg("run")
        .arg("--config")
        .arg(&config_path)
        .spawn()
        .expect("daemon starts");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket_path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        socket_path.exists(),
        "continuous ingestion socket was not created"
    );

    let mut event: serde_json::Value =
        serde_json::from_str(CANONICAL_EVENT).expect("fixture parses");
    event["event_id"] = serde_json::json!("evt_unix_daemon_live");
    let mut client = UnixStream::connect(&socket_path).expect("producer connects");
    client
        .write_all(&frame(
            &serde_json::to_vec(&event).expect("event serializes"),
        ))
        .expect("frame writes");
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("frame completes");
    let mut ack = String::new();
    client.read_to_string(&mut ack).expect("ack reads");
    assert!(ack.contains(r#""status":"persisted""#), "{ack}");
    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(
        fs::read_to_string(&historical).expect("historical sentinel remains"),
        "HISTORICAL_SENTINEL_MUST_NOT_BE_OPENED\n"
    );
    assert_eq!(
        fs::metadata(&historical)
            .expect("historical metadata")
            .modified()
            .expect("historical mtime"),
        before
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn unix_exfil_ack_after_atomic_visibility() {
    let db_path = temp_path("p1a-exfil-visibility.sqlite");
    drop(LocalStore::open(&db_path).expect("schema initializes"));
    let config = config(temp_path("p1a-exfil-visibility.sock"), vec![1_301]);
    let mut precursor_attrs = p1a_request_attributes("read_file");
    precursor_attrs["sensitive_access"] = serde_json::json!(true);
    let precursor = p1a_event(
        "evt_p1a_unix_26_a",
        "agent.tool.requested",
        "file",
        "agent_action",
        1_781_600_000_000,
        "FAKE_UNIX_TRACE_26",
        precursor_attrs,
    );
    let mut successor_attrs = p1a_request_attributes("terminal");
    successor_attrs["network_indicator"] = serde_json::json!(true);
    successor_attrs["command_class"] = serde_json::json!("network_egress");
    let successor = p1a_event(
        "evt_p1a_unix_26_b",
        "agent.tool.requested",
        "process",
        "agent_action",
        1_781_600_000_001,
        "FAKE_UNIX_TRACE_26",
        successor_attrs,
    );
    assert!(p1a_exchange(1_301, &config, &db_path, &precursor).contains("persisted"));
    let ack = p1a_exchange(1_301, &config, &db_path, &successor);
    assert!(ack.contains("persisted"), "{ack}");
    let visible = LocalStore::open_read_only(&db_path).unwrap();
    assert_eq!(visible.count_ingest_receipts().unwrap(), 2);
    assert!(visible
        .list_incidents()
        .unwrap()
        .iter()
        .any(|incident| incident.id.as_str().contains("EDR-EXFIL-001")));
    let _ = fs::remove_file(db_path);
}

#[test]
fn unix_malware_ack_after_atomic_visibility() {
    let db_path = temp_path("p1a-malware-visibility.sqlite");
    drop(LocalStore::open(&db_path).expect("schema initializes"));
    let config = config(temp_path("p1a-malware-visibility.sock"), vec![1_302]);
    let event = p1a_event(
        "evt_p1a_unix_27",
        "agent.tool.completed",
        "mcp_tool",
        "tool_output",
        1_781_600_000_000,
        "FAKE_UNIX_TRACE_27",
        serde_json::json!({
            "hook":"post_tool_call","tool_name":"remote.fetch","result_omitted":true,
            "result_length":0,"network_indicator":false,"direct_ip":false,
            "delivery_indicator":false,"sensitive_access":false,
            "prompt_injection_indicator":false,"malware_indicator":true,
            "malware_signature":"eicar_test_string"
        }),
    );
    let ack = p1a_exchange(1_302, &config, &db_path, &event);
    assert!(ack.contains("persisted"), "{ack}");
    let visible = LocalStore::open_read_only(&db_path).unwrap();
    assert_eq!(visible.count_ingest_receipts().unwrap(), 1);
    assert!(visible
        .list_incidents()
        .unwrap()
        .iter()
        .any(|incident| incident.id.as_str().contains("EDR-MALWARE-001")));
    let _ = fs::remove_file(db_path);
}

#[test]
fn unix_derived_incident_failure_returns_retry_later() {
    let db_path = temp_path("p1a-incident-failure.sqlite");
    drop(LocalStore::open(&db_path).expect("schema initializes"));
    let config = config(temp_path("p1a-incident-failure.sock"), vec![1_303]);
    let mut precursor_attrs = p1a_request_attributes("read_file");
    precursor_attrs["sensitive_access"] = serde_json::json!(true);
    let precursor = p1a_event(
        "evt_p1a_unix_28_a",
        "agent.tool.requested",
        "file",
        "agent_action",
        1_781_600_000_000,
        "FAKE_UNIX_TRACE_28",
        precursor_attrs,
    );
    assert!(p1a_exchange(1_303, &config, &db_path, &precursor).contains("persisted"));
    rusqlite::Connection::open(&db_path).unwrap().execute_batch("CREATE TRIGGER p1a_unix_fail BEFORE INSERT ON incidents BEGIN SELECT RAISE(FAIL, 'forced unix p1a incident failure'); END;").unwrap();
    let mut successor_attrs = p1a_request_attributes("terminal");
    successor_attrs["network_indicator"] = serde_json::json!(true);
    successor_attrs["command_class"] = serde_json::json!("network_egress");
    let successor = p1a_event(
        "evt_p1a_unix_28_b",
        "agent.tool.requested",
        "process",
        "agent_action",
        1_781_600_000_001,
        "FAKE_UNIX_TRACE_28",
        successor_attrs,
    );
    let ack = p1a_exchange(1_303, &config, &db_path, &successor);
    assert!(ack.contains("retry_later"), "{ack}");
    let visible = LocalStore::open_read_only(&db_path).unwrap();
    assert!(visible.get_event("evt_p1a_unix_28_b").unwrap().is_none());
    assert_eq!(visible.count_ingest_receipts().unwrap(), 1);
    let _ = fs::remove_file(db_path);
}

#[test]
fn unix_incident_collision_is_terminal_visible_and_atomic() {
    let db_path = temp_path("p1a-incident-collision.sqlite");
    let oracle_path = temp_path("p1a-incident-collision-oracle.sqlite");
    drop(LocalStore::open(&db_path).expect("schema initializes"));
    drop(LocalStore::open(&oracle_path).expect("oracle schema initializes"));
    let config = config(temp_path("p1a-incident-collision.sock"), vec![1_306]);
    let mut precursor_attrs = p1a_request_attributes("read_file");
    precursor_attrs["sensitive_access"] = serde_json::json!(true);
    let precursor = p1a_event(
        "evt_p1a_unix_collision_a",
        "agent.tool.requested",
        "file",
        "agent_action",
        1_781_600_000_000,
        "FAKE_UNIX_TRACE_COLLISION",
        precursor_attrs,
    );
    let mut successor_attrs = p1a_request_attributes("terminal");
    successor_attrs["network_indicator"] = serde_json::json!(true);
    successor_attrs["command_class"] = serde_json::json!("network_egress");
    let successor = p1a_event(
        "evt_p1a_unix_collision_b",
        "agent.tool.requested",
        "process",
        "agent_action",
        1_781_600_000_001,
        "FAKE_UNIX_TRACE_COLLISION",
        successor_attrs,
    );
    for path in [&db_path, &oracle_path] {
        assert!(p1a_exchange(1_306, &config, path, &precursor).contains("persisted"));
    }
    assert!(p1a_exchange(1_306, &config, &oracle_path, &successor).contains("persisted"));
    let incident_id = LocalStore::open_read_only(&oracle_path)
        .unwrap()
        .list_incidents()
        .unwrap()
        .into_iter()
        .find(|incident| incident.id.as_str().contains("EDR-EXFIL-001"))
        .unwrap()
        .id;
    rusqlite::Connection::open(&db_path).unwrap().execute(
        "INSERT INTO incidents (id,created_at_unix_ms,updated_at_unix_ms,status,severity,title,payload_json)
         VALUES (?1,0,0,'open','high','collision','{}')", [incident_id.as_str()],
    ).unwrap();

    let health = IngestionHealth::default();
    let ack = exchange_with_health(
        1_306,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&successor).unwrap()),
        &health,
    );
    assert!(ack.contains(r#""status":"rejected_permanent""#), "{ack}");
    assert!(ack.contains(r#""reason":"incident_collision""#), "{ack}");
    let visible = LocalStore::open_read_only(&db_path).unwrap();
    assert!(visible
        .get_event("evt_p1a_unix_collision_b")
        .unwrap()
        .is_none());
    assert_eq!(visible.count_ingest_receipts().unwrap(), 1);
    assert_eq!(visible.count_incidents().unwrap(), 1);
    assert_eq!(visible.count_incident_collision_diagnostics().unwrap(), 1);
    assert_eq!(health.snapshot().incident_integrity_collision_total, 1);
    let status = health.status_json(Duration::from_secs(30));
    assert_eq!(status["incident_integrity_collision_total"], 1);
    assert_eq!(
        status["sources"][0]["last_error_category"],
        "incident_collision"
    );
    let diagnostics = rusqlite::Connection::open(&db_path)
        .unwrap()
        .query_row(
            "SELECT diagnostic_id || ' ' || incident_fingerprint || ' ' || source_fingerprint
         FROM incident_collision_diagnostics",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    for raw in [
        incident_id.as_str(),
        "evt_p1a_unix_collision_a",
        "evt_p1a_unix_collision_b",
        "FAKE_UNIX_TRACE_COLLISION",
        "uid:1306",
    ] {
        assert!(!diagnostics.contains(raw), "raw marker leaked: {raw}");
    }
    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(oracle_path);
}

#[test]
fn unix_incident_collision_diagnostic_failure_returns_retry_later() {
    let db_path = temp_path("p1a-incident-collision-diagnostic-failure.sqlite");
    let oracle_path = temp_path("p1a-incident-collision-diagnostic-failure-oracle.sqlite");
    drop(LocalStore::open(&db_path).expect("schema initializes"));
    drop(LocalStore::open(&oracle_path).expect("oracle schema initializes"));
    let config = config(
        temp_path("p1a-incident-collision-diagnostic-failure.sock"),
        vec![1_307],
    );
    let mut precursor_attrs = p1a_request_attributes("read_file");
    precursor_attrs["sensitive_access"] = serde_json::json!(true);
    let precursor = p1a_event(
        "evt_p1a_unix_collision_fail_a",
        "agent.tool.requested",
        "file",
        "agent_action",
        1_781_600_000_000,
        "FAKE_UNIX_TRACE_COLLISION_FAIL",
        precursor_attrs,
    );
    let mut successor_attrs = p1a_request_attributes("terminal");
    successor_attrs["network_indicator"] = serde_json::json!(true);
    successor_attrs["command_class"] = serde_json::json!("network_egress");
    let successor = p1a_event(
        "evt_p1a_unix_collision_fail_b",
        "agent.tool.requested",
        "process",
        "agent_action",
        1_781_600_000_001,
        "FAKE_UNIX_TRACE_COLLISION_FAIL",
        successor_attrs,
    );
    for path in [&db_path, &oracle_path] {
        assert!(p1a_exchange(1_307, &config, path, &precursor).contains("persisted"));
    }
    assert!(p1a_exchange(1_307, &config, &oracle_path, &successor).contains("persisted"));
    let incident_id = LocalStore::open_read_only(&oracle_path)
        .unwrap()
        .list_incidents()
        .unwrap()
        .into_iter()
        .find(|incident| incident.id.as_str().contains("EDR-EXFIL-001"))
        .unwrap()
        .id;
    let connection = rusqlite::Connection::open(&db_path).unwrap();
    connection.execute(
        "INSERT INTO incidents (id,created_at_unix_ms,updated_at_unix_ms,status,severity,title,payload_json)
         VALUES (?1,0,0,'open','high','collision','{}')", [incident_id.as_str()],
    ).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_incident_collision_diagnostic
         BEFORE INSERT ON incident_collision_diagnostics
         BEGIN SELECT RAISE(FAIL, 'forced incident collision diagnostic failure'); END;",
        )
        .unwrap();
    let ack = p1a_exchange(1_307, &config, &db_path, &successor);
    assert!(ack.contains(r#""status":"retry_later""#), "{ack}");
    let visible = LocalStore::open_read_only(&db_path).unwrap();
    assert!(visible
        .get_event("evt_p1a_unix_collision_fail_b")
        .unwrap()
        .is_none());
    assert_eq!(visible.count_ingest_receipts().unwrap(), 1);
    assert_eq!(visible.count_incidents().unwrap(), 1);
    assert_eq!(visible.count_incident_collision_diagnostics().unwrap(), 0);
    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(oracle_path);
}

#[test]
fn unix_different_v3_source_keys_do_not_correlate() {
    const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FIRST_NONCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SECOND_NONCE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let db_path = temp_path("p1a-uid-isolation.sqlite");
    drop(LocalStore::open(&db_path).expect("schema initializes"));
    let config = config(temp_path("p1a-uid-isolation.sock"), vec![1_304, 2_304]);
    let mut precursor_attrs = p1a_request_attributes("read_file");
    precursor_attrs["sensitive_access"] = serde_json::json!(true);
    let precursor = p1a_event(
        "evt_p1a_unix_29_a",
        "agent.tool.requested",
        "file",
        "agent_action",
        1_781_600_000_000,
        "FAKE_UNIX_TRACE_29",
        precursor_attrs,
    );
    let mut successor_attrs = p1a_request_attributes("terminal");
    successor_attrs["network_indicator"] = serde_json::json!(true);
    successor_attrs["command_class"] = serde_json::json!("network_egress");
    let successor = p1a_event(
        "evt_p1a_unix_29_b",
        "agent.tool.requested",
        "process",
        "agent_action",
        1_781_600_000_001,
        "FAKE_UNIX_TRACE_29",
        successor_attrs,
    );
    let first = v3_event("gateway", GENERATION, FIRST_NONCE, &precursor);
    let second = v3_event("gateway", GENERATION, SECOND_NONCE, &successor);
    assert!(exchange(
        1_304,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&first).unwrap())
    )
    .contains("persisted"));
    assert!(exchange(
        2_304,
        &config,
        &db_path,
        &frame(&serde_json::to_vec(&second).unwrap())
    )
    .contains("persisted"));
    assert!(LocalStore::open_read_only(&db_path)
        .unwrap()
        .list_incidents()
        .unwrap()
        .iter()
        .all(|incident| !incident.id.as_str().contains("EDR-EXFIL-001")));
    let _ = fs::remove_file(db_path);
}

#[test]
fn unix_invalid_event_is_permanently_rejected_before_storage() {
    let db_path = temp_path("p1a-invalid.sqlite");
    drop(LocalStore::open(&db_path).expect("schema initializes"));
    let config = config(temp_path("p1a-invalid.sock"), vec![1_305]);
    let mut attrs = p1a_request_attributes("terminal");
    attrs["raw_command"] = serde_json::json!("FAKE_RAW_UNIX_30");
    let invalid = p1a_event(
        "evt_p1a_unix_30",
        "agent.tool.requested",
        "process",
        "agent_action",
        1_781_600_000_000,
        "FAKE_UNIX_TRACE_30",
        attrs,
    );
    let ack = p1a_exchange(1_305, &config, &db_path, &invalid);
    assert!(ack.contains("rejected_permanent"), "{ack}");
    let visible = LocalStore::open_read_only(&db_path).unwrap();
    assert_eq!(visible.count_events().unwrap(), 0);
    assert_eq!(visible.count_incidents().unwrap(), 0);
    assert_eq!(visible.count_ingest_receipts().unwrap(), 0);
    let _ = fs::remove_file(db_path);
}
