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
    bind_ingest_listener, process_ingest_connection, IngestionHealth, UnixIngestConfig,
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
    }
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut framed = u32::try_from(payload.len())
        .expect("test payload length fits")
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(payload);
    framed
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
    process_ingest_connection(server, uid, config, db_path, health).expect("connection handled");
    let mut ack = String::new();
    client.read_to_string(&mut ack).expect("ack reads");
    ack
}

#[test]
fn authorized_frame_is_acked_only_after_atomic_visibility_and_replay_is_duplicate() {
    let db_path = temp_path("commit.sqlite");
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
fn collision_ack_is_explicit_only_after_durable_evidence() {
    let db_path = temp_path("collision.sqlite");
    let config = config(temp_path("collision.sock"), vec![1_234, 2_345]);
    let mut event: serde_json::Value =
        serde_json::from_str(CANONICAL_EVENT).expect("fixture parses");
    event["event_id"] = serde_json::json!("evt_unix_collision");
    let first_payload = serde_json::to_vec(&event).expect("event serializes");
    let health = IngestionHealth::default();
    assert!(
        exchange_with_health(1_234, &config, &db_path, &frame(&first_payload), &health,)
            .contains(r#""status":"persisted""#)
    );
    event["title"] = serde_json::json!("FAKE_COLLISION_PAYLOAD_MUST_NOT_PERSIST");
    let collision_payload = serde_json::to_vec(&event).expect("collision serializes");

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
    assert_eq!(status["sources"][1]["source_id"], "uid:2345");
    assert!(status["sources"][1]["last_event_committed_at_unix_ms"].is_null());
    assert_eq!(status["sources"][1]["events_collision_total"], 1);
    let _ = fs::remove_file(db_path);
}

#[test]
fn unauthorized_peer_is_rejected_before_payload_read() {
    let db_path = temp_path("unauthorized.sqlite");
    let health = IngestionHealth::default();
    let config = config(temp_path("unauthorized.sock"), vec![1_234]);
    let (mut client, server) = UnixStream::pair().expect("stream pair opens");

    let started = Instant::now();
    process_ingest_connection(server, 9_999, &config, &db_path, &health)
        .expect("unauthorized connection is handled");
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
    process_ingest_connection(slow_server, 1_234, &config, &db_path, &health)
        .expect("slow frame timeout is isolated");
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

    process_ingest_connection(server, 1_234, &config, &db_path, &health)
        .expect("slow-drip frame is isolated");
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
    assert_eq!(status["sources"][0]["source_id"], "uid:1234");
    assert_eq!(status["sources"][0]["producer_checkpoint_bytes"], 128);
    assert_eq!(status["sources"][0]["backlog_bytes"], 64);
    assert_eq!(status["sources"][0]["backlog_age_ms"], 250);
    assert_eq!(status["sources"][0]["events_dropped_total"], 2);
    assert_eq!(status["sources"][0]["events_malformed_total"], 1);
    assert!(status["sources"][0]["last_event_received_at_unix_ms"].is_u64());
    assert!(status["sources"][0]["last_event_committed_at_unix_ms"].is_u64());
    let serialized = status.to_string();
    for forbidden in ["events-v1.jsonl", "FAKE_SECRET", "/root/", "command"] {
        assert!(!serialized.contains(forbidden));
    }

    thread::sleep(Duration::from_millis(2));
    let stale = health.status_json(Duration::ZERO);
    assert_eq!(stale["state"], "degraded");
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
