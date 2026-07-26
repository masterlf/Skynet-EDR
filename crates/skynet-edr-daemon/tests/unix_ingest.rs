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

fn exchange(uid: u32, config: UnixIngestConfig, db_path: PathBuf, bytes: &[u8]) -> String {
    let health = IngestionHealth::default();
    let (mut client, server) = UnixStream::pair().expect("stream pair opens");
    let worker =
        thread::spawn(move || process_ingest_connection(server, uid, &config, &db_path, &health));
    client.write_all(bytes).expect("request writes");
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("request completes");
    let mut ack = String::new();
    client.read_to_string(&mut ack).expect("ack reads");
    worker
        .join()
        .expect("worker joins")
        .expect("connection handled");
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

    let first = exchange(1_234, config.clone(), db_path.clone(), &frame(&payload));
    assert!(first.contains(r#""status":"persisted""#), "{first}");
    assert!(LocalStore::open_read_only(&db_path)
        .expect("store opens read-only")
        .get_event("evt_unix_ingest_commit")
        .expect("event lookup succeeds")
        .is_some());

    let replay = exchange(1_234, config, db_path.clone(), &frame(&payload));
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

    let zero = exchange(1_234, config.clone(), db_path.clone(), &0_u32.to_be_bytes());
    assert!(zero.contains(r#""status":"rejected_permanent""#));
    let oversize = exchange(
        1_234,
        config.clone(),
        db_path.clone(),
        &33_u32.to_be_bytes(),
    );
    assert!(oversize.contains(r#""reason":"frame_size""#));
    let malformed = exchange(1_234, config.clone(), db_path.clone(), &frame(b"not-json"));
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
