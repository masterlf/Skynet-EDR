//! Live canonical JSONL spool ingestion regression tests.

use std::{fs, path::PathBuf};

use skynet_edr_core::{ingest_canonical_jsonl_spool, LocalStore};

const CANONICAL_EVENT: &str = include_str!("fixtures/canonical_event_v0.json");

fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "skynet-edr-core-spool-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    ));
    path
}

fn variant_event(id: &str, title: &str) -> String {
    let mut value: serde_json::Value = serde_json::from_str(CANONICAL_EVENT).expect("fixture JSON");
    value["event_id"] = serde_json::json!(id);
    value["title"] = serde_json::json!(title);
    serde_json::to_string(&value).expect("variant serializes")
}

#[test]
fn live_spool_ingestion_skips_malformed_lines_and_counts_dropped_events() {
    let db_path = temp_path("malformed.sqlite");
    let spool_path = temp_path("malformed.jsonl");
    let checkpoint_path = temp_path("malformed.offset");
    let good_event = variant_event("evt_spool_good", "Spool accepted canonical event");
    fs::write(&spool_path, format!("{good_event}\n{{not-json\n\n")).expect("spool is written");

    let store = LocalStore::open(&db_path).expect("store opens");
    let summary = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("malformed lines are accounted, not fatal");

    assert_eq!(summary.ingested_events, 1);
    assert_eq!(summary.dropped_events, 1);
    assert_eq!(summary.malformed_lines, vec![2]);
    assert_eq!(summary.duplicate_events, 0);
    assert!(store
        .get_event("evt_spool_good")
        .expect("event lookup succeeds")
        .is_some());
    assert_eq!(store.list_events().expect("events list").len(), 1);
    assert_eq!(
        fs::read_to_string(&checkpoint_path).expect("checkpoint exists"),
        summary.last_processed_byte.to_string()
    );

    let replay = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("restarting from checkpoint is safe");
    assert_eq!(replay.ingested_events, 0);
    assert_eq!(replay.dropped_events, 0);
    assert_eq!(store.list_events().expect("events list").len(), 1);

    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(spool_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn live_spool_ingestion_is_idempotent_and_processes_only_complete_lines() {
    let db_path = temp_path("restart.sqlite");
    let spool_path = temp_path("restart.jsonl");
    let checkpoint_path = temp_path("restart.offset");
    let first_event = variant_event("evt_spool_once", "Spool event ingested once");
    let second_event = variant_event("evt_spool_after_restart", "Spool event after restart");
    fs::write(&spool_path, format!("{first_event}\n{second_event}"))
        .expect("partial spool is written");

    let store = LocalStore::open(&db_path).expect("store opens");
    let first = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("complete lines ingest");

    assert_eq!(first.ingested_events, 1);
    assert_eq!(first.dropped_events, 0);
    assert!(store
        .get_event("evt_spool_once")
        .expect("event lookup succeeds")
        .is_some());
    assert!(store
        .get_event("evt_spool_after_restart")
        .expect("event lookup succeeds")
        .is_none());

    fs::write(
        &spool_path,
        format!("{first_event}\n{second_event}\n{first_event}\n"),
    )
    .expect("spool gains complete tail and duplicate event id");
    let second = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("restart ingests only new complete lines");

    assert_eq!(second.ingested_events, 1);
    assert_eq!(second.duplicate_events, 1);
    assert_eq!(second.dropped_events, 0);
    assert_eq!(store.list_events().expect("events list").len(), 2);

    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(spool_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn live_spool_ingestion_ignores_partial_non_utf8_tail_without_losing_complete_events() {
    let db_path = temp_path("partial-utf8.sqlite");
    let spool_path = temp_path("partial-utf8.jsonl");
    let checkpoint_path = temp_path("partial-utf8.offset");
    let complete_event = variant_event(
        "evt_spool_before_partial_utf8",
        "Complete before UTF-8 tail",
    );
    let mut spool = format!("{complete_event}\n").into_bytes();
    spool.push(0xC3);
    fs::write(&spool_path, spool).expect("spool with partial UTF-8 tail is written");

    let store = LocalStore::open(&db_path).expect("store opens");
    let summary = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("partial non-UTF-8 tail is ignored until complete");

    assert_eq!(summary.ingested_events, 1);
    assert_eq!(summary.dropped_events, 0);
    assert!(store
        .get_event("evt_spool_before_partial_utf8")
        .expect("event lookup succeeds")
        .is_some());
    assert_eq!(
        fs::read_to_string(&checkpoint_path).expect("checkpoint exists"),
        format!("{}", complete_event.len() + 1)
    );

    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(spool_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn live_spool_ingestion_resets_stale_checkpoint_after_spool_truncation() {
    let db_path = temp_path("truncated.sqlite");
    let spool_path = temp_path("truncated.jsonl");
    let checkpoint_path = temp_path("truncated.offset");
    let replacement_event = variant_event("evt_spool_after_truncate", "Spool event after truncate");
    fs::write(&spool_path, format!("{replacement_event}\n")).expect("replacement spool written");
    fs::write(&checkpoint_path, "999999").expect("stale checkpoint written");

    let store = LocalStore::open(&db_path).expect("store opens");
    let summary = ingest_canonical_jsonl_spool(&store, &spool_path, &checkpoint_path)
        .expect("stale checkpoint is reset after truncation");

    assert_eq!(summary.ingested_events, 1);
    assert_eq!(summary.dropped_events, 0);
    assert!(store
        .get_event("evt_spool_after_truncate")
        .expect("event lookup succeeds")
        .is_some());
    assert_eq!(
        fs::read_to_string(&checkpoint_path).expect("checkpoint exists"),
        summary.last_processed_byte.to_string()
    );

    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(spool_path);
    let _ = fs::remove_file(checkpoint_path);
}
