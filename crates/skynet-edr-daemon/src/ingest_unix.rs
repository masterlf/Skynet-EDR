//! Bounded authenticated Linux `AF_UNIX` continuous ingestion.

use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use nix::{
    sys::socket::{getsockopt, sockopt::PeerCredentials},
    unistd::{chown, Gid, Uid},
};
use serde_json::json;
use skynet_edr_core::{
    built_in_ai_agent_sequence_rules, parse_canonical_event_json, CanonicalEventEnvelope,
    ContinuousIngestStatus, LocalStore,
};

const MAX_HEALTH_SOURCES: usize = 64;

/// Fixed runtime roles accepted by the attributed producer-health protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProducerRole {
    /// Hermes dashboard/API runtime.
    Dashboard,
    /// Hermes gateway runtime where interactive hooks are normally expected.
    Gateway,
    /// Hermes background worker runtime.
    Worker,
    /// Safe fallback when Hermes does not expose a known runtime role.
    Unknown,
    /// Backward-compatible version-1 producer with no runtime attribution.
    Legacy,
}

impl ProducerRole {
    /// Parse a protocol/config role from the fixed vocabulary.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "dashboard" => Some(Self::Dashboard),
            "gateway" => Some(Self::Gateway),
            "worker" => Some(Self::Worker),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Dashboard => "dashboard",
            Self::Gateway => "gateway",
            Self::Worker => "worker",
            Self::Unknown => "unknown",
            Self::Legacy => "legacy",
        }
    }
}

/// Runtime bounds and authorization policy for the Unix ingestion listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixIngestConfig {
    /// Exact Linux pathname socket to bind.
    pub socket_path: PathBuf,
    /// Optional numeric group applied after bind.
    pub socket_gid: Option<u32>,
    /// Explicit numeric producer UID allowlist.
    pub allowed_uids: Vec<u32>,
    /// Explicit opt-in for UID 0 producers.
    pub allow_root: bool,
    /// Maximum declared frame body length.
    pub max_frame_bytes: usize,
    /// Maximum simultaneously active accepted connections.
    pub max_connections: usize,
    /// Header/body read deadline.
    pub read_timeout: Duration,
    /// ACK write deadline.
    pub write_timeout: Duration,
    /// Maximum indexed correlation candidates per event.
    pub candidate_limit: usize,
    /// Optional fixed roles that must have a fresh attributed heartbeat.
    pub required_roles: Vec<ProducerRole>,
}

/// Bounded aggregate ingestion counters shared with the read-only status projection.
#[derive(Debug)]
pub struct IngestionHealth {
    accepted: AtomicU64,
    unauthorized: AtomicU64,
    capacity_rejected: AtomicU64,
    listener_errors: AtomicU64,
    peer_credential_errors: AtomicU64,
    received: AtomicU64,
    oversized: AtomicU64,
    invalid: AtomicU64,
    timed_out: AtomicU64,
    persisted: AtomicU64,
    duplicates: AtomicU64,
    collisions: AtomicU64,
    correlation_truncated: AtomicU64,
    storage_errors: AtomicU64,
    last_degraded_at_unix_ms: AtomicU64,
    listener_live: AtomicBool,
    last_event_received_at_unix_ms: AtomicU64,
    last_event_committed_at_unix_ms: AtomicU64,
    required_roles: Vec<ProducerRole>,
    sources: Mutex<BTreeMap<(u32, ProducerRole), SourceHealth>>,
}

#[derive(Debug, Default)]
struct SourceHealth {
    instance_id: Option<String>,
    last_event_received_at_unix_ms: Option<u64>,
    last_event_committed_at_unix_ms: Option<u64>,
    producer_checkpoint_bytes: Option<u64>,
    backlog_bytes: Option<u64>,
    backlog_age_ms: Option<u64>,
    daemon_events_malformed_total: u64,
    producer_events_malformed_total: u64,
    events_dropped_total: u64,
    events_duplicate_total: u64,
    events_collision_total: u64,
    producer_reported_at_unix_ms: Option<u64>,
    transport_state: Option<ProducerTransportState>,
    last_error_category: Option<&'static str>,
    last_error_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProducerTransportState {
    Available,
    Degraded,
}

#[derive(Debug)]
struct ProducerHealthReport {
    role: ProducerRole,
    instance_id: Option<String>,
    checkpoint_bytes: u64,
    backlog_bytes: u64,
    backlog_age_ms: Option<u64>,
    events_dropped_total: u64,
    events_malformed_total: u64,
    transport_state: ProducerTransportState,
}

fn parse_producer_health(value: &serde_json::Value) -> Option<ProducerHealthReport> {
    let object = value.as_object()?;
    let common = [
        "version",
        "message_type",
        "checkpoint_bytes",
        "backlog_bytes",
        "backlog_age_ms",
        "events_dropped_total",
        "events_malformed_total",
        "transport_state",
    ];
    let version = object.get("version")?.as_u64()?;
    if object.get("message_type")?.as_str()? != "producer_health" {
        return None;
    }
    let (role, instance_id) = match version {
        1 if object.len() == common.len()
            && object.keys().all(|key| common.contains(&key.as_str())) =>
        {
            (ProducerRole::Legacy, None)
        }
        2 => {
            let mut allowed = common.to_vec();
            allowed.extend(["runtime_role", "instance_id"]);
            if object.len() != allowed.len()
                || object.keys().any(|key| !allowed.contains(&key.as_str()))
            {
                return None;
            }
            let role = ProducerRole::parse(object.get("runtime_role")?.as_str()?)?;
            let instance = object.get("instance_id")?.as_str()?;
            if !valid_instance_id(instance) {
                return None;
            }
            (role, Some(instance.to_owned()))
        }
        _ => return None,
    };
    let backlog_age_ms = match object.get("backlog_age_ms")? {
        serde_json::Value::Null => None,
        value => Some(value.as_u64()?),
    };
    let transport_state = match object.get("transport_state")?.as_str()? {
        "available" => ProducerTransportState::Available,
        "degraded" => ProducerTransportState::Degraded,
        _ => return None,
    };
    Some(ProducerHealthReport {
        role,
        instance_id,
        checkpoint_bytes: object.get("checkpoint_bytes")?.as_u64()?,
        backlog_bytes: object.get("backlog_bytes")?.as_u64()?,
        backlog_age_ms,
        events_dropped_total: object.get("events_dropped_total")?.as_u64()?,
        events_malformed_total: object.get("events_malformed_total")?.as_u64()?,
        transport_state,
    })
}

fn valid_instance_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// Point-in-time aggregate ingestion counters containing no frame content or paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestionHealthSnapshot {
    /// Authorized connections accepted.
    pub connections_accepted_total: u64,
    /// Connections rejected before frame parsing.
    pub connections_unauthorized_total: u64,
    /// Connections rejected because the bounded worker capacity was full.
    pub connections_capacity_rejected_total: u64,
    /// Listener accept failures observed after startup.
    pub listener_errors_total: u64,
    /// Accepted streams whose kernel peer credentials could not be read.
    pub peer_credential_errors_total: u64,
    /// Bounded frames received.
    pub frames_received_total: u64,
    /// Zero or oversized frames rejected before body allocation.
    pub frames_oversize_total: u64,
    /// UTF-8, JSON, or canonical-schema rejects.
    pub frames_invalid_total: u64,
    /// Header/body reads that exceeded the deadline.
    pub frames_timeout_total: u64,
    /// Events atomically persisted.
    pub events_persisted_total: u64,
    /// Immutable duplicate events acknowledged.
    pub events_duplicate_total: u64,
    /// Event identifiers rejected because source identity or payload did not match.
    pub events_collision_total: u64,
    /// Events persisted while bounded correlation was skipped due to candidate overflow.
    pub correlation_truncated_total: u64,
    /// Transactional storage/correlation failures.
    pub storage_errors_total: u64,
}

impl Default for IngestionHealth {
    fn default() -> Self {
        Self::with_required_roles(Vec::new())
    }
}

impl IngestionHealth {
    /// Create process-lifetime health state with optional required runtime roles.
    #[must_use]
    pub fn with_required_roles(required_roles: Vec<ProducerRole>) -> Self {
        Self {
            accepted: AtomicU64::new(0),
            unauthorized: AtomicU64::new(0),
            capacity_rejected: AtomicU64::new(0),
            listener_errors: AtomicU64::new(0),
            peer_credential_errors: AtomicU64::new(0),
            received: AtomicU64::new(0),
            oversized: AtomicU64::new(0),
            invalid: AtomicU64::new(0),
            timed_out: AtomicU64::new(0),
            persisted: AtomicU64::new(0),
            duplicates: AtomicU64::new(0),
            collisions: AtomicU64::new(0),
            correlation_truncated: AtomicU64::new(0),
            storage_errors: AtomicU64::new(0),
            last_degraded_at_unix_ms: AtomicU64::new(0),
            listener_live: AtomicBool::new(false),
            last_event_received_at_unix_ms: AtomicU64::new(0),
            last_event_committed_at_unix_ms: AtomicU64::new(0),
            required_roles,
            sources: Mutex::new(BTreeMap::new()),
        }
    }

    /// Return a bounded aggregate snapshot.
    #[must_use]
    pub fn snapshot(&self) -> IngestionHealthSnapshot {
        IngestionHealthSnapshot {
            connections_accepted_total: self.accepted.load(Ordering::Relaxed),
            connections_unauthorized_total: self.unauthorized.load(Ordering::Relaxed),
            connections_capacity_rejected_total: self.capacity_rejected.load(Ordering::Relaxed),
            listener_errors_total: self.listener_errors.load(Ordering::Relaxed),
            peer_credential_errors_total: self.peer_credential_errors.load(Ordering::Relaxed),
            frames_received_total: self.received.load(Ordering::Relaxed),
            frames_oversize_total: self.oversized.load(Ordering::Relaxed),
            frames_invalid_total: self.invalid.load(Ordering::Relaxed),
            frames_timeout_total: self.timed_out.load(Ordering::Relaxed),
            events_persisted_total: self.persisted.load(Ordering::Relaxed),
            events_duplicate_total: self.duplicates.load(Ordering::Relaxed),
            events_collision_total: self.collisions.load(Ordering::Relaxed),
            correlation_truncated_total: self.correlation_truncated.load(Ordering::Relaxed),
            storage_errors_total: self.storage_errors.load(Ordering::Relaxed),
        }
    }

    /// Record a connection rejected by the bounded accept-loop capacity gate.
    pub fn record_capacity_rejection(&self) {
        self.capacity_rejected.fetch_add(1, Ordering::Relaxed);
        self.record_degradation();
    }

    /// Record an accept-loop failure so status cannot remain falsely healthy.
    pub fn record_listener_error(&self) {
        self.listener_errors.fetch_add(1, Ordering::Relaxed);
        self.record_degradation();
    }

    /// Record a failure to read kernel-authenticated peer credentials.
    pub fn record_peer_credential_error(&self) {
        self.peer_credential_errors.fetch_add(1, Ordering::Relaxed);
        self.record_degradation();
    }

    /// Mark the authenticated listener thread live after a successful bind.
    pub fn record_listener_started(&self) {
        self.listener_live.store(true, Ordering::Release);
    }

    /// Mark the listener unavailable when its accept loop exits.
    pub fn record_listener_stopped(&self) {
        self.listener_live.store(false, Ordering::Release);
    }

    /// Return bounded transport enrollment and independent hook-event recency.
    #[must_use]
    pub fn status_json(&self, stale_after: Duration) -> serde_json::Value {
        let snapshot = self.snapshot();
        let now = unix_ms_now();
        let stale_after_ms = u64::try_from(stale_after.as_millis()).unwrap_or(u64::MAX);
        let sources = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut source_values = Vec::with_capacity(sources.len());
        let mut producer_count = 0usize;
        let mut producer_degraded = false;
        let mut any_fresh_heartbeat = false;
        for ((uid, role), source) in sources.iter() {
            let (value, has_report, is_degraded, fresh_heartbeat) =
                source_status_json(*uid, *role, source, now, stale_after_ms);
            producer_count += usize::from(has_report);
            producer_degraded |= is_degraded;
            any_fresh_heartbeat |= fresh_heartbeat;
            source_values.push(value);
        }
        let mut required_values = Vec::with_capacity(self.required_roles.len());
        let mut required_degraded = false;
        for required in &self.required_roles {
            let mut present = false;
            let mut fresh = false;
            for ((_, role), source) in sources.iter() {
                if role != required || source.producer_reported_at_unix_ms.is_none() {
                    continue;
                }
                present = true;
                fresh |= source.producer_reported_at_unix_ms.is_some_and(|reported| {
                    now.saturating_sub(reported) <= stale_after_ms
                        && source.transport_state == Some(ProducerTransportState::Available)
                        && source.backlog_bytes.unwrap_or(0) == 0
                });
            }
            let state = if fresh {
                "fresh"
            } else if present {
                "stale"
            } else {
                "absent"
            };
            required_degraded |= !fresh;
            required_values.push(json!({"runtime_role": required.as_str(), "state": state}));
        }
        let last_received =
            optional_timestamp(self.last_event_received_at_unix_ms.load(Ordering::Relaxed));
        let last_committed =
            optional_timestamp(self.last_event_committed_at_unix_ms.load(Ordering::Relaxed));
        let listener_live = self.listener_live.load(Ordering::Acquire);
        let last_degraded = self.last_degraded_at_unix_ms.load(Ordering::Relaxed);
        let recently_degraded =
            last_degraded != 0 && now.saturating_sub(last_degraded) <= stale_after_ms;
        let degraded = !listener_live
            || producer_count == 0
            || producer_degraded
            || required_degraded
            || recently_degraded;
        json!({
            "state": if degraded { "degraded" } else { "healthy" },
            "listener_live": listener_live,
            "transport_heartbeat_state": if any_fresh_heartbeat { "fresh" } else if producer_count > 0 { "stale" } else { "not_observed" },
            "hook_event_state": match last_received {
                Some(at) if now.saturating_sub(at) <= stale_after_ms => "fresh",
                Some(_) => "stale",
                None => "not_observed",
            },
            "hook_event_freshness_affects_state": false,
            "last_event_received_at_unix_ms": last_received,
            "last_event_received_age_ms": last_received.map(|at| now.saturating_sub(at)),
            "last_event_committed_at_unix_ms": last_committed,
            "last_event_committed_age_ms": last_committed.map(|at| now.saturating_sub(at)),
            "required_roles": required_values,
            "connections_accepted_total": snapshot.connections_accepted_total,
            "connections_unauthorized_total": snapshot.connections_unauthorized_total,
            "connections_capacity_rejected_total": snapshot.connections_capacity_rejected_total,
            "listener_errors_total": snapshot.listener_errors_total,
            "peer_credential_errors_total": snapshot.peer_credential_errors_total,
            "frames_received_total": snapshot.frames_received_total,
            "frames_oversize_total": snapshot.frames_oversize_total,
            "frames_invalid_total": snapshot.frames_invalid_total,
            "frames_timeout_total": snapshot.frames_timeout_total,
            "events_persisted_total": snapshot.events_persisted_total,
            "events_duplicate_total": snapshot.events_duplicate_total,
            "events_collision_total": snapshot.events_collision_total,
            "correlation_truncated_total": snapshot.correlation_truncated_total,
            "storage_errors_total": snapshot.storage_errors_total,
            "sources": source_values,
        })
    }

    fn record_source_error(&self, uid: u32, category: &'static str) {
        let mut sources = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (uid, ProducerRole::Legacy);
        if sources.contains_key(&key) || sources.len() < MAX_HEALTH_SOURCES {
            let source = sources.entry(key).or_default();
            source.last_error_category = Some(category);
            source.last_error_at_unix_ms = Some(unix_ms_now());
            if category == "malformed_frame" {
                source.daemon_events_malformed_total =
                    source.daemon_events_malformed_total.saturating_add(1);
            }
        }
        drop(sources);
        if is_degrading_error(category) {
            self.record_degradation();
        }
    }

    fn record_event_received(&self, uid: u32) {
        let now = unix_ms_now();
        self.last_event_received_at_unix_ms
            .store(now, Ordering::Relaxed);
        let mut sources = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (uid, ProducerRole::Legacy);
        if sources.contains_key(&key) || sources.len() < MAX_HEALTH_SOURCES {
            sources
                .entry(key)
                .or_default()
                .last_event_received_at_unix_ms = Some(now);
        }
    }

    fn record_result(&self, uid: u32, status: ContinuousIngestStatus) {
        let mut sources = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (uid, ProducerRole::Legacy);
        if !sources.contains_key(&key) && sources.len() >= MAX_HEALTH_SOURCES {
            if status == ContinuousIngestStatus::Persisted {
                self.last_event_committed_at_unix_ms
                    .store(unix_ms_now(), Ordering::Relaxed);
            }
            return;
        }
        let source = sources.entry(key).or_default();
        match status {
            ContinuousIngestStatus::Persisted => {
                let now = unix_ms_now();
                source.last_event_committed_at_unix_ms = Some(now);
                self.last_event_committed_at_unix_ms
                    .store(now, Ordering::Relaxed);
            }
            ContinuousIngestStatus::Duplicate => {
                source.events_duplicate_total = source.events_duplicate_total.saturating_add(1);
            }
            ContinuousIngestStatus::Collision => {
                source.events_collision_total = source.events_collision_total.saturating_add(1);
            }
        }
    }

    fn record_producer_health(&self, uid: u32, report: &ProducerHealthReport) -> bool {
        let mut sources = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (uid, report.role);
        if !sources.contains_key(&key) && sources.len() >= MAX_HEALTH_SOURCES {
            return false;
        }
        let source = sources.entry(key).or_default();
        if source.instance_id != report.instance_id {
            *source = SourceHealth {
                instance_id: report.instance_id.clone(),
                ..SourceHealth::default()
            };
        }
        source.producer_checkpoint_bytes = Some(report.checkpoint_bytes);
        source.backlog_bytes = Some(report.backlog_bytes);
        source.backlog_age_ms = report.backlog_age_ms;
        source.events_dropped_total = report.events_dropped_total;
        source.producer_events_malformed_total = report.events_malformed_total;
        source.transport_state = Some(report.transport_state);
        source.producer_reported_at_unix_ms = Some(unix_ms_now());
        true
    }

    fn record_correlation_truncated(&self) {
        self.correlation_truncated.fetch_add(1, Ordering::Relaxed);
        self.record_degradation();
    }

    fn record_degradation(&self) {
        self.last_degraded_at_unix_ms
            .store(unix_ms_now(), Ordering::Relaxed);
    }
}

fn is_degrading_error(category: &str) -> bool {
    matches!(category, "frame_timeout" | "storage" | "transaction")
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn source_status_json(
    uid: u32,
    role: ProducerRole,
    source: &SourceHealth,
    now: u64,
    stale_after_ms: u64,
) -> (serde_json::Value, bool, bool, bool) {
    let has_report = source.producer_reported_at_unix_ms.is_some();
    let stale = source
        .producer_reported_at_unix_ms
        .is_some_and(|reported| now.saturating_sub(reported) > stale_after_ms);
    let transport_state = match source.transport_state {
        Some(ProducerTransportState::Available) if !stale => "available",
        Some(ProducerTransportState::Available) => "stale",
        Some(ProducerTransportState::Degraded) => "degraded",
        None => "unknown",
    };
    let recent_degrading_error = source.last_error_category.is_some_and(|category| {
        is_degrading_error(category)
            && source
                .last_error_at_unix_ms
                .is_some_and(|at| now.saturating_sub(at) <= stale_after_ms)
    });
    let degraded = has_report
        && (stale
            || source.transport_state == Some(ProducerTransportState::Degraded)
            || source.backlog_bytes.unwrap_or(0) > 0
            || recent_degrading_error);
    let source_id = source.instance_id.as_ref().map_or_else(
        || format!("uid:{uid}"),
        |instance| format!("uid:{uid}:{}:{instance}", role.as_str()),
    );
    let value = json!({
        "source_id": source_id,
        "authenticated_uid": uid,
        "runtime_role": role.as_str(),
        "instance_id": source.instance_id,
        "last_event_received_at_unix_ms": source.last_event_received_at_unix_ms,
        "last_event_committed_at_unix_ms": source.last_event_committed_at_unix_ms,
        "producer_checkpoint_bytes": source.producer_checkpoint_bytes,
        "backlog_bytes": source.backlog_bytes,
        "backlog_age_ms": source.backlog_age_ms,
        "events_malformed_total": source.daemon_events_malformed_total.saturating_add(source.producer_events_malformed_total),
        "events_dropped_total": source.events_dropped_total,
        "events_duplicate_total": source.events_duplicate_total,
        "events_collision_total": source.events_collision_total,
        "last_error_category": source.last_error_category,
        "last_error_at_unix_ms": source.last_error_at_unix_ms,
        "producer_reported_at_unix_ms": source.producer_reported_at_unix_ms,
        "producer_report_age_ms": source.producer_reported_at_unix_ms.map(|at| now.saturating_sub(at)),
        "transport_state": transport_state,
    });
    (value, has_report, degraded, has_report && !stale)
}

fn optional_timestamp(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

/// Safely replace an owned stale socket and bind the configured listener.
///
/// # Errors
///
/// Fails closed for symlinks, non-sockets, unexpected owners, active listeners,
/// invalid parents, bind failures, or ownership/mode failures.
pub fn bind_ingest_listener(config: &UnixIngestConfig) -> io::Result<UnixListener> {
    let path = &config.socket_path;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ingest socket requires a parent directory",
            )
        })?;
    fs::create_dir_all(parent)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != Uid::effective().as_raw()
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing unsafe ingest socket parent directory",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing symlink at ingest socket path",
                ));
            }
            if !metadata.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "refusing non-socket at ingest socket path",
                ));
            }
            if metadata.uid() != Uid::effective().as_raw() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing ingest socket with unexpected owner",
                ));
            }
            if UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "refusing to replace active ingest socket",
                ));
            }
            fs::remove_file(path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let (listener, private_dir, private_path) = bind_private_socket(parent)?;
    if let Err(error) = secure_bound_socket(&private_path, config.socket_gid) {
        drop(listener);
        cleanup_private_socket(&private_dir, &private_path);
        return Err(error);
    }
    if let Err(error) = publish_secured_socket(&private_path, path) {
        drop(listener);
        cleanup_private_socket(&private_dir, &private_path);
        return Err(error);
    }
    if let Err(error) = fs::remove_dir(&private_dir) {
        drop(listener);
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(&private_dir);
        return Err(error);
    }
    Ok(listener)
}

fn bind_private_socket(parent: &Path) -> io::Result<(UnixListener, PathBuf, PathBuf)> {
    static PRIVATE_SOCKET_NONCE: AtomicU64 = AtomicU64::new(0);

    for _ in 0..16 {
        let nonce = PRIVATE_SOCKET_NONCE.fetch_add(1, Ordering::Relaxed);
        let private_dir = parent.join(format!(".i{nonce:x}"));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&private_dir) {
            Ok(()) => {
                let private_path = private_dir.join("s");
                match UnixListener::bind(&private_path) {
                    Ok(listener) => return Ok((listener, private_dir, private_path)),
                    Err(error) => {
                        let _ = fs::remove_dir_all(&private_dir);
                        return Err(error);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate private ingest socket directory",
    ))
}

fn publish_secured_socket(private_path: &Path, final_path: &Path) -> io::Result<()> {
    fs::hard_link(private_path, final_path)?;
    if let Err(error) = fs::remove_file(private_path) {
        let _ = fs::remove_file(final_path);
        return Err(error);
    }
    Ok(())
}

fn cleanup_private_socket(private_dir: &Path, private_path: &Path) {
    let _ = fs::remove_file(private_path);
    let _ = fs::remove_dir_all(private_dir);
}

fn secure_bound_socket(path: &Path, socket_gid: Option<u32>) -> io::Result<()> {
    if let Some(gid) = socket_gid {
        chown(path, None, Some(Gid::from_raw(gid))).map_err(io::Error::other)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))
}

/// Read the kernel-authenticated peer UID from an accepted Unix stream.
///
/// # Errors
///
/// Returns an I/O error when `SO_PEERCRED` cannot be read.
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    getsockopt(stream, PeerCredentials)
        .map(|credentials| credentials.uid())
        .map_err(io::Error::other)
}

fn handle_producer_health_frame(
    text: &str,
    stream: &mut UnixStream,
    uid: u32,
    health: &IngestionHealth,
) -> Option<io::Result<()>> {
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    if value
        .get("message_type")
        .and_then(serde_json::Value::as_str)
        != Some("producer_health")
    {
        return None;
    }
    let Some(report) = parse_producer_health(&value) else {
        health.invalid.fetch_add(1, Ordering::Relaxed);
        return Some(write_ack(
            stream,
            &json!({"version":1,"status":"rejected_permanent","reason":"invalid_health"}),
        ));
    };
    if !health.record_producer_health(uid, &report) {
        health.invalid.fetch_add(1, Ordering::Relaxed);
        return Some(write_ack(
            stream,
            &json!({"version":1,"status":"rejected_permanent","reason":"source_capacity"}),
        ));
    }
    Some(write_ack(
        stream,
        &json!({"version":1,"status":"health_recorded"}),
    ))
}

fn commit_event_and_ack(
    stream: &mut UnixStream,
    uid: u32,
    config: &UnixIngestConfig,
    db_path: &Path,
    health: &IngestionHealth,
    event: &CanonicalEventEnvelope,
) -> io::Result<()> {
    health.record_event_received(uid);
    let Ok(store) = LocalStore::open_existing_writable(db_path) else {
        health.storage_errors.fetch_add(1, Ordering::Relaxed);
        health.record_source_error(uid, "storage");
        return write_ack(
            stream,
            &json!({"version":1,"status":"retry_later","reason":"storage"}),
        );
    };
    let source_id = format!("uid:{uid}");
    if let Ok(result) = store.commit_continuous_event(
        &source_id,
        event,
        &built_in_ai_agent_sequence_rules(),
        config.candidate_limit,
    ) {
        health.record_result(uid, result.status);
        if result.correlation_truncated {
            health.record_correlation_truncated();
        }
        let status = match result.status {
            ContinuousIngestStatus::Persisted => {
                health.persisted.fetch_add(1, Ordering::Relaxed);
                "persisted"
            }
            ContinuousIngestStatus::Duplicate => {
                health.duplicates.fetch_add(1, Ordering::Relaxed);
                "duplicate"
            }
            ContinuousIngestStatus::Collision => {
                health.collisions.fetch_add(1, Ordering::Relaxed);
                "collision"
            }
        };
        write_ack(
            stream,
            &json!({"version":1,"event_id":event.event_id.as_str(),"status":status}),
        )
    } else {
        health.storage_errors.fetch_add(1, Ordering::Relaxed);
        health.record_source_error(uid, "transaction");
        write_ack(
            stream,
            &json!({"version":1,"event_id":event.event_id.as_str(),"status":"retry_later","reason":"transaction"}),
        )
    }
}

/// Process one authenticated, bounded frame and emit one bounded ACK when possible.
///
/// Authorization occurs before any frame byte is read. `persisted` is written only
/// after the event, incidents, and receipt transaction commits.
///
/// # Errors
///
/// Returns only socket setup/write errors. Hostile frames and persistence failures
/// are isolated as bounded protocol responses.
pub fn process_ingest_connection(
    mut stream: UnixStream,
    uid: u32,
    config: &UnixIngestConfig,
    db_path: &Path,
    health: &IngestionHealth,
) -> io::Result<()> {
    let authorized = if uid == 0 {
        config.allow_root
    } else {
        config.allowed_uids.contains(&uid)
    };
    if !authorized {
        health.unauthorized.fetch_add(1, Ordering::Relaxed);
        stream.shutdown(std::net::Shutdown::Both)?;
        return Ok(());
    }
    health.accepted.fetch_add(1, Ordering::Relaxed);
    stream.set_write_timeout(Some(config.write_timeout))?;
    let read_deadline = Instant::now() + config.read_timeout;

    let mut header = [0_u8; 4];
    if let Err(error) = read_exact_until(&mut stream, &mut header, read_deadline) {
        if is_timeout(&error) {
            health.timed_out.fetch_add(1, Ordering::Relaxed);
            health.record_source_error(uid, "frame_timeout");
        } else {
            health.invalid.fetch_add(1, Ordering::Relaxed);
            health.record_source_error(uid, "malformed_frame");
        }
        return Ok(());
    }
    let declared = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length is unsupported"))?;
    if declared == 0 || declared > config.max_frame_bytes {
        health.oversized.fetch_add(1, Ordering::Relaxed);
        health.record_source_error(uid, "frame_size");
        return write_ack(
            &mut stream,
            &json!({"version":1,"status":"rejected_permanent","reason":"frame_size"}),
        );
    }

    let mut body = vec![0_u8; declared];
    if let Err(error) = read_exact_until(&mut stream, &mut body, read_deadline) {
        if is_timeout(&error) {
            health.timed_out.fetch_add(1, Ordering::Relaxed);
            health.record_source_error(uid, "frame_timeout");
        } else {
            health.invalid.fetch_add(1, Ordering::Relaxed);
            health.record_source_error(uid, "malformed_frame");
        }
        return Ok(());
    }
    health.received.fetch_add(1, Ordering::Relaxed);
    let Ok(text) = std::str::from_utf8(&body) else {
        health.invalid.fetch_add(1, Ordering::Relaxed);
        health.record_source_error(uid, "malformed_frame");
        return write_ack(
            &mut stream,
            &json!({"version":1,"status":"rejected_permanent","reason":"invalid_event"}),
        );
    };
    if let Some(result) = handle_producer_health_frame(text, &mut stream, uid, health) {
        return result;
    }
    let Ok(event) = parse_canonical_event_json(text) else {
        health.invalid.fetch_add(1, Ordering::Relaxed);
        health.record_source_error(uid, "malformed_frame");
        return write_ack(
            &mut stream,
            &json!({"version":1,"status":"rejected_permanent","reason":"invalid_event"}),
        );
    };
    commit_event_and_ack(&mut stream, uid, config, db_path, health, &event)
}

fn read_exact_until(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "ingest frame deadline exceeded")
            })?;
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ingest frame ended early",
                ));
            }
            Ok(read) => offset += read,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn write_ack(stream: &mut UnixStream, value: &serde_json::Value) -> io::Result<()> {
    let mut encoded = serde_json::to_vec(value).map_err(io::Error::other)?;
    if encoded.len() > 4_096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ingestion ACK exceeded protocol bound",
        ));
    }
    encoded.push(b'\n');
    stream.write_all(&encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_failure_preserves_secured_private_socket_and_existing_target() {
        let root = std::env::temp_dir().join(format!(
            "skynet-edr-socket-publication-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("test root created");
        let private_path = root.join("private.sock");
        let final_path = root.join("ingest.sock");
        let listener = UnixListener::bind(&private_path).expect("private listener binds");
        secure_bound_socket(&private_path, Some(Gid::effective().as_raw()))
            .expect("private listener secured");
        fs::write(&final_path, "do-not-replace").expect("publication target created");

        let error = publish_secured_socket(&private_path, &final_path)
            .expect_err("publication must not replace an existing path");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read_to_string(&final_path).expect("existing target remains readable"),
            "do-not-replace"
        );
        let metadata = fs::symlink_metadata(&private_path).expect("private socket remains");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
        assert_eq!(metadata.uid(), Uid::effective().as_raw());
        assert_eq!(metadata.gid(), Gid::effective().as_raw());

        drop(listener);
        let _ = fs::remove_dir_all(root);
    }
}
