//! Bounded authenticated Linux `AF_UNIX` continuous ingestion.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    os::fd::{AsRawFd, OwnedFd},
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
    fcntl::{open, openat, OFlag},
    sys::socket::{getsockopt, sockopt::PeerCredentials, sockopt::PeerPidfd},
    sys::stat::Mode,
    unistd::{chown, Gid, Uid},
};
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use serde_json::{json, value::RawValue};
use skynet_edr_core::{
    built_in_ai_agent_sequence_rules, parse_canonical_event_json, CanonicalEventEnvelope,
    ContinuousIngestError, ContinuousIngestResult, ContinuousIngestStatus, LocalStore,
};

const MAX_HEALTH_SOURCES: usize = 64;
const DEFAULT_STALE_SOURCE_RETENTION: Duration = Duration::from_mins(5);

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
    pub required_reported_roles: Vec<ProducerRole>,
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
    incident_integrity_collisions: AtomicU64,
    correlation_truncated: AtomicU64,
    storage_errors: AtomicU64,
    last_degraded_at_unix_ms: AtomicU64,
    listener_live: AtomicBool,
    last_event_received_at_unix_ms: AtomicU64,
    last_event_committed_at_unix_ms: AtomicU64,
    required_reported_roles: Vec<ProducerRole>,
    stale_source_retention: Duration,
    sources: Mutex<BTreeMap<SourceKey, SourceHealth>>,
}

#[derive(Debug, Default)]
struct SourceHealth {
    instance_id: Option<String>,
    protocol_version: u64,
    plugin_generation: Option<String>,
    runtime_instance_nonce: Option<String>,
    kernel_peer_pid: Option<i32>,
    kernel_peer_start_ticks: Option<u64>,
    last_event_received_at_unix_ms: Option<u64>,
    last_event_committed_at_unix_ms: Option<u64>,
    events_persisted_total: u64,
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
    last_persisted_canary_event_id: Option<String>,
    last_persisted_canary_receipt_status: Option<&'static str>,
    last_persisted_canary_incidents_opened: Option<u64>,
}

impl SourceHealth {
    fn bind_kernel_peer(&mut self, peer: KernelPeerIdentity) {
        let prior = self.kernel_peer_pid.zip(self.kernel_peer_start_ticks);
        if prior.is_some_and(|identity| identity != (peer.pid, peer.process_start_ticks)) {
            self.instance_id = None;
            self.producer_checkpoint_bytes = None;
            self.backlog_bytes = None;
            self.backlog_age_ms = None;
            self.producer_events_malformed_total = 0;
            self.events_dropped_total = 0;
            self.producer_reported_at_unix_ms = None;
            self.transport_state = None;
        }
        self.kernel_peer_pid = Some(peer.pid);
        self.kernel_peer_start_ticks = Some(peer.process_start_ticks);
    }
}

type SourceKey = (u32, ProducerRole, Option<String>, Option<String>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelPeerIdentity {
    pid: i32,
    process_start_ticks: u64,
}

/// Kernel-authenticated credentials plus an opened process identity anchor.
#[derive(Debug)]
pub struct AuthenticatedPeer {
    uid: u32,
    identity: KernelPeerIdentity,
    pidfd: Option<OwnedFd>,
    proc_dir: File,
}

impl AuthenticatedPeer {
    /// Return the kernel-authenticated UID captured at accept time.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    fn verified_kernel_identity(&self) -> io::Result<KernelPeerIdentity> {
        if let Some(pidfd) = &self.pidfd {
            verify_pidfd_pid(pidfd, self.identity.pid)?;
        }
        let current_start_ticks = read_process_start_ticks(&self.proc_dir)?;
        if current_start_ticks != self.identity.process_start_ticks {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "peer process identity changed after accept",
            ));
        }
        if let Some(pidfd) = &self.pidfd {
            verify_pidfd_pid(pidfd, self.identity.pid)?;
        }
        Ok(self.identity)
    }

    #[cfg(test)]
    fn from_open_proc_dir_for_test(uid: u32, pid: i32, start_ticks: u64, proc_dir: File) -> Self {
        Self {
            uid,
            identity: KernelPeerIdentity {
                pid,
                process_start_ticks: start_ticks,
            },
            pidfd: None,
            proc_dir,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProducerTransportState {
    Available,
    Degraded,
}

#[derive(Debug)]
struct ProducerHealthReport {
    version: u64,
    role: ProducerRole,
    instance_id: Option<String>,
    plugin_generation: Option<String>,
    runtime_instance_nonce: Option<String>,
    checkpoint_bytes: u64,
    backlog_bytes: u64,
    backlog_age_ms: Option<u64>,
    events_dropped_total: u64,
    events_malformed_total: u64,
    transport_state: ProducerTransportState,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerHealthV3 {
    version: u64,
    message_type: String,
    runtime_role: String,
    plugin_generation: String,
    runtime_instance_nonce: String,
    checkpoint_bytes: u64,
    backlog_bytes: u64,
    backlog_age_ms: Option<u64>,
    events_dropped_total: u64,
    events_malformed_total: u64,
    transport_state: String,
}

fn parse_producer_health_v3(text: &str) -> Option<ProducerHealthReport> {
    let report: ProducerHealthV3 = serde_json::from_str(text).ok()?;
    if report.version != 3 || report.message_type != "producer_health" {
        return None;
    }
    let role = ProducerRole::parse(&report.runtime_role)?;
    if !valid_hex_identity(&report.plugin_generation)
        || !valid_hex_identity(&report.runtime_instance_nonce)
        || report.plugin_generation == report.runtime_instance_nonce
    {
        return None;
    }
    let transport_state = match report.transport_state.as_str() {
        "available" => ProducerTransportState::Available,
        "degraded" => ProducerTransportState::Degraded,
        _ => return None,
    };
    Some(ProducerHealthReport {
        version: 3,
        role,
        instance_id: None,
        plugin_generation: Some(report.plugin_generation),
        runtime_instance_nonce: Some(report.runtime_instance_nonce),
        checkpoint_bytes: report.checkpoint_bytes,
        backlog_bytes: report.backlog_bytes,
        backlog_age_ms: report.backlog_age_ms,
        events_dropped_total: report.events_dropped_total,
        events_malformed_total: report.events_malformed_total,
        transport_state,
    })
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
    let (role, instance_id, plugin_generation, runtime_instance_nonce) = match version {
        1 if object.len() == common.len()
            && object.keys().all(|key| common.contains(&key.as_str())) =>
        {
            (ProducerRole::Legacy, None, None, None)
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
            (role, Some(instance.to_owned()), None, None)
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
        version,
        role,
        instance_id,
        plugin_generation,
        runtime_instance_nonce,
        checkpoint_bytes: object.get("checkpoint_bytes")?.as_u64()?,
        backlog_bytes: object.get("backlog_bytes")?.as_u64()?,
        backlog_age_ms,
        events_dropped_total: object.get("events_dropped_total")?.as_u64()?,
        events_malformed_total: object.get("events_malformed_total")?.as_u64()?,
        transport_state,
    })
}

fn valid_hex_identity(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalEventTransportV3 {
    version: u64,
    message_type: String,
    runtime_role: String,
    plugin_generation: String,
    runtime_instance_nonce: String,
    event: Box<RawValue>,
}

fn parse_v3_event_transport(text: &str) -> Option<(ProducerRole, String, String, Box<RawValue>)> {
    let envelope: CanonicalEventTransportV3 = serde_json::from_str(text).ok()?;
    if envelope.version != 3 || envelope.message_type != "canonical_event" {
        return None;
    }
    let role = ProducerRole::parse(&envelope.runtime_role)?;
    if !valid_hex_identity(&envelope.plugin_generation)
        || !valid_hex_identity(&envelope.runtime_instance_nonce)
        || envelope.plugin_generation == envelope.runtime_instance_nonce
    {
        return None;
    }
    Some((
        role,
        envelope.plugin_generation,
        envelope.runtime_instance_nonce,
        envelope.event,
    ))
}

struct DuplicateRejectingJson;

impl<'de> Deserialize<'de> for DuplicateRejectingJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateRejectingJsonVisitor)
    }
}

struct DuplicateRejectingJsonVisitor;

impl<'de> Visitor<'de> for DuplicateRejectingJsonVisitor {
    type Value = DuplicateRejectingJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<DuplicateRejectingJson>()?.is_some() {}
        Ok(DuplicateRejectingJson)
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            object.next_value::<DuplicateRejectingJson>()?;
        }
        Ok(DuplicateRejectingJson)
    }
}

fn has_no_duplicate_json_keys(input: &str) -> bool {
    serde_json::from_str::<DuplicateRejectingJson>(input).is_ok()
}

struct ProducerHealthFrameProbe {
    contains_producer_health_type: bool,
}

impl<'de> Deserialize<'de> for ProducerHealthFrameProbe {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ProducerHealthFrameProbeVisitor)
    }
}

struct ProducerHealthFrameProbeVisitor;

impl<'de> Visitor<'de> for ProducerHealthFrameProbeVisitor {
    type Value = ProducerHealthFrameProbe;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON producer frame object")
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut contains_producer_health_type = false;
        while let Some(key) = object.next_key::<String>()? {
            let value = object.next_value::<Box<RawValue>>()?;
            if key == "message_type"
                && serde_json::from_str::<String>(value.get()).ok().as_deref()
                    == Some("producer_health")
            {
                contains_producer_health_type = true;
            }
        }
        Ok(ProducerHealthFrameProbe {
            contains_producer_health_type,
        })
    }
}

fn is_producer_health_frame(input: &str) -> Option<bool> {
    serde_json::from_str::<ProducerHealthFrameProbe>(input)
        .ok()
        .map(|probe| probe.contains_producer_health_type)
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
    /// Derived incident identifiers rejected because sanitized evidence differed.
    pub incident_integrity_collision_total: u64,
    /// Events persisted while a bounded candidate subset was evaluated and truncated.
    pub correlation_truncated_total: u64,
    /// Transactional storage/correlation failures.
    pub storage_errors_total: u64,
}

impl Default for IngestionHealth {
    fn default() -> Self {
        Self::with_required_reported_roles(Vec::new())
    }
}

impl IngestionHealth {
    /// Create process-lifetime health state with optional required reported roles.
    #[must_use]
    pub fn with_required_reported_roles(required_reported_roles: Vec<ProducerRole>) -> Self {
        Self::with_required_reported_roles_and_retention(
            required_reported_roles,
            DEFAULT_STALE_SOURCE_RETENTION,
        )
    }

    /// Create health state with explicit stale-source retention for deterministic tests.
    #[must_use]
    pub fn with_required_reported_roles_and_retention(
        required_reported_roles: Vec<ProducerRole>,
        stale_source_retention: Duration,
    ) -> Self {
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
            incident_integrity_collisions: AtomicU64::new(0),
            correlation_truncated: AtomicU64::new(0),
            storage_errors: AtomicU64::new(0),
            last_degraded_at_unix_ms: AtomicU64::new(0),
            listener_live: AtomicBool::new(false),
            last_event_received_at_unix_ms: AtomicU64::new(0),
            last_event_committed_at_unix_ms: AtomicU64::new(0),
            required_reported_roles,
            stale_source_retention,
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
            incident_integrity_collision_total: self
                .incident_integrity_collisions
                .load(Ordering::Relaxed),
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
    #[allow(clippy::too_many_lines)]
    pub fn status_json(&self, stale_after: Duration) -> serde_json::Value {
        let snapshot = self.snapshot();
        let now = unix_ms_now();
        let stale_after_ms = u64::try_from(stale_after.as_millis()).unwrap_or(u64::MAX);
        let mut sources = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        evict_stale_sources(&mut sources, now, self.stale_source_retention);
        let mut source_values = Vec::with_capacity(sources.len());
        let mut producer_count = 0usize;
        let mut fresh_producer_count = 0usize;
        let mut producer_degraded = false;
        let mut any_fresh_heartbeat = false;
        for ((uid, role, generation, nonce), source) in sources.iter() {
            let (value, has_report, is_degraded, fresh_heartbeat) = source_status_json(
                *uid,
                *role,
                generation.as_deref(),
                nonce.as_deref(),
                source,
                now,
                stale_after_ms,
            );
            producer_count += usize::from(has_report);
            fresh_producer_count += usize::from(fresh_heartbeat);
            producer_degraded |= is_degraded;
            any_fresh_heartbeat |= fresh_heartbeat;
            source_values.push(value);
        }
        let mut required_values = Vec::with_capacity(self.required_reported_roles.len());
        let mut required_degraded = false;
        for required in &self.required_reported_roles {
            let mut present = false;
            let mut fresh = false;
            for ((_, role, _, _), source) in sources.iter() {
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
            || fresh_producer_count == 0
            || producer_degraded
            || required_degraded
            || recently_degraded;
        json!({
            "state": if degraded { "degraded" } else { "healthy" },
            "role_identity_assurance": "authorized_uid_self_reported",
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
            "required_reported_roles": required_values,
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
            "incident_integrity_collision_total": snapshot.incident_integrity_collision_total,
            "correlation_truncated_total": snapshot.correlation_truncated_total,
            "storage_errors_total": snapshot.storage_errors_total,
            "sources": source_values,
        })
    }

    fn record_source_error(&self, key: &SourceKey, category: &'static str) {
        self.record_source_error_for_peer(key, category, None);
    }

    fn record_source_error_for_peer(
        &self,
        key: &SourceKey,
        category: &'static str,
        peer: Option<KernelPeerIdentity>,
    ) {
        let mut sources = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if sources.contains_key(key) || sources.len() < MAX_HEALTH_SOURCES {
            let source = sources.entry(key.clone()).or_default();
            if key.2.is_some() && key.3.is_some() {
                source.protocol_version = 3;
                source.plugin_generation.clone_from(&key.2);
                source.runtime_instance_nonce.clone_from(&key.3);
            }
            if let Some(peer) = peer {
                source.bind_kernel_peer(peer);
            }
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

    fn record_event_received(&self, key: &SourceKey, peer: KernelPeerIdentity) {
        let now = unix_ms_now();
        self.last_event_received_at_unix_ms
            .store(now, Ordering::Relaxed);
        let mut sources = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if sources.contains_key(key) || sources.len() < MAX_HEALTH_SOURCES {
            let source = sources.entry(key.clone()).or_default();
            if key.2.is_some() && key.3.is_some() {
                source.protocol_version = 3;
                source.plugin_generation.clone_from(&key.2);
                source.runtime_instance_nonce.clone_from(&key.3);
            }
            source.last_event_received_at_unix_ms = Some(now);
            source.bind_kernel_peer(peer);
        }
    }

    fn record_result(
        &self,
        key: &SourceKey,
        event: &CanonicalEventEnvelope,
        result: &ContinuousIngestResult,
    ) {
        let mut sources = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !sources.contains_key(key) && sources.len() >= MAX_HEALTH_SOURCES {
            if result.status == ContinuousIngestStatus::Persisted {
                self.last_event_committed_at_unix_ms
                    .store(unix_ms_now(), Ordering::Relaxed);
            }
            return;
        }
        let source = sources.entry(key.clone()).or_default();
        match result.status {
            ContinuousIngestStatus::Persisted => {
                let now = unix_ms_now();
                source.last_event_committed_at_unix_ms = Some(now);
                source.events_persisted_total = source.events_persisted_total.saturating_add(1);
                self.last_event_committed_at_unix_ms
                    .store(now, Ordering::Relaxed);
                if valid_attestation_event_id(event.event_id.as_str()) {
                    source.last_persisted_canary_event_id =
                        Some(event.event_id.as_str().to_owned());
                    source.last_persisted_canary_receipt_status = Some("persisted");
                    source.last_persisted_canary_incidents_opened =
                        u64::try_from(result.opened_incidents).ok();
                }
            }
            ContinuousIngestStatus::Duplicate => {
                source.events_duplicate_total = source.events_duplicate_total.saturating_add(1);
            }
            ContinuousIngestStatus::Collision => {
                source.events_collision_total = source.events_collision_total.saturating_add(1);
            }
        }
    }

    fn record_producer_health(
        &self,
        uid: u32,
        report: &ProducerHealthReport,
        peer: KernelPeerIdentity,
    ) -> bool {
        let mut sources = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = unix_ms_now();
        evict_stale_sources(&mut sources, now, self.stale_source_retention);
        let key = source_key_for_report(uid, report);
        if !sources.contains_key(&key) && sources.len() >= MAX_HEALTH_SOURCES {
            return false;
        }
        let source = sources.entry(key).or_default();
        source.instance_id.clone_from(&report.instance_id);
        source.protocol_version = report.version;
        source
            .plugin_generation
            .clone_from(&report.plugin_generation);
        source
            .runtime_instance_nonce
            .clone_from(&report.runtime_instance_nonce);
        source.bind_kernel_peer(peer);
        source.producer_checkpoint_bytes = Some(report.checkpoint_bytes);
        source.backlog_bytes = Some(report.backlog_bytes);
        source.backlog_age_ms = report.backlog_age_ms;
        source.events_dropped_total = report.events_dropped_total;
        source.producer_events_malformed_total = report.events_malformed_total;
        source.transport_state = Some(report.transport_state);
        source.producer_reported_at_unix_ms = Some(now);
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

fn legacy_source_key(uid: u32) -> SourceKey {
    (uid, ProducerRole::Legacy, None, None)
}

fn source_key_for_report(uid: u32, report: &ProducerHealthReport) -> SourceKey {
    (
        uid,
        report.role,
        report.plugin_generation.clone(),
        report
            .runtime_instance_nonce
            .clone()
            .or_else(|| report.instance_id.clone()),
    )
}

fn v3_source_key(uid: u32, role: ProducerRole, generation: String, nonce: String) -> SourceKey {
    (uid, role, Some(generation), Some(nonce))
}

fn source_id_for_key(key: &SourceKey) -> String {
    match (&key.2, &key.3) {
        (Some(generation), Some(nonce)) => {
            format!("uid:{}:{}:{generation}:{nonce}", key.0, key.1.as_str())
        }
        _ => format!("uid:{}", key.0),
    }
}

fn valid_attestation_event_id(value: &str) -> bool {
    value
        .strip_prefix("evt_skynet_attest_")
        .is_some_and(valid_hex_identity)
}

fn is_degrading_error(category: &str) -> bool {
    matches!(
        category,
        "frame_timeout" | "storage" | "transaction" | "incident_collision"
    )
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn source_last_activity(source: &SourceHealth) -> Option<u64> {
    [
        source.producer_reported_at_unix_ms,
        source.last_event_received_at_unix_ms,
        source.last_event_committed_at_unix_ms,
        source.last_error_at_unix_ms,
    ]
    .into_iter()
    .flatten()
    .max()
}

fn evict_stale_sources(
    sources: &mut BTreeMap<SourceKey, SourceHealth>,
    now: u64,
    retention: Duration,
) {
    let retention_ms = u64::try_from(retention.as_millis()).unwrap_or(u64::MAX);
    sources.retain(|_, source| {
        source_last_activity(source).is_none_or(|at| now.saturating_sub(at) <= retention_ms)
    });
}

fn source_status_json(
    uid: u32,
    role: ProducerRole,
    generation: Option<&str>,
    nonce_or_instance: Option<&str>,
    source: &SourceHealth,
    now: u64,
    stale_after_ms: u64,
) -> (serde_json::Value, bool, bool, bool) {
    let has_report = source.producer_reported_at_unix_ms.is_some();
    let stale = source
        .producer_reported_at_unix_ms
        .is_some_and(|reported| now.saturating_sub(reported) > stale_after_ms);
    let transport_state = if stale {
        "stale"
    } else {
        match source.transport_state {
            Some(ProducerTransportState::Available) => "available",
            Some(ProducerTransportState::Degraded) => "degraded",
            None => "unknown",
        }
    };
    let recent_degrading_error = source.last_error_category.is_some_and(|category| {
        is_degrading_error(category)
            && source
                .last_error_at_unix_ms
                .is_some_and(|at| now.saturating_sub(at) <= stale_after_ms)
    });
    let degraded = has_report
        && !stale
        && (source.transport_state == Some(ProducerTransportState::Degraded)
            || source.backlog_bytes.unwrap_or(0) > 0
            || recent_degrading_error);
    let source_id = match (generation, nonce_or_instance) {
        (Some(generation), Some(nonce)) => {
            format!("uid:{uid}:{}:{generation}:{nonce}", role.as_str())
        }
        (None, Some(instance)) => format!("uid:{uid}:{}:{instance}", role.as_str()),
        _ => format!("uid:{uid}"),
    };
    let value = json!({
        "source_id": source_id,
        "authenticated_uid": uid,
        "runtime_role": role.as_str(),
        "protocol_version": source.protocol_version,
        "s3_eligible": source.protocol_version == 3
            && source.producer_reported_at_unix_ms.is_some()
            && source.plugin_generation.is_some()
            && source.runtime_instance_nonce.is_some()
            && source.kernel_peer_pid.is_some_and(|pid| pid > 0)
            && source.kernel_peer_start_ticks.is_some(),
        "instance_id": source.instance_id,
        "plugin_generation": source.plugin_generation,
        "runtime_instance_nonce": source.runtime_instance_nonce,
        "kernel_peer_pid": source.kernel_peer_pid,
        "kernel_peer_start_ticks": source.kernel_peer_start_ticks,
        "commit_sequence": source.events_persisted_total,
        "events_persisted_total": source.events_persisted_total,
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
        "last_error_age_ms": source.last_error_at_unix_ms.map(|at| now.saturating_sub(at)),
        "producer_reported_at_unix_ms": source.producer_reported_at_unix_ms,
        "producer_report_age_ms": source.producer_reported_at_unix_ms.map(|at| now.saturating_sub(at)),
        "transport_state": transport_state,
        "last_persisted_canary_event_id": source.last_persisted_canary_event_id,
        "last_persisted_canary_receipt_status": source.last_persisted_canary_receipt_status,
        "last_persisted_canary_incidents_opened": source.last_persisted_canary_incidents_opened,
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

/// Capture kernel-authenticated peer credentials and stable process evidence once.
///
/// # Errors
///
/// Returns an error when credentials or opened-proc identity evidence is unavailable.
pub fn authenticate_ingest_peer(stream: &UnixStream) -> io::Result<AuthenticatedPeer> {
    let credentials = getsockopt(stream, PeerCredentials).map_err(io::Error::other)?;
    let pid = credentials.pid();
    if pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer credentials did not contain a positive PID",
        ));
    }
    let pidfd = peer_pidfd(stream)?;
    verify_pidfd_pid(&pidfd, pid)?;
    let proc_fd = open(
        format!("/proc/{pid}").as_str(),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::other)?;
    let proc_dir = File::from(proc_fd);
    let process_start_ticks = read_process_start_ticks(&proc_dir)?;
    verify_pidfd_pid(&pidfd, pid)?;
    Ok(AuthenticatedPeer {
        uid: credentials.uid(),
        identity: KernelPeerIdentity {
            pid,
            process_start_ticks,
        },
        pidfd: Some(pidfd),
        proc_dir,
    })
}

fn peer_pidfd(stream: &UnixStream) -> io::Result<OwnedFd> {
    getsockopt(stream, PeerPidfd).map_err(io::Error::other)
}

fn verify_pidfd_pid(pidfd: &OwnedFd, expected_pid: i32) -> io::Result<()> {
    let path = format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd());
    let mut fdinfo = String::new();
    File::open(path)?.take(4_097).read_to_string(&mut fdinfo)?;
    if fdinfo.len() > 4_096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer pidfd metadata exceeded bound",
        ));
    }
    let observed_pid = fdinfo.lines().find_map(|line| {
        line.strip_prefix("Pid:")
            .and_then(|value| value.trim().parse::<i32>().ok())
    });
    if observed_pid != Some(expected_pid) || expected_pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer pidfd no longer identifies the accepted process",
        ));
    }
    Ok(())
}

fn read_process_start_ticks(proc_dir: &File) -> io::Result<u64> {
    let stat_fd = openat(
        proc_dir,
        "stat",
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(io::Error::other)?;
    let mut stat = String::new();
    File::from(stat_fd).take(4_097).read_to_string(&mut stat)?;
    if stat.len() > 4_096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer process stat exceeded bound",
        ));
    }
    parse_process_start_ticks(&stat).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "peer process stat was malformed",
        )
    })
}

fn parse_process_start_ticks(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    stat.get(close + 1..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn handle_producer_health_frame(
    text: &str,
    stream: &mut UnixStream,
    uid: u32,
    peer: &AuthenticatedPeer,
    health: &IngestionHealth,
) -> Option<io::Result<()>> {
    if !is_producer_health_frame(text)? {
        return None;
    }
    if !has_no_duplicate_json_keys(text) {
        health.invalid.fetch_add(1, Ordering::Relaxed);
        return Some(write_ack(
            stream,
            &json!({"version":1,"status":"rejected_permanent","reason":"invalid_health"}),
        ));
    }
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    let report = if value.get("version").and_then(serde_json::Value::as_u64) == Some(3) {
        parse_producer_health_v3(text)
    } else {
        parse_producer_health(&value)
    };
    let Some(report) = report else {
        health.invalid.fetch_add(1, Ordering::Relaxed);
        return Some(write_ack(
            stream,
            &json!({"version":1,"status":"rejected_permanent","reason":"invalid_health"}),
        ));
    };
    let kernel_identity = if report.version == 3 {
        if let Ok(identity) = peer.verified_kernel_identity() {
            identity
        } else {
            health.invalid.fetch_add(1, Ordering::Relaxed);
            return Some(write_ack(
                stream,
                &json!({"version":1,"status":"rejected_permanent","reason":"peer_identity"}),
            ));
        }
    } else {
        peer.identity
    };
    if !health.record_producer_health(uid, &report, kernel_identity) {
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
    source_key: &SourceKey,
    peer: KernelPeerIdentity,
    config: &UnixIngestConfig,
    db_path: &Path,
    health: &IngestionHealth,
    event: &CanonicalEventEnvelope,
) -> io::Result<()> {
    health.record_event_received(source_key, peer);
    let Ok(store) = LocalStore::open_existing_writable(db_path) else {
        health.storage_errors.fetch_add(1, Ordering::Relaxed);
        health.record_source_error(source_key, "storage");
        return write_ack(
            stream,
            &json!({"version":1,"status":"retry_later","reason":"storage"}),
        );
    };
    let source_id = source_id_for_key(source_key);
    match store.commit_continuous_event(
        &source_id,
        event,
        &built_in_ai_agent_sequence_rules(),
        config.candidate_limit,
    ) {
        Ok(result) => {
            health.record_result(source_key, event, &result);
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
        }
        Err(ContinuousIngestError::Canonical(_)) => {
            health.invalid.fetch_add(1, Ordering::Relaxed);
            health.record_source_error(source_key, "invalid_event");
            write_ack(
                stream,
                &json!({"version":1,"event_id":event.event_id.as_str(),"status":"rejected_permanent","reason":"invalid_event"}),
            )
        }
        Err(ContinuousIngestError::IncidentCollision { .. }) => {
            health
                .incident_integrity_collisions
                .fetch_add(1, Ordering::Relaxed);
            health.record_source_error(source_key, "incident_collision");
            write_ack(
                stream,
                &json!({"version":1,"event_id":event.event_id.as_str(),"status":"rejected_permanent","reason":"incident_collision"}),
            )
        }
        Err(_) => {
            health.storage_errors.fetch_add(1, Ordering::Relaxed);
            health.record_source_error(source_key, "transaction");
            write_ack(
                stream,
                &json!({"version":1,"event_id":event.event_id.as_str(),"status":"retry_later","reason":"transaction"}),
            )
        }
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
#[allow(clippy::too_many_lines)]
pub fn process_ingest_connection(
    mut stream: UnixStream,
    peer: &AuthenticatedPeer,
    config: &UnixIngestConfig,
    db_path: &Path,
    health: &IngestionHealth,
) -> io::Result<()> {
    let uid = peer.uid;
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
    let legacy_key = legacy_source_key(uid);
    stream.set_write_timeout(Some(config.write_timeout))?;
    let read_deadline = Instant::now() + config.read_timeout;

    let mut header = [0_u8; 4];
    if let Err(error) = read_exact_until(&mut stream, &mut header, read_deadline) {
        if is_timeout(&error) {
            health.timed_out.fetch_add(1, Ordering::Relaxed);
            health.record_source_error(&legacy_key, "frame_timeout");
        } else {
            health.invalid.fetch_add(1, Ordering::Relaxed);
            health.record_source_error(&legacy_key, "malformed_frame");
        }
        return Ok(());
    }
    let declared = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length is unsupported"))?;
    if declared == 0 || declared > config.max_frame_bytes {
        health.oversized.fetch_add(1, Ordering::Relaxed);
        health.record_source_error(&legacy_key, "frame_size");
        return write_ack(
            &mut stream,
            &json!({"version":1,"status":"rejected_permanent","reason":"frame_size"}),
        );
    }

    let mut body = vec![0_u8; declared];
    if let Err(error) = read_exact_until(&mut stream, &mut body, read_deadline) {
        if is_timeout(&error) {
            health.timed_out.fetch_add(1, Ordering::Relaxed);
            health.record_source_error(&legacy_key, "frame_timeout");
        } else {
            health.invalid.fetch_add(1, Ordering::Relaxed);
            health.record_source_error(&legacy_key, "malformed_frame");
        }
        return Ok(());
    }
    health.received.fetch_add(1, Ordering::Relaxed);
    let Ok(text) = std::str::from_utf8(&body) else {
        health.invalid.fetch_add(1, Ordering::Relaxed);
        health.record_source_error(&legacy_key, "malformed_frame");
        return write_ack(
            &mut stream,
            &json!({"version":1,"status":"rejected_permanent","reason":"invalid_event"}),
        );
    };
    if let Some(result) = handle_producer_health_frame(text, &mut stream, uid, peer, health) {
        return result;
    }
    let message_type = serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| {
            value
                .get("message_type")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    if message_type.as_deref() == Some("canonical_event") {
        let Some((role, generation, nonce, raw_event)) = parse_v3_event_transport(text) else {
            health.invalid.fetch_add(1, Ordering::Relaxed);
            health.record_source_error(&legacy_key, "malformed_frame");
            return write_ack(
                &mut stream,
                &json!({"version":1,"status":"rejected_permanent","reason":"invalid_event"}),
            );
        };
        let source_key = v3_source_key(uid, role, generation, nonce);
        let Ok(kernel_identity) = peer.verified_kernel_identity() else {
            health.invalid.fetch_add(1, Ordering::Relaxed);
            return write_ack(
                &mut stream,
                &json!({"version":1,"status":"rejected_permanent","reason":"peer_identity"}),
            );
        };
        let event_text = raw_event.get();
        let Some(event) = has_no_duplicate_json_keys(event_text)
            .then(|| parse_canonical_event_json(event_text))
            .and_then(Result::ok)
        else {
            health.invalid.fetch_add(1, Ordering::Relaxed);
            health.record_source_error_for_peer(
                &source_key,
                "malformed_frame",
                Some(kernel_identity),
            );
            return write_ack(
                &mut stream,
                &json!({"version":1,"status":"rejected_permanent","reason":"invalid_event"}),
            );
        };
        return commit_event_and_ack(
            &mut stream,
            &source_key,
            kernel_identity,
            config,
            db_path,
            health,
            &event,
        );
    }
    let Ok(event) = parse_canonical_event_json(text) else {
        health.invalid.fetch_add(1, Ordering::Relaxed);
        health.record_source_error(&legacy_key, "malformed_frame");
        return write_ack(
            &mut stream,
            &json!({"version":1,"status":"rejected_permanent","reason":"invalid_event"}),
        );
    };
    commit_event_and_ack(
        &mut stream,
        &legacy_key,
        peer.identity,
        config,
        db_path,
        health,
        &event,
    )
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

    fn fake_proc_stat(start_ticks: &str) -> String {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[19] = start_ticks;
        format!("123 (fake peer) {}", fields.join(" "))
    }

    #[test]
    fn captured_peer_pidfd_matches_socket_peer_and_verifies() {
        let (_client, server) = UnixStream::pair().expect("stream pair opens");
        let peer = authenticate_ingest_peer(&server).expect("peer capture succeeds");

        assert!(peer.pidfd.is_some());
        assert!(peer.identity.pid > 0);
        assert_eq!(
            peer.verified_kernel_identity()
                .expect("live peer identity verifies"),
            peer.identity
        );
    }

    #[test]
    fn new_process_on_existing_v3_key_must_report_its_own_health() {
        let health = IngestionHealth::default();
        let report = parse_producer_health_v3(
            r#"{"version":3,"message_type":"producer_health","runtime_role":"gateway","plugin_generation":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","runtime_instance_nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","checkpoint_bytes":0,"backlog_bytes":0,"backlog_age_ms":null,"events_dropped_total":0,"events_malformed_total":0,"transport_state":"available"}"#,
        )
        .expect("valid v3 health parses");
        let key = source_key_for_report(1_234, &report);

        assert!(health.record_producer_health(
            1_234,
            &report,
            KernelPeerIdentity {
                pid: 111,
                process_start_ticks: 10,
            },
        ));
        health.record_event_received(
            &key,
            KernelPeerIdentity {
                pid: 222,
                process_start_ticks: 20,
            },
        );

        let status = health.status_json(Duration::from_secs(30));
        assert_eq!(status["sources"][0]["s3_eligible"], false);
        assert_eq!(status["sources"][0]["kernel_peer_pid"], 222);
    }

    #[test]
    fn opened_proc_identity_rejects_missing_malformed_and_changed_start_ticks() {
        let root =
            std::env::temp_dir().join(format!("skynet-edr-peer-proof-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("proof directory created");
        let proc_dir = fs::File::open(&root).expect("proof directory opens");
        let peer = AuthenticatedPeer::from_open_proc_dir_for_test(1_234, 123, 42, proc_dir);

        assert!(peer.verified_kernel_identity().is_err());
        fs::write(root.join("stat"), "malformed").expect("malformed stat written");
        assert!(peer.verified_kernel_identity().is_err());
        fs::write(root.join("stat"), fake_proc_stat("43")).expect("changed stat written");
        assert!(peer.verified_kernel_identity().is_err());
        fs::write(root.join("stat"), fake_proc_stat("42")).expect("stable stat written");
        assert_eq!(
            peer.verified_kernel_identity()
                .expect("stable identity verifies")
                .process_start_ticks,
            42
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn changed_process_identity_cannot_record_v3_health() {
        let root = std::env::temp_dir().join(format!(
            "skynet-edr-peer-reject-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("proof directory created");
        fs::write(root.join("stat"), fake_proc_stat("43")).expect("changed stat written");
        let proc_dir = fs::File::open(&root).expect("proof directory opens");
        let peer = AuthenticatedPeer::from_open_proc_dir_for_test(1_234, 123, 42, proc_dir);
        let health = IngestionHealth::default();
        let report = json!({
            "version": 3,
            "message_type": "producer_health",
            "runtime_role": "gateway",
            "plugin_generation": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "runtime_instance_nonce": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "checkpoint_bytes": 0,
            "backlog_bytes": 0,
            "backlog_age_ms": null,
            "events_dropped_total": 0,
            "events_malformed_total": 0,
            "transport_state": "available"
        })
        .to_string();
        let (mut client, mut server) = UnixStream::pair().expect("stream pair opens");

        handle_producer_health_frame(&report, &mut server, peer.uid(), &peer, &health)
            .expect("health frame recognized")
            .expect("rejection ack writes");
        drop(server);
        let mut ack = String::new();
        client.read_to_string(&mut ack).expect("ack reads");

        assert!(ack.contains(r#""reason":"peer_identity""#), "{ack}");
        assert!(!ack.contains("health_recorded"));
        assert!(health.status_json(Duration::from_secs(30))["sources"]
            .as_array()
            .expect("sources array")
            .is_empty());
        let _ = fs::remove_dir_all(root);
    }

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
