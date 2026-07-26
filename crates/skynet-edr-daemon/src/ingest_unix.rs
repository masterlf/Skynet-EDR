//! Bounded authenticated Linux `AF_UNIX` continuous ingestion.

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use nix::{
    sys::socket::{getsockopt, sockopt::PeerCredentials},
    unistd::{chown, Gid, Uid},
};
use serde_json::json;
use skynet_edr_core::{
    built_in_ai_agent_sequence_rules, parse_canonical_event_json, ContinuousIngestStatus,
    LocalStore,
};

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
}

/// Bounded aggregate ingestion counters shared with the read-only status projection.
#[derive(Debug, Default)]
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

impl IngestionHealth {
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
    }

    /// Record an accept-loop failure so status cannot remain falsely healthy.
    pub fn record_listener_error(&self) {
        self.listener_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failure to read kernel-authenticated peer credentials.
    pub fn record_peer_credential_error(&self) {
        self.peer_credential_errors.fetch_add(1, Ordering::Relaxed);
    }
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

    let listener = UnixListener::bind(path)?;
    if let Err(error) = secure_bound_socket(path, config.socket_gid) {
        drop(listener);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(listener)
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
        } else {
            health.invalid.fetch_add(1, Ordering::Relaxed);
        }
        return Ok(());
    }
    let declared = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length is unsupported"))?;
    if declared == 0 || declared > config.max_frame_bytes {
        health.oversized.fetch_add(1, Ordering::Relaxed);
        return write_ack(
            &mut stream,
            &json!({"version":1,"status":"rejected_permanent","reason":"frame_size"}),
        );
    }

    let mut body = vec![0_u8; declared];
    if let Err(error) = read_exact_until(&mut stream, &mut body, read_deadline) {
        if is_timeout(&error) {
            health.timed_out.fetch_add(1, Ordering::Relaxed);
        } else {
            health.invalid.fetch_add(1, Ordering::Relaxed);
        }
        return Ok(());
    }
    health.received.fetch_add(1, Ordering::Relaxed);
    let Ok(text) = std::str::from_utf8(&body) else {
        health.invalid.fetch_add(1, Ordering::Relaxed);
        return write_ack(
            &mut stream,
            &json!({"version":1,"status":"rejected_permanent","reason":"invalid_event"}),
        );
    };
    let Ok(event) = parse_canonical_event_json(text) else {
        health.invalid.fetch_add(1, Ordering::Relaxed);
        return write_ack(
            &mut stream,
            &json!({"version":1,"status":"rejected_permanent","reason":"invalid_event"}),
        );
    };

    let Ok(store) = LocalStore::open(db_path) else {
        health.storage_errors.fetch_add(1, Ordering::Relaxed);
        return write_ack(
            &mut stream,
            &json!({"version":1,"status":"retry_later","reason":"storage"}),
        );
    };

    let source_id = format!("uid:{uid}");
    if let Ok(result) = store.commit_continuous_event(
        &source_id,
        &event,
        &built_in_ai_agent_sequence_rules(),
        config.candidate_limit,
    ) {
        if result.correlation_truncated {
            health.correlation_truncated.fetch_add(1, Ordering::Relaxed);
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
                "rejected_permanent"
            }
        };
        write_ack(
            &mut stream,
            &json!({"version":1,"event_id":event.event_id.as_str(),"status":status}),
        )
    } else {
        health.storage_errors.fetch_add(1, Ordering::Relaxed);
        write_ack(
            &mut stream,
            &json!({"version":1,"event_id":event.event_id.as_str(),"status":"retry_later","reason":"transaction"}),
        )
    }
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
