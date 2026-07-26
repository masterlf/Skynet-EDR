//! Minimal daemon entry point for Skynet-EDR.

use std::{
    env, fs, io,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
    thread,
    time::Duration,
};

use skynet_edr_core::{ingest_canonical_jsonl_spool, LocalStore, ProductInfo};
use skynet_edr_daemon::{
    bind_ingest_listener, handle_console_request, handle_http_request, peer_uid,
    process_ingest_connection, HttpMethod, IngestionHealth, UnixIngestConfig,
};

static ACTIVE_INGESTION_HEALTH: OnceLock<Arc<IngestionHealth>> = OnceLock::new();

fn main() -> ExitCode {
    let mut args = env::args();
    let binary = args
        .next()
        .unwrap_or_else(|| "skynet-edr-daemon".to_owned());
    let remaining = args.collect::<Vec<_>>();

    match remaining.first().map(String::as_str) {
        None | Some("status") => {
            if remaining.len() > 1 {
                print_unexpected_args(&binary, &remaining[1..]);
                return ExitCode::FAILURE;
            }
            print_status();
            ExitCode::SUCCESS
        }
        Some("run") => match run_command(&remaining[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                eprintln!("try '{binary} --help'");
                ExitCode::FAILURE
            }
        },
        Some("--help" | "-h" | "help") => {
            print_help(&binary);
            ExitCode::SUCCESS
        }
        Some("--version" | "-V") => {
            println!("skynet-edr-daemon {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(command) => {
            eprintln!("unknown daemon command: {command}");
            eprintln!("try '{binary} --help'");
            ExitCode::FAILURE
        }
    }
}

fn print_unexpected_args(binary: &str, args: &[String]) {
    eprintln!("unexpected daemon argument(s): {}", args.join(" "));
    eprintln!("try '{binary} --help'");
}

fn print_status() {
    let info = ProductInfo::default();
    println!(
        "{} daemon status: mode={} sensors=not-started",
        info.name,
        info.run_mode.as_str()
    );
}

fn print_help(binary: &str) {
    println!("Usage: {binary} [status|run --config <path>|--version|--help]");
    println!();
    println!("Commands:");
    println!("  status               Print daemon status without starting privileged sensors");
    println!("  run --config <path>  Start the passive long-running daemon service path");
    println!("                         Optionally polls [spool] canonical JSONL ingestion");
    println!();
    println!("Safety:");
    println!(
        "  run validates passive mode, loopback read-only API, and disabled privileged sensors"
    );
}

fn run_command(args: &[String]) -> Result<(), DaemonCliError> {
    let config_path = parse_run_args(args)?;
    let config = DaemonConfig::load(&config_path)?;
    config.validate()?;

    println!(
        "daemon run: mode={} http_api={} sensors=not-started privileged_sensors=disabled",
        config.mode,
        config
            .http_api_bind
            .map_or_else(|| "disabled".to_owned(), |bind| bind.to_string())
    );

    initialize_active_store(&config)?;
    run_spool_ingestion_once(&config)?;
    let ingest_server = start_ingestion_if_enabled(&config)?;
    let http_server = start_http_api_if_enabled(&config)?;

    if should_exit_after_startup_for_test() {
        drop((ingest_server, http_server));
        return Ok(());
    }

    loop {
        thread::sleep(Duration::from_secs(5));
        run_spool_ingestion_once(&config)?;
    }
}

fn initialize_active_store(config: &DaemonConfig) -> Result<(), DaemonCliError> {
    if !config.http_api_enabled && config.spool.is_none() && config.ingest.is_none() {
        return Ok(());
    }

    let store_path = config.http_store_path();
    drop(LocalStore::open(&store_path)?);
    Ok(())
}

fn start_ingestion_if_enabled(
    config: &DaemonConfig,
) -> Result<Option<thread::JoinHandle<()>>, DaemonCliError> {
    let Some(ingest) = config.ingest.clone() else {
        return Ok(None);
    };
    let listener = bind_ingest_listener(&ingest).map_err(|error| {
        DaemonCliError::new(format!("failed to bind Unix ingestion listener: {error}"))
    })?;
    let db_path = config.http_store_path();
    let health = Arc::new(IngestionHealth::default());
    let _ = ACTIVE_INGESTION_HEALTH.set(Arc::clone(&health));
    let active = Arc::new(AtomicUsize::new(0));
    println!("unix ingestion listening: {}", ingest.socket_path.display());

    Ok(Some(thread::spawn(move || {
        for accepted in listener.incoming() {
            let Ok(stream) = accepted else {
                health.record_listener_error();
                continue;
            };
            let previous = active.fetch_add(1, Ordering::AcqRel);
            if previous >= ingest.max_connections {
                active.fetch_sub(1, Ordering::AcqRel);
                health.record_capacity_rejection();
                let _ = stream.shutdown(std::net::Shutdown::Both);
                continue;
            }
            let Ok(uid) = peer_uid(&stream) else {
                active.fetch_sub(1, Ordering::AcqRel);
                health.record_peer_credential_error();
                let _ = stream.shutdown(std::net::Shutdown::Both);
                continue;
            };
            let worker_active = Arc::clone(&active);
            let worker_health = Arc::clone(&health);
            let worker_ingest = ingest.clone();
            let worker_db = db_path.clone();
            thread::spawn(move || {
                let _ = process_ingest_connection(
                    stream,
                    uid,
                    &worker_ingest,
                    &worker_db,
                    &worker_health,
                );
                worker_active.fetch_sub(1, Ordering::AcqRel);
            });
        }
    })))
}

fn run_spool_ingestion_once(config: &DaemonConfig) -> Result<(), DaemonCliError> {
    let Some(spool) = &config.spool else {
        return Ok(());
    };
    let store = LocalStore::open(&spool.db)?;
    let summary = ingest_canonical_jsonl_spool(&store, &spool.path, &spool.checkpoint)?;
    println!(
        "spool ingestion: ingested={} opened_incidents={} dropped={} duplicates={} checkpoint={} byte(s)",
        summary.ingested_events,
        summary.opened_incidents,
        summary.dropped_events,
        summary.duplicate_events,
        summary.last_processed_byte
    );
    Ok(())
}

fn start_http_api_if_enabled(
    config: &DaemonConfig,
) -> Result<Option<thread::JoinHandle<()>>, DaemonCliError> {
    if !config.http_api_enabled {
        return Ok(None);
    }

    let bind = config.http_api_bind.ok_or_else(|| {
        DaemonCliError::new("HTTP API is enabled but no bind address is configured")
    })?;
    let store_path = config.http_store_path();
    let read_only_store = LocalStore::open_read_only(&store_path)?;
    read_only_store.count_incidents()?;
    read_only_store.count_events()?;
    drop(read_only_store);
    let listener = TcpListener::bind(bind).map_err(|error| {
        DaemonCliError::new(format!(
            "failed to bind read-only HTTP API on {bind}: {error}"
        ))
    })?;

    println!("http api listening: {bind}");
    Ok(Some(thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => handle_http_connection(stream, &store_path),
                Err(error) => eprintln!("HTTP API accept failed: {error}"),
            }
        }
    })))
}

fn handle_http_connection(mut stream: TcpStream, store_path: &Path) {
    if let Err(error) = write_http_connection_response(&mut stream, store_path) {
        let _ = write_raw_http_response(
            &mut stream,
            500,
            "application/json",
            &format!(r#"{{"error":"internal_server_error","message":"{error}"}}"#),
        );
    }
}

fn write_http_connection_response(
    stream: &mut TcpStream,
    store_path: &Path,
) -> Result<(), DaemonCliError> {
    let mut buffer = [0_u8; 8192];
    let bytes_read = stream
        .read(&mut buffer)
        .map_err(|error| DaemonCliError::new(format!("failed to read HTTP request: {error}")))?;
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let Some(request_line) = request.lines().next() else {
        return write_raw_http_response(
            stream,
            400,
            "application/json",
            r#"{"error":"bad_request"}"#,
        )
        .map_err(|error| DaemonCliError::new(format!("failed to write HTTP response: {error}")));
    };
    let mut parts = request_line.split_whitespace();
    let method = parse_http_method(parts.next().unwrap_or_default());
    let raw_path = parts.next().unwrap_or("/");
    let path = raw_path.split('?').next().unwrap_or(raw_path);

    let store = LocalStore::open_read_only(store_path)?;
    if path == "/" || path.starts_with("/console") {
        let response = handle_console_request(&store, method, path)
            .map_err(|error| DaemonCliError::new(format!("console request failed: {error}")))?;
        write_raw_http_response(
            stream,
            response.status.as_u16(),
            response.content_type,
            &response.body,
        )
    } else {
        let mut response = handle_http_request(&store, method, raw_path)
            .map_err(|error| DaemonCliError::new(format!("HTTP API request failed: {error}")))?;
        if path == "/api/status" {
            if let Some(object) = response.body.as_object_mut() {
                let ingestion = if let Some(health) = ACTIVE_INGESTION_HEALTH.get() {
                    let snapshot = health.snapshot();
                    let state = if snapshot.storage_errors_total > 0
                        || snapshot.frames_timeout_total > 0
                        || snapshot.correlation_truncated_total > 0
                        || snapshot.connections_capacity_rejected_total > 0
                        || snapshot.listener_errors_total > 0
                        || snapshot.peer_credential_errors_total > 0
                    {
                        "degraded"
                    } else {
                        "healthy"
                    };
                    serde_json::json!({
                        "state": state,
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
                    })
                } else {
                    serde_json::json!({"state":"disabled"})
                };
                object.insert("ingestion".to_owned(), ingestion);
            }
        }
        write_raw_http_response(
            stream,
            response.status.as_u16(),
            response.content_type,
            &response.body.to_string(),
        )
    }
    .map_err(|error| DaemonCliError::new(format!("failed to write HTTP response: {error}")))
}

fn parse_http_method(method: &str) -> HttpMethod {
    match method {
        "GET" => HttpMethod::Get,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        _ => HttpMethod::Post,
    }
}

fn write_raw_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Response",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn should_exit_after_startup_for_test() -> bool {
    cfg!(debug_assertions) && env::var_os("SKYNET_EDR_DAEMON_EXIT_AFTER_STARTUP").is_some()
}

fn parse_run_args(args: &[String]) -> Result<PathBuf, DaemonCliError> {
    match args {
        [flag, path] if flag == "--config" => Ok(PathBuf::from(path)),
        [] => Err(DaemonCliError::new("run requires --config <path>")),
        [flag] if flag == "--config" => Err(DaemonCliError::new("run requires --config <path>")),
        [flag, ..] if flag != "--config" => Err(DaemonCliError::new(format!(
            "unknown run argument: {flag}; run requires --config <path>"
        ))),
        _ => Err(DaemonCliError::new(
            "run accepts only --config <path>; refusing ambiguous service startup",
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DaemonConfig {
    mode: String,
    data_dir: PathBuf,
    http_api_enabled: bool,
    http_api_bind: Option<SocketAddr>,
    http_api_read_only: bool,
    linux_privileged_sensors: bool,
    spool: Option<SpoolConfig>,
    ingest: Option<UnixIngestConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpoolConfig {
    db: PathBuf,
    path: PathBuf,
    checkpoint: PathBuf,
}

impl DaemonConfig {
    fn load(path: &Path) -> Result<Self, DaemonCliError> {
        let content = fs::read_to_string(path).map_err(|error| {
            DaemonCliError::new(format!(
                "failed to read daemon config {}: {error}",
                path.display()
            ))
        })?;
        Self::parse(&content)
    }

    #[allow(clippy::too_many_lines)]
    fn parse(content: &str) -> Result<Self, DaemonCliError> {
        let mut config = Self {
            mode: "passive".to_owned(),
            data_dir: PathBuf::from("/var/lib/skynet-edr"),
            http_api_enabled: false,
            http_api_bind: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8787)),
            http_api_read_only: true,
            linux_privileged_sensors: false,
            spool: None,
            ingest: None,
        };
        let mut spool_enabled = false;
        let mut spool_db: Option<PathBuf> = None;
        let mut spool_path: Option<PathBuf> = None;
        let mut spool_checkpoint: Option<PathBuf> = None;
        let mut ingest_enabled = false;
        let mut ingest_socket = PathBuf::from("/run/skynet-edr-ingest/ingest.sock");
        let mut ingest_socket_gid = None;
        let mut ingest_socket_group = None;
        let mut ingest_allowed_uids = Vec::new();
        let mut ingest_allow_root = false;
        let mut ingest_max_frame_bytes = 262_144;
        let mut ingest_max_connections = 64;
        let mut ingest_read_timeout_ms = 2_000;
        let mut ingest_write_timeout_ms = 2_000;
        let mut ingest_candidate_limit = 10_000;
        let mut section = String::new();
        let mut in_multiline_array = false;

        for (index, raw_line) in content.lines().enumerate() {
            let line = strip_comment(raw_line).trim();
            if in_multiline_array {
                if line.ends_with(']') {
                    in_multiline_array = false;
                }
                continue;
            }
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                line[1..line.len() - 1].trim().clone_into(&mut section);
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                return Err(DaemonCliError::new(format!(
                    "invalid daemon config line {}: expected key = value",
                    index + 1
                )));
            };
            let key = key.trim();
            let value = value.trim();
            if value.starts_with('[') && !value.ends_with(']') {
                in_multiline_array = true;
            }

            match (section.as_str(), key) {
                ("", "mode") => config.mode = parse_string(value, index)?,
                ("", "data_dir") => config.data_dir = PathBuf::from(parse_string(value, index)?),
                ("http_api", "enabled") => config.http_api_enabled = parse_bool(value, index)?,
                ("http_api", "bind") => {
                    let bind = parse_string(value, index)?;
                    config.http_api_bind = Some(bind.parse::<SocketAddr>().map_err(|error| {
                        DaemonCliError::new(format!(
                            "invalid daemon config line {}: http_api.bind is not a socket address: {error}",
                            index + 1
                        ))
                    })?);
                }
                ("http_api", "read_only") => config.http_api_read_only = parse_bool(value, index)?,
                ("sensors", "linux_privileged") => {
                    config.linux_privileged_sensors = parse_bool(value, index)?;
                }
                ("spool", "enabled") => spool_enabled = parse_bool(value, index)?,
                ("spool", "db") => spool_db = Some(PathBuf::from(parse_string(value, index)?)),
                ("spool", "path") => spool_path = Some(PathBuf::from(parse_string(value, index)?)),
                ("spool", "checkpoint") => {
                    spool_checkpoint = Some(PathBuf::from(parse_string(value, index)?));
                }
                ("ingest", "enabled") => ingest_enabled = parse_bool(value, index)?,
                ("ingest", "socket") => {
                    ingest_socket = PathBuf::from(parse_string(value, index)?);
                }
                ("ingest", "socket_gid") => {
                    ingest_socket_gid = Some(parse_u32(value, index, "ingest.socket_gid")?);
                }
                ("ingest", "socket_group") => {
                    ingest_socket_group = Some(parse_string(value, index)?);
                }
                ("ingest", "allowed_uids") => {
                    ingest_allowed_uids = parse_u32_array(value, index, "ingest.allowed_uids")?;
                }
                ("ingest", "allow_root") => ingest_allow_root = parse_bool(value, index)?,
                ("ingest", "max_frame_bytes") => {
                    ingest_max_frame_bytes = parse_usize(value, index, "ingest.max_frame_bytes")?;
                }
                ("ingest", "max_connections") => {
                    ingest_max_connections = parse_usize(value, index, "ingest.max_connections")?;
                }
                ("ingest", "read_timeout_ms") => {
                    ingest_read_timeout_ms = parse_u64(value, index, "ingest.read_timeout_ms")?;
                }
                ("ingest", "write_timeout_ms") => {
                    ingest_write_timeout_ms = parse_u64(value, index, "ingest.write_timeout_ms")?;
                }
                ("ingest", "candidate_limit") => {
                    ingest_candidate_limit = parse_usize(value, index, "ingest.candidate_limit")?;
                }
                _ => {}
            }
        }

        if spool_enabled {
            config.spool = Some(SpoolConfig {
                db: spool_db.ok_or_else(|| {
                    DaemonCliError::new("spool.db is required when spool is enabled")
                })?,
                path: spool_path.ok_or_else(|| {
                    DaemonCliError::new("spool.path is required when spool is enabled")
                })?,
                checkpoint: spool_checkpoint.ok_or_else(|| {
                    DaemonCliError::new("spool.checkpoint is required when spool is enabled")
                })?,
            });
        }

        if ingest_enabled {
            if ingest_socket_gid.is_some() && ingest_socket_group.is_some() {
                return Err(DaemonCliError::new(
                    "configure only one of ingest.socket_gid or ingest.socket_group",
                ));
            }
            if let Some(group_name) = ingest_socket_group.as_deref() {
                ingest_socket_gid = Some(resolve_group_gid(group_name)?);
            }
            config.ingest = Some(UnixIngestConfig {
                socket_path: ingest_socket,
                socket_gid: ingest_socket_gid,
                allowed_uids: ingest_allowed_uids,
                allow_root: ingest_allow_root,
                max_frame_bytes: ingest_max_frame_bytes,
                max_connections: ingest_max_connections,
                read_timeout: Duration::from_millis(ingest_read_timeout_ms),
                write_timeout: Duration::from_millis(ingest_write_timeout_ms),
                candidate_limit: ingest_candidate_limit,
            });
        }

        Ok(config)
    }

    fn http_store_path(&self) -> PathBuf {
        self.spool.as_ref().map_or_else(
            || self.data_dir.join("skynet.sqlite"),
            |spool| spool.db.clone(),
        )
    }

    fn validate(&self) -> Result<(), DaemonCliError> {
        let mut reasons = Vec::new();

        if self.mode != "passive" {
            reasons.push(format!(
                "daemon mode must remain passive for MVP service path; got {}",
                self.mode
            ));
        }
        if self.http_api_enabled {
            match self.http_api_bind {
                Some(bind) if bind.ip().is_loopback() => {}
                Some(_) => reasons.push("HTTP API bind address must be loopback".to_owned()),
                None => reasons.push("HTTP API bind address is required when enabled".to_owned()),
            }
            if !self.http_api_read_only {
                reasons.push("HTTP API must remain read-only".to_owned());
            }
        }
        if self.linux_privileged_sensors {
            reasons.push(
                "privileged Linux sensors are not supported by this passive daemon path".to_owned(),
            );
        }
        if let Some(ingest) = &self.ingest {
            if ingest.max_frame_bytes == 0 || ingest.max_frame_bytes > 262_144 {
                reasons.push("ingest.max_frame_bytes must be within 1..=262144".to_owned());
            }
            if ingest.max_connections == 0 || ingest.max_connections > 64 {
                reasons.push("ingest.max_connections must be within 1..=64".to_owned());
            }
            if ingest.candidate_limit == 0 || ingest.candidate_limit > 10_000 {
                reasons.push("ingest.candidate_limit must be within 1..=10000".to_owned());
            }
            if ingest.read_timeout.is_zero() || ingest.write_timeout.is_zero() {
                reasons.push("ingest timeouts must be greater than zero".to_owned());
            }
            if ingest.allowed_uids.contains(&0) {
                reasons.push("UID 0 requires ingest.allow_root, not allowed_uids".to_owned());
            }
        }

        if reasons.is_empty() {
            Ok(())
        } else {
            Err(DaemonCliError::new(format!(
                "invalid daemon config: {}",
                reasons.join(", ")
            )))
        }
    }
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(before, _)| before)
}

fn parse_string(value: &str, index: usize) -> Result<String, DaemonCliError> {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .map(str::to_owned)
        .ok_or_else(|| {
            DaemonCliError::new(format!(
                "invalid daemon config line {}: expected quoted string",
                index + 1
            ))
        })
}

fn parse_bool(value: &str, index: usize) -> Result<bool, DaemonCliError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(DaemonCliError::new(format!(
            "invalid daemon config line {}: expected boolean",
            index + 1
        ))),
    }
}

fn parse_u64(value: &str, index: usize, field: &str) -> Result<u64, DaemonCliError> {
    value.parse::<u64>().map_err(|error| {
        DaemonCliError::new(format!(
            "invalid daemon config line {}: {field} must be an unsigned integer: {error}",
            index + 1
        ))
    })
}

fn parse_u32(value: &str, index: usize, field: &str) -> Result<u32, DaemonCliError> {
    value.parse::<u32>().map_err(|error| {
        DaemonCliError::new(format!(
            "invalid daemon config line {}: {field} must be a numeric UID/GID: {error}",
            index + 1
        ))
    })
}

fn resolve_group_gid(group_name: &str) -> Result<u32, DaemonCliError> {
    nix::unistd::Group::from_name(group_name)
        .map_err(|error| {
            DaemonCliError::new(format!(
                "cannot resolve ingest.socket_group {group_name:?}: {error}"
            ))
        })?
        .map(|group| group.gid.as_raw())
        .ok_or_else(|| {
            DaemonCliError::new(format!(
                "ingest.socket_group does not exist: {group_name:?}"
            ))
        })
}

fn parse_usize(value: &str, index: usize, field: &str) -> Result<usize, DaemonCliError> {
    value.parse::<usize>().map_err(|error| {
        DaemonCliError::new(format!(
            "invalid daemon config line {}: {field} must be an unsigned integer: {error}",
            index + 1
        ))
    })
}

fn parse_u32_array(value: &str, index: usize, field: &str) -> Result<Vec<u32>, DaemonCliError> {
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| {
            DaemonCliError::new(format!(
                "invalid daemon config line {}: {field} must be an integer array",
                index + 1
            ))
        })?;
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    inner
        .split(',')
        .map(|item| parse_u32(item.trim(), index, field))
        .collect()
}

#[derive(Debug)]
struct DaemonCliError {
    message: String,
}

impl DaemonCliError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for DaemonCliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for DaemonCliError {}

impl From<io::Error> for DaemonCliError {
    fn from(error: io::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<skynet_edr_core::StorageError> for DaemonCliError {
    fn from(error: skynet_edr_core::StorageError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<skynet_edr_core::CanonicalSpoolIngestError> for DaemonCliError {
    fn from(error: skynet_edr_core::CanonicalSpoolIngestError) -> Self {
        Self::new(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        net::{Shutdown, TcpStream},
    };

    use skynet_edr_core::{
        sqlite_sidecar_path, Event, EventId, EventSource, Incident, IncidentId, IncidentStatus,
        RedactionMetadata, Severity, SourceKind,
    };

    use super::*;

    #[test]
    fn http_listener_fails_closed_for_missing_database_without_creating_files() {
        let db_path = temp_path("missing-http-listener.sqlite");
        cleanup_sqlite_files(&db_path);
        let config = daemon_config_for_db(&db_path);

        let error = start_http_api_if_enabled(&config)
            .expect_err("HTTP API startup must fail closed for missing DB");

        assert!(error.to_string().contains("sqlite"));
        assert_no_sqlite_files(&db_path);
    }

    #[test]
    fn explicit_daemon_storage_initialization_creates_database_before_read_only_http_preflight() {
        let db_path = temp_path("explicit-startup-init.sqlite");
        cleanup_sqlite_files(&db_path);
        let config = daemon_config_for_db(&db_path);

        initialize_active_store(&config).expect("startup initialization creates and migrates DB");
        let read_only =
            LocalStore::open_read_only(&db_path).expect("DB opens read-only after init");
        assert_eq!(read_only.count_events().expect("event count succeeds"), 0);
        drop(read_only);

        let _server = start_http_api_if_enabled(&config)
            .expect("HTTP API preflight succeeds after explicit init");
        assert!(db_path.exists());
        assert_no_appended_sidecars(&db_path);
        cleanup_sqlite_files(&db_path);
    }

    #[test]
    fn inactive_daemon_storage_initialization_does_not_create_sqlite_files() {
        let data_dir = temp_path("inactive-startup-init");
        let db_path = data_dir.join("skynet.sqlite");
        let _ = fs::remove_dir_all(&data_dir);
        fs::create_dir_all(&data_dir).expect("temporary data dir is created");
        let config = DaemonConfig {
            mode: "passive".to_owned(),
            data_dir: data_dir.clone(),
            http_api_enabled: false,
            http_api_bind: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            http_api_read_only: true,
            linux_privileged_sensors: false,
            spool: None,
            ingest: None,
        };

        initialize_active_store(&config).expect("inactive startup initialization is a no-op");

        assert_no_sqlite_files(&db_path);
        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn http_listener_fails_closed_for_empty_existing_database_without_migrating_or_sidecars() {
        let db_path = temp_path("empty-http-listener.sqlite");
        cleanup_sqlite_files(&db_path);
        fs::write(&db_path, b"").expect("empty DB placeholder is created");
        let config = daemon_config_for_db(&db_path);

        let error = start_http_api_if_enabled(&config)
            .expect_err("HTTP API startup must reject missing schema");

        assert!(error.to_string().contains("no such table: incidents"));
        assert!(db_path.exists(), "existing DB file remains present");
        assert_no_appended_sidecars(&db_path);
        let read_only =
            LocalStore::open_read_only(&db_path).expect("empty DB still opens read-only");
        let schema_error = read_only
            .count_incidents()
            .expect_err("HTTP preflight must not migrate schema");
        assert!(schema_error
            .to_string()
            .contains("no such table: incidents"));
        cleanup_sqlite_files(&db_path);
    }

    #[test]
    fn run_source_initializes_active_store_before_spool_ingestion_and_http_startup() {
        let source = include_str!("main.rs");
        let body = source
            .split("fn run_command(")
            .nth(1)
            .expect("run_command exists")
            .split(
                "
}",
            )
            .next()
            .expect("run_command body exists");

        let init = body
            .find("initialize_active_store(&config)?")
            .expect("run initializes active store explicitly");
        let spool = body
            .find("run_spool_ingestion_once(&config)?")
            .expect("run ingests configured spool");
        let http = body
            .find("start_http_api_if_enabled(&config)?")
            .expect("run starts HTTP API");
        assert!(
            init < spool,
            "startup init must happen before spool ingestion"
        );
        assert!(
            init < http,
            "startup init must happen before HTTP listener startup"
        );
    }

    #[test]
    fn http_connection_status_and_risk_gets_are_served_from_read_only_store() {
        let db_path = temp_path("http-read-only-get.sqlite");
        cleanup_sqlite_files(&db_path);
        {
            let writable = LocalStore::open(&db_path).expect("writable DB opens");
            writable
                .insert_incident(&sample_incident())
                .expect("incident persists");
        }

        let before = fs::read(&db_path).expect("DB bytes read before read-only requests");
        assert_no_appended_sidecars(&db_path);

        let status = http_get_response(&db_path, "/api/status");
        let risks = http_get_response(&db_path, "/api/v1/risks?limit=10&offset=0");
        let detail = http_get_response(&db_path, "/api/v1/risks/inc_http_read_only_get");

        assert!(status.contains("HTTP/1.1 200 OK"));
        assert!(status.contains(r#""incident_count":1"#));
        assert!(status.contains(r#""ingestion":{"state":"disabled"}"#));
        assert!(risks.contains("HTTP/1.1 200 OK"));
        assert!(risks.contains(r#""schema_version":"skynet.risk.v1""#));
        assert!(risks.contains(r#""total":1"#));
        assert!(detail.contains("HTTP/1.1 200 OK"));
        assert!(detail.contains(r#""id":"inc_http_read_only_get""#));
        assert_eq!(
            fs::read(&db_path).expect("DB bytes read after read-only requests"),
            before
        );
        assert_no_appended_sidecars(&db_path);
        cleanup_sqlite_files(&db_path);
    }

    #[test]
    fn http_startup_and_request_sources_use_read_only_store_only() {
        let source = include_str!("main.rs");
        let startup_body = source
            .split("fn start_http_api_if_enabled(")
            .nth(1)
            .expect("HTTP startup function exists")
            .split("fn handle_http_connection(")
            .next()
            .expect("HTTP startup body exists");
        let request_body = source
            .split("fn write_http_connection_response(")
            .nth(1)
            .expect("connection response function exists")
            .split("fn parse_http_method(")
            .next()
            .expect("connection response body exists");

        assert!(startup_body.contains("LocalStore::open_read_only(&store_path)?"));
        assert!(!startup_body.contains("LocalStore::open(&store_path)?"));
        assert!(request_body.contains("LocalStore::open_read_only(store_path)?"));
        assert!(!request_body.contains("LocalStore::open(store_path)?"));
    }

    fn daemon_config_for_db(db_path: &Path) -> DaemonConfig {
        DaemonConfig {
            mode: "passive".to_owned(),
            data_dir: db_path
                .parent()
                .expect("temporary DB has parent")
                .to_path_buf(),
            http_api_enabled: true,
            http_api_bind: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            http_api_read_only: true,
            linux_privileged_sensors: false,
            spool: Some(SpoolConfig {
                db: db_path.to_path_buf(),
                path: temp_path("unused-spool.jsonl"),
                checkpoint: temp_path("unused-checkpoint"),
            }),
            ingest: None,
        }
    }

    fn assert_no_sqlite_files(path: &Path) {
        assert!(!path.exists(), "HTTP preflight must not create DB file");
        assert_no_appended_sidecars(path);
    }

    fn assert_no_appended_sidecars(path: &Path) {
        assert!(
            !sqlite_sidecar_path(path, "-wal").exists(),
            "HTTP preflight must not create WAL sidecar"
        );
        assert!(
            !sqlite_sidecar_path(path, "-shm").exists(),
            "HTTP preflight must not create SHM sidecar"
        );
    }

    fn http_get_response(db_path: &Path, path: &str) -> String {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("test listener binds");
        let address = listener.local_addr().expect("test listener address");
        let mut client = TcpStream::connect(address).expect("client connects");
        let (mut server, _) = listener.accept().expect("server accepts");
        write!(
            client,
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        .expect("request writes");
        client
            .shutdown(Shutdown::Write)
            .expect("request is complete");

        write_http_connection_response(&mut server, db_path).expect("response writes");
        drop(server);
        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .expect("response reads");
        response
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "skynet-edr-daemon-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ))
    }

    fn cleanup_sqlite_files(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(sqlite_sidecar_path(path, "-wal"));
        let _ = fs::remove_file(sqlite_sidecar_path(path, "-shm"));
    }

    fn sample_incident() -> Incident {
        let event = Event {
            id: EventId::new("evt_http_read_only_get"),
            observed_at_unix_ms: 1_781_440_123_000,
            severity: Severity::High,
            source: sample_source(),
            title: "Fake HTTP read-only event".to_owned(),
            details: Some("Clearly fake test data; no secrets.".to_owned()),
            attributes: BTreeMap::from([
                ("rule_id".to_owned(), serde_json::json!("EDR-MCP-001")),
                (
                    "event_type".to_owned(),
                    serde_json::json!("agent.mcp.tool.requested"),
                ),
            ]),
            redaction: no_redaction(),
        };
        Incident {
            id: IncidentId::new("inc_http_read_only_get"),
            created_at_unix_ms: 1_781_440_123_000,
            updated_at_unix_ms: 1_781_440_124_000,
            status: IncidentStatus::Open,
            severity: Severity::High,
            title: "Fake HTTP read-only incident".to_owned(),
            summary: "Clearly fake incident; no secrets.".to_owned(),
            source: event.source.clone(),
            events: vec![event],
            redaction: no_redaction(),
        }
    }

    fn sample_source() -> EventSource {
        EventSource {
            kind: SourceKind::Sensor,
            sensor: "daemon-read-only-test".to_owned(),
            integration: Some("fake-test".to_owned()),
        }
    }

    fn no_redaction() -> RedactionMetadata {
        RedactionMetadata {
            contains_sensitive_data: false,
            redacted_fields: Vec::new(),
        }
    }
}
