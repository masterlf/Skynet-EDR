//! Minimal daemon entry point for Skynet-EDR.

use std::{
    env, fs, io,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::ExitCode,
    thread,
    time::Duration,
};

use skynet_edr_core::{ingest_canonical_jsonl_spool, LocalStore, ProductInfo};
use skynet_edr_daemon::{handle_console_request, handle_http_request, HttpMethod};

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

    run_spool_ingestion_once(&config)?;
    let http_server = start_http_api_if_enabled(&config)?;

    if should_exit_after_startup_for_test() {
        drop(http_server);
        return Ok(());
    }

    loop {
        thread::sleep(Duration::from_secs(5));
        run_spool_ingestion_once(&config)?;
    }
}

fn run_spool_ingestion_once(config: &DaemonConfig) -> Result<(), DaemonCliError> {
    let Some(spool) = &config.spool else {
        return Ok(());
    };
    let store = LocalStore::open(&spool.db)?;
    let summary = ingest_canonical_jsonl_spool(&store, &spool.path, &spool.checkpoint)?;
    println!(
        "spool ingestion: ingested={} dropped={} duplicates={} checkpoint={} byte(s)",
        summary.ingested_events,
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

    let store = LocalStore::open(store_path)?;
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
        let response = handle_http_request(&store, method, path)
            .map_err(|error| DaemonCliError::new(format!("HTTP API request failed: {error}")))?;
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

    fn parse(content: &str) -> Result<Self, DaemonCliError> {
        let mut config = Self {
            mode: "passive".to_owned(),
            data_dir: PathBuf::from("/var/lib/skynet-edr"),
            http_api_enabled: false,
            http_api_bind: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8787)),
            http_api_read_only: true,
            linux_privileged_sensors: false,
            spool: None,
        };
        let mut spool_enabled = false;
        let mut spool_db: Option<PathBuf> = None;
        let mut spool_path: Option<PathBuf> = None;
        let mut spool_checkpoint: Option<PathBuf> = None;
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
