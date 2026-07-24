//! Command-line entry point for Skynet-EDR.

use std::{
    env, fs,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use skynet_edr_core::{
    ingest_canonical_jsonl_spool, ingest_hermes_events_json_with_detection, redact_text,
    run_secret_egress_attack_simulation, Event, Incident, LocalStore, ProductInfo,
};

const DEFAULT_CONFIG_PATH: &str = "/etc/skynet-edr/config.toml";
const DEFAULT_DB_PATH: &str = "/var/lib/skynet-edr/skynet-edr.sqlite";
const DEFAULT_PLUGIN_SPOOL_PATH: &str = "/var/lib/skynet-edr/events.jsonl";
const DEFAULT_API_ADDR: &str = "127.0.0.1:8787";

fn main() -> ExitCode {
    let args = env::args().collect::<Vec<_>>();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::CommandFailed) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), CliError> {
    let binary = args
        .first()
        .cloned()
        .unwrap_or_else(|| "skynet-edr".to_owned());
    let command = args.get(1).map(String::as_str);

    match command {
        None | Some("status") => {
            ensure_no_extra_args(args, 2, &binary)?;
            print_status();
            Ok(())
        }
        Some("--help" | "-h" | "help") => {
            ensure_no_extra_args(args, 2, &binary)?;
            print_help(&binary);
            Ok(())
        }
        Some("--version" | "-V") => {
            ensure_no_extra_args(args, 2, &binary)?;
            println!(
                "{} {}",
                ProductInfo::default().binary_name,
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        Some("doctor") => handle_doctor(args),
        Some("diagnostics") => handle_diagnostics(args),
        Some("store") => handle_store(args),
        Some("events") => handle_events(args),
        Some("incidents") => handle_incidents(args),
        Some("attack-sim") => handle_attack_sim(args),
        Some(other) => Err(CliError::Usage(format!(
            "unknown command: {other}\ntry '{binary} --help'"
        ))),
    }
}

fn handle_doctor(args: &[String]) -> Result<(), CliError> {
    ensure_known_options(&args[2..], &["--config", "--db", "--spool", "--api"])?;
    let options = parse_options(&args[2..])?;
    let config_path = option_value(&options, "--config").unwrap_or(DEFAULT_CONFIG_PATH);
    let db_path = option_value(&options, "--db").unwrap_or(DEFAULT_DB_PATH);
    let spool_path = option_value(&options, "--spool").unwrap_or(DEFAULT_PLUGIN_SPOOL_PATH);
    let api_addr = option_value(&options, "--api").unwrap_or(DEFAULT_API_ADDR);

    let mut ok = true;
    ok &= print_check("install", &doctor_install_check());
    let config = doctor_config_check(Path::new(config_path), api_addr);
    let api_loopback = config.api_loopback;
    ok &= print_check("config", &config.result);
    ok &= print_check("store", &doctor_store_check(Path::new(db_path)));
    ok &= print_check(
        "readiness",
        &doctor_readiness_check(api_addr, Path::new(spool_path), api_loopback),
    );

    if ok {
        println!("doctor: ok");
        Ok(())
    } else {
        println!("doctor: fail");
        Err(CliError::CommandFailed)
    }
}

fn handle_diagnostics(args: &[String]) -> Result<(), CliError> {
    match args.get(2).map(String::as_str) {
        Some("collect") => {
            ensure_known_options(
                &args[3..],
                &[
                    "--output",
                    "--config",
                    "--db",
                    "--log-file",
                    "--service-status-file",
                ],
            )?;
            collect_diagnostics(&parse_options(&args[3..])?)
        }
        Some(command) => Err(CliError::Usage(format!(
            "unknown diagnostics command: {command}"
        ))),
        None => Err(CliError::Usage("missing diagnostics command".to_owned())),
    }
}

fn collect_diagnostics(options: &[(&str, &str)]) -> Result<(), CliError> {
    let output_dir = PathBuf::from(required_option(options, "--output")?);
    let config_path = option_value(options, "--config").unwrap_or(DEFAULT_CONFIG_PATH);
    let db_path = option_value(options, "--db").unwrap_or(DEFAULT_DB_PATH);

    fs::create_dir_all(&output_dir)?;
    set_dir_private(&output_dir)?;

    write_private_file(&output_dir.join("versions.txt"), &diagnostics_versions())?;
    write_private_file(
        &output_dir.join("config-summary.toml"),
        &diagnostics_config_summary(Path::new(config_path)),
    )?;
    write_private_file(
        &output_dir.join("storage-status.json"),
        &diagnostics_storage_status(Path::new(db_path))?,
    )?;

    if let Some(log_file) = option_value(options, "--log-file") {
        write_private_file(
            &output_dir.join("recent-logs.txt"),
            &redact_file_to_string(Path::new(log_file)),
        )?;
    }
    if let Some(status_file) = option_value(options, "--service-status-file") {
        write_private_file(
            &output_dir.join("service-status.txt"),
            &redact_file_to_string(Path::new(status_file)),
        )?;
    }

    write_private_file(&output_dir.join("manifest.json"), &diagnostics_manifest()?)?;
    println!("diagnostics bundle written: <operator-output-dir>");
    Ok(())
}

fn handle_store(args: &[String]) -> Result<(), CliError> {
    match args.get(2).map(String::as_str) {
        Some("init") => {
            let options = parse_options(&args[3..])?;
            let db_path = required_option(&options, "--db")?;
            let store = LocalStore::open(db_path)?;
            println!("initialized local store: {}", store.path().display());
            Ok(())
        }
        Some(command) => Err(CliError::Usage(format!("unknown store command: {command}"))),
        None => Err(CliError::Usage("missing store command".to_owned())),
    }
}

fn handle_events(args: &[String]) -> Result<(), CliError> {
    match args.get(2).map(String::as_str) {
        Some("ingest") => {
            let options = parse_options(&args[3..])?;
            let db_path = required_option(&options, "--db")?;
            let incident_json = required_option(&options, "--incident-json")?;
            let incident: Incident = serde_json::from_str(&fs::read_to_string(incident_json)?)?;
            let store = LocalStore::open(db_path)?;
            store.insert_incident(&incident)?;
            println!(
                "ingested incident {} with {} event(s)",
                incident.id.as_str(),
                incident.events.len()
            );
            Ok(())
        }
        Some("ingest-hermes") => {
            let options = parse_options(&args[3..])?;
            let db_path = required_option(&options, "--db")?;
            let trace_json = required_option(&options, "--trace-json")?;
            let trace_json = fs::read_to_string(trace_json)?;
            let store = LocalStore::open(db_path)?;
            let summary = ingest_hermes_events_json_with_detection(&store, &trace_json)?;
            println!(
                "ingested {} Hermes event(s), opened {} incident(s)",
                summary.event_count, summary.incident_count
            );
            Ok(())
        }
        Some("ingest-spool") => {
            let options = parse_options(&args[3..])?;
            let db_path = required_option(&options, "--db")?;
            let spool_path = required_option(&options, "--spool")?;
            let checkpoint_path = required_option(&options, "--checkpoint")?;
            let store = LocalStore::open(db_path)?;
            let summary = ingest_canonical_jsonl_spool(&store, spool_path, checkpoint_path)?;
            println!(
                "ingested {} canonical event(s), dropped {} malformed event(s), skipped {} duplicate event(s), checkpoint={} byte(s)",
                summary.ingested_events,
                summary.dropped_events,
                summary.duplicate_events,
                summary.last_processed_byte
            );
            Ok(())
        }
        Some("list") => {
            let options = parse_options(&args[3..])?;
            let db_path = required_option(&options, "--db")?;
            let store = LocalStore::open(db_path)?;
            for event in store.list_events()? {
                print_event_row(&event)?;
            }
            Ok(())
        }
        Some("show") => {
            let id = args
                .get(3)
                .ok_or_else(|| CliError::Usage("missing event id".to_owned()))?;
            let options = parse_options(&args[4..])?;
            let db_path = required_option(&options, "--db")?;
            let store = LocalStore::open(db_path)?;
            let event = store
                .get_event(id)?
                .ok_or_else(|| CliError::Usage(format!("event not found: {id}")))?;
            println!("{}", serde_json::to_string_pretty(&event)?);
            Ok(())
        }
        Some("export") => {
            let options = parse_options(&args[3..])?;
            let db_path = required_option(&options, "--db")?;
            let format = required_option(&options, "--format")?;
            if format != "jsonl" {
                return Err(CliError::Usage(format!(
                    "unsupported events export format: {format}"
                )));
            }
            let store = LocalStore::open(db_path)?;
            for event in store.list_events()? {
                println!("{}", serde_json::to_string(&event)?);
            }
            Ok(())
        }
        Some(command) => Err(CliError::Usage(format!(
            "unknown events command: {command}"
        ))),
        None => Err(CliError::Usage("missing events command".to_owned())),
    }
}

fn handle_attack_sim(args: &[String]) -> Result<(), CliError> {
    match args.get(2).map(String::as_str) {
        Some("secret-egress") => {
            let options = parse_options(&args[3..])?;
            let db_path = required_option(&options, "--db")?;
            let store = LocalStore::open(db_path)?;
            let summary = run_secret_egress_attack_simulation(&store)?;
            println!(
                "attack simulation secret-egress completed: ingested {} event(s), stored {} critical incident(s)",
                summary.event_count, summary.incident_count
            );
            Ok(())
        }
        Some(command) => Err(CliError::Usage(format!(
            "unknown attack-sim command: {command}"
        ))),
        None => Err(CliError::Usage("missing attack-sim command".to_owned())),
    }
}

fn handle_incidents(args: &[String]) -> Result<(), CliError> {
    match args.get(2).map(String::as_str) {
        Some("list") => {
            let options = parse_options(&args[3..])?;
            let db_path = required_option(&options, "--db")?;
            let store = LocalStore::open(db_path)?;
            for incident in store.list_incidents()? {
                let severity = serde_json::to_value(incident.severity)?;
                println!(
                    "{}\t{}\t{}",
                    incident.id.as_str(),
                    string_value(&severity),
                    incident.title
                );
            }
            Ok(())
        }
        Some("show") => {
            let id = args
                .get(3)
                .ok_or_else(|| CliError::Usage("missing incident id".to_owned()))?;
            let options = parse_options(&args[4..])?;
            let db_path = required_option(&options, "--db")?;
            let store = LocalStore::open(db_path)?;
            let incident = store
                .get_incident(id)?
                .ok_or_else(|| CliError::Usage(format!("incident not found: {id}")))?;
            println!("{}", serde_json::to_string_pretty(&incident)?);
            Ok(())
        }
        Some("export") => {
            let options = parse_options(&args[3..])?;
            let db_path = required_option(&options, "--db")?;
            let format = required_option(&options, "--format")?;
            if format != "jsonl" {
                return Err(CliError::Usage(format!(
                    "unsupported incidents export format: {format}"
                )));
            }
            let store = LocalStore::open(db_path)?;
            for incident in store.list_incidents()? {
                println!("{}", serde_json::to_string(&incident)?);
            }
            Ok(())
        }
        Some(command) => Err(CliError::Usage(format!(
            "unknown incidents command: {command}"
        ))),
        None => Err(CliError::Usage("missing incidents command".to_owned())),
    }
}

fn parse_options(args: &[String]) -> Result<Vec<(&str, &str)>, CliError> {
    let chunks = args.chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err(CliError::Usage(
            "options must be supplied as --name value pairs".to_owned(),
        ));
    }

    chunks
        .map(|pair| {
            let name = pair[0].as_str();
            if !name.starts_with("--") {
                return Err(CliError::Usage(format!("unexpected argument: {name}")));
            }
            Ok((name, pair[1].as_str()))
        })
        .collect()
}

fn ensure_known_options(args: &[String], allowed: &[&str]) -> Result<(), CliError> {
    let chunks = args.chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err(CliError::Usage(
            "options must be supplied as --name value pairs".to_owned(),
        ));
    }
    for pair in chunks {
        let name = pair[0].as_str();
        if !allowed.contains(&name) {
            return Err(CliError::Usage(format!("unknown option: {name}")));
        }
    }
    Ok(())
}

fn required_option<'a>(options: &'a [(&str, &str)], name: &str) -> Result<&'a str, CliError> {
    option_value(options, name)
        .ok_or_else(|| CliError::Usage(format!("missing required option: {name}")))
}

fn option_value<'a>(options: &'a [(&str, &str)], name: &str) -> Option<&'a str> {
    options
        .iter()
        .find_map(|(option_name, value)| (*option_name == name).then_some(*value))
}

fn ensure_no_extra_args(args: &[String], allowed_len: usize, binary: &str) -> Result<(), CliError> {
    if let Some(extra) = args.get(allowed_len) {
        return Err(CliError::Usage(format!(
            "unexpected argument: {extra}\ntry '{binary} --help'"
        )));
    }
    Ok(())
}

fn print_status() {
    let info = ProductInfo::default();
    println!("{} status: mode={}", info.name, info.run_mode.as_str());
}

fn print_event_row(event: &Event) -> Result<(), CliError> {
    let severity = serde_json::to_value(event.severity)?;
    println!(
        "{}\t{}\t{}",
        event.id.as_str(),
        string_value(&severity),
        event.title
    );
    Ok(())
}

fn print_help(binary: &str) {
    println!("Usage: {binary} [status|doctor|diagnostics|store|events|incidents|--version|--help]");
    println!();
    println!("Commands:");
    println!("  status                              Print product status and default runtime mode");
    println!("  doctor [--config <path>] [--db <path>] [--spool <path>] [--api <loopback:port>]");
    println!("                                      Check packaged install, config, store, and local readiness");
    println!("  diagnostics collect --output <dir> [--config <path>] [--db <path>]");
    println!("                      [--log-file <path>] [--service-status-file <path>]");
    println!("                                      Collect redacted operator diagnostics without raw events");
    println!("  store init --db <path>              Initialize local SQLite storage");
    println!("  events ingest --db <path> --incident-json <file>");
    println!("                                      Ingest one incident JSON document and embedded events");
    println!("  events ingest-hermes --db <path> --trace-json <file>");
    println!("                                      Ingest read-only Hermes tool-call trace JSON");
    println!("  events ingest-spool --db <path> --spool <file> --checkpoint <file>");
    println!(
        "                                      Ingest complete canonical event JSONL spool records"
    );
    println!("  events list --db <path>            List stored events");
    println!("  events show <id> --db <path>       Print one event as JSON");
    println!("  events export --db <path> --format jsonl");
    println!("                                      Export events as one JSON object per line");
    println!("  incidents list --db <path>          List stored incidents");
    println!("  incidents show <id> --db <path>     Print one incident as JSON");
    println!("  incidents export --db <path> --format jsonl");
    println!("                                      Export incidents as one JSON object per line");
    println!("  attack-sim secret-egress --db <path>");
    println!("                                      Run deterministic fake secret-read plus egress simulation");
}

fn string_value(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), ToOwned::to_owned)
}

struct ConfigCheck {
    result: CheckResult,
    api_loopback: bool,
}

struct CheckResult {
    ok: bool,
    detail: String,
}

fn ok_detail(detail: impl Into<String>) -> CheckResult {
    CheckResult {
        ok: true,
        detail: detail.into(),
    }
}

fn fail_detail(detail: impl Into<String>) -> CheckResult {
    CheckResult {
        ok: false,
        detail: detail.into(),
    }
}

fn print_check(name: &str, result: &CheckResult) -> bool {
    let status = if result.ok { "ok" } else { "fail" };
    println!("{name}: {status} - {}", result.detail);
    result.ok
}

fn doctor_install_check() -> CheckResult {
    match env::current_exe() {
        Ok(path) if path.is_file() => ok_detail("cli binary is present"),
        Ok(_) => fail_detail("cli binary path is not a file"),
        Err(_) => fail_detail("cli binary path cannot be resolved"),
    }
}

fn doctor_config_check(config_path: &Path, api_addr: &str) -> ConfigCheck {
    let Ok(config) = fs::read_to_string(config_path) else {
        return ConfigCheck {
            result: fail_detail("packaged config is missing or unreadable"),
            api_loopback: false,
        };
    };
    let mut failures = Vec::new();
    let mode = config_value(&config, "mode");
    if !matches!(mode.as_deref(), Some("passive" | "guard" | "enforcement")) {
        failures.push("mode must be passive, guard, or enforcement".to_owned());
    }
    let configured_bind = config_value(&config, "bind").unwrap_or_else(|| api_addr.to_owned());
    let api_loopback =
        socket_addr_is_loopback(&configured_bind) && socket_addr_is_loopback(api_addr);
    if !api_loopback {
        failures.push("http_api bind/api target must be loopback-only".to_owned());
    }
    if config.contains("api_token") || config.contains("/home/") || config.contains("/root/") {
        failures.push(redact_text(&config).value);
    }

    ConfigCheck {
        result: if failures.is_empty() {
            ok_detail("config is readable and loopback-only")
        } else {
            fail_detail(failures.join("; "))
        },
        api_loopback,
    }
}

fn doctor_store_check(db_path: &Path) -> CheckResult {
    if !db_path.is_file() {
        return fail_detail("local store database is missing; initialize it explicitly");
    }
    match LocalStore::open(db_path) {
        Ok(_) => ok_detail("local store database opens"),
        Err(_) => fail_detail("local store database is unreadable or has invalid schema"),
    }
}

fn doctor_readiness_check(api_addr: &str, spool_path: &Path, api_loopback: bool) -> CheckResult {
    if !api_loopback {
        return fail_detail("refusing to contact non-loopback API target");
    }
    if loopback_tcp_connects(api_addr) {
        return ok_detail("loopback API accepts TCP connections");
    }
    if spool_path.is_file() {
        return ok_detail("plugin spool is present for daemon ingestion");
    }
    fail_detail("no loopback API connection or plugin spool readiness detected")
}

fn loopback_tcp_connects(addr: &str) -> bool {
    let Ok(addr) = addr.parse::<SocketAddr>() else {
        return false;
    };
    if !addr.ip().is_loopback() {
        return false;
    }
    TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

fn socket_addr_is_loopback(value: &str) -> bool {
    value
        .parse::<SocketAddr>()
        .is_ok_and(|addr| addr.ip().is_loopback())
}

fn config_value(config: &str, key: &str) -> Option<String> {
    config.lines().find_map(|line| {
        let line = line.trim();
        let (name, value) = line.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        Some(value.trim().trim_matches('"').to_owned())
    })
}

fn diagnostics_versions() -> String {
    format!(
        "skynet-edr {}\nrust target {}/{}\n",
        env!("CARGO_PKG_VERSION"),
        env::consts::OS,
        env::consts::ARCH
    )
}

fn diagnostics_config_summary(config_path: &Path) -> String {
    match fs::read_to_string(config_path) {
        Ok(config) => redact_text(&config).value,
        Err(_) => "config_present = false\n".to_owned(),
    }
}

fn diagnostics_storage_status(db_path: &Path) -> Result<String, CliError> {
    if !db_path.is_file() {
        return Ok(
            "{\n  \"store_present\": false,\n  \"event_count\": 0,\n  \"incident_count\": 0\n}\n"
                .to_owned(),
        );
    }
    let store = LocalStore::open(db_path)?;
    let event_count = store.list_events()?.len();
    let incident_count = store.list_incidents()?.len();
    Ok(format!(
        "{{\n  \"store_present\": true,\n  \"event_count\": {event_count},\n  \"incident_count\": {incident_count}\n}}\n"
    ))
}

fn redact_file_to_string(path: &Path) -> String {
    fs::read_to_string(path).map_or_else(
        |_| "operator_supplied_file_present = false\n".to_owned(),
        |content| redact_text(&content).value,
    )
}

fn diagnostics_manifest() -> Result<String, CliError> {
    let manifest = serde_json::json!({
        "schema_version": 1,
        "bundle_type": "skynet-edr-diagnostics",
        "raw_events_included": false,
        "redaction_applied": true,
        "files": [
            "versions.txt",
            "config-summary.toml",
            "storage-status.json",
            "recent-logs.txt",
            "service-status.txt"
        ]
    });
    Ok(serde_json::to_string_pretty(&manifest)? + "\n")
}

fn write_private_file(path: &Path, content: &str) -> Result<(), CliError> {
    fs::write(path, content)?;
    set_file_private(path)
}

#[cfg(unix)]
fn set_dir_private(path: &Path) -> Result<(), CliError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_private(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[cfg(unix)]
fn set_file_private(path: &Path) -> Result<(), CliError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_private(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    Storage(skynet_edr_core::StorageError),
    HermesIngest(skynet_edr_core::HermesIngestError),
    CanonicalSpoolIngest(skynet_edr_core::CanonicalSpoolIngestError),
    Json(serde_json::Error),
    Io(std::io::Error),
    CommandFailed,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::Storage(error) => write!(formatter, "{error}"),
            Self::HermesIngest(error) => write!(formatter, "{error}"),
            Self::CanonicalSpoolIngest(error) => write!(formatter, "{error}"),
            Self::Json(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::CommandFailed => write!(formatter, "command failed"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<skynet_edr_core::StorageError> for CliError {
    fn from(error: skynet_edr_core::StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<skynet_edr_core::HermesIngestError> for CliError {
    fn from(error: skynet_edr_core::HermesIngestError) -> Self {
        Self::HermesIngest(error)
    }
}

impl From<skynet_edr_core::CanonicalSpoolIngestError> for CliError {
    fn from(error: skynet_edr_core::CanonicalSpoolIngestError) -> Self {
        Self::CanonicalSpoolIngest(error)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
