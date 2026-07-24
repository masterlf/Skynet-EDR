//! Command-line entry point for Skynet-EDR.

use std::{
    env, fs,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use skynet_edr_core::{
    ingest_canonical_jsonl_spool, ingest_hermes_events_json_with_detection, redact_text,
    run_secret_egress_attack_simulation, Event, Incident, LocalStore, ProductInfo,
};

const DEFAULT_CONFIG_PATH: &str = "/etc/skynet-edr/config.toml";
const DEFAULT_DB_PATH: &str = "/var/lib/skynet-edr/skynet-edr.sqlite";
const DEFAULT_PLUGIN_SPOOL_PATH: &str = "/var/lib/skynet-edr/events.jsonl";
const MAX_EVIDENCE_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE_LINES: usize = 200;

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
    let explicit_spool_path = option_value(&options, "--spool");
    let explicit_api_addr = option_value(&options, "--api");

    let mut ok = true;
    ok &= print_check("install", &doctor_install_check());
    let config = doctor_config_check(Path::new(config_path), explicit_api_addr);
    let readiness_api = config.readiness_api.clone();
    let readiness_spool = explicit_spool_path
        .map(PathBuf::from)
        .or_else(|| config.spool_path.clone())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PLUGIN_SPOOL_PATH));
    ok &= print_check("config", &config.result);
    ok &= print_check("store", &doctor_store_check(Path::new(db_path)));
    ok &= print_check(
        "readiness",
        &doctor_readiness_check(readiness_api, &readiness_spool),
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
    let log_file = option_value(options, "--log-file").map(PathBuf::from);
    let status_file = option_value(options, "--service-status-file").map(PathBuf::from);

    validate_evidence_file(log_file.as_deref())?;
    validate_evidence_file(status_file.as_deref())?;
    create_fresh_private_dir(&output_dir)?;

    let mut written_files = Vec::new();
    write_private_file(&output_dir.join("versions.txt"), &diagnostics_versions())?;
    written_files.push("versions.txt".to_owned());
    write_private_file(
        &output_dir.join("config-summary.json"),
        &diagnostics_config_summary(Path::new(config_path)),
    )?;
    written_files.push("config-summary.json".to_owned());
    write_private_file(
        &output_dir.join("storage-status.json"),
        &diagnostics_storage_status(Path::new(db_path))?,
    )?;
    written_files.push("storage-status.json".to_owned());

    if let Some(log_file) = log_file {
        write_private_file(
            &output_dir.join("recent-logs.txt"),
            &redact_evidence_file_to_string(&log_file)?,
        )?;
        written_files.push("recent-logs.txt".to_owned());
    }
    if let Some(status_file) = status_file {
        write_private_file(
            &output_dir.join("service-status.txt"),
            &redact_evidence_file_to_string(&status_file)?,
        )?;
        written_files.push("service-status.txt".to_owned());
    }

    write_private_file(
        &output_dir.join("manifest.json"),
        &diagnostics_manifest(&written_files)?,
    )?;
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
                "ingested {} canonical event(s), opened {} incident(s), dropped {} malformed event(s), skipped {} duplicate event(s), checkpoint={} byte(s)",
                summary.ingested_events,
                summary.opened_incidents,
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
    readiness_api: Option<String>,
    spool_path: Option<PathBuf>,
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

fn doctor_config_check(config_path: &Path, explicit_api_addr: Option<&str>) -> ConfigCheck {
    let Ok(config) = fs::read_to_string(config_path) else {
        return ConfigCheck {
            result: fail_detail("packaged config is missing or unreadable"),
            readiness_api: None,
            spool_path: None,
        };
    };
    let parsed = ParsedConfig::parse(&config);
    let mut failures = Vec::new();
    if parsed.mode.as_deref() != Some("passive") {
        failures.push("mode must be passive".to_owned());
    }
    if parsed.http_api_enabled != Some(true) {
        failures.push("http_api.enabled must be true".to_owned());
    }
    if parsed.http_api_read_only != Some(true) {
        failures.push("http_api.read_only must be true for read-only operation".to_owned());
    }
    if parsed.http_api_enabled == Some(true) {
        match parsed.http_api_bind.as_deref() {
            Some(bind) if socket_addr_is_loopback(bind) => {}
            _ => failures.push("http_api.bind must be loopback-only".to_owned()),
        }
    }
    if explicit_api_addr.is_some_and(|addr| !socket_addr_is_loopback(addr)) {
        failures.push("explicit API target must be loopback-only".to_owned());
    }
    if parsed.redact_before_storage != Some(true) {
        failures.push("redaction before storage must be enabled".to_owned());
    }
    if parsed.redact_before_logs != Some(true) {
        failures.push("redaction before logs must be enabled".to_owned());
    }
    if parsed.redact_before_api != Some(true) {
        failures.push("redaction before API output must be enabled".to_owned());
    }
    if parsed.linux_privileged != Some(false) {
        failures.push("privileged Linux sensors must be disabled".to_owned());
    }
    if parsed.outbound_alerting_enabled != Some(false) {
        failures.push("outbound alerting must be disabled".to_owned());
    }
    let readiness_api = explicit_api_addr
        .map(ToOwned::to_owned)
        .or_else(|| parsed.http_api_bind.clone());

    ConfigCheck {
        result: if failures.is_empty() {
            ok_detail("config matches passive local-only packaged contract")
        } else {
            fail_detail(failures.join("; "))
        },
        readiness_api,
        spool_path: parsed.spool_path.map(PathBuf::from),
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

fn doctor_readiness_check(api_addr: Option<String>, spool_path: &Path) -> CheckResult {
    if let Some(api_addr) = api_addr {
        if !socket_addr_is_loopback(&api_addr) {
            return fail_detail("refusing to contact non-loopback API target");
        }
        if loopback_tcp_connects(&api_addr) {
            return ok_detail("configured loopback API accepts TCP connections");
        }
    }
    if spool_path.is_file() {
        return ok_detail("configured plugin spool is present for daemon ingestion");
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

#[derive(Default)]
struct ParsedConfig {
    mode: Option<String>,
    http_api_enabled: Option<bool>,
    http_api_bind: Option<String>,
    http_api_read_only: Option<bool>,
    redact_before_storage: Option<bool>,
    redact_before_logs: Option<bool>,
    redact_before_api: Option<bool>,
    linux_privileged: Option<bool>,
    outbound_alerting_enabled: Option<bool>,
    spool_path: Option<String>,
}

impl ParsedConfig {
    fn parse(config: &str) -> Self {
        let mut parsed = Self::default();
        let mut section = String::new();
        for raw_line in config.lines() {
            let line = strip_config_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                line[1..line.len() - 1].trim().clone_into(&mut section);
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            match (section.as_str(), key) {
                ("", "mode") => parsed.mode = parse_config_string(value),
                ("http_api", "enabled") => parsed.http_api_enabled = parse_config_bool(value),
                ("http_api", "bind") => parsed.http_api_bind = parse_config_string(value),
                ("http_api", "read_only") => parsed.http_api_read_only = parse_config_bool(value),
                ("redaction", "redact_before_storage") => {
                    parsed.redact_before_storage = parse_config_bool(value);
                }
                ("redaction", "redact_before_logs") => {
                    parsed.redact_before_logs = parse_config_bool(value);
                }
                ("redaction", "redact_before_api") => {
                    parsed.redact_before_api = parse_config_bool(value);
                }
                ("sensors", "linux_privileged") => {
                    parsed.linux_privileged = parse_config_bool(value);
                }
                ("network", "outbound_alerting_enabled") => {
                    parsed.outbound_alerting_enabled = parse_config_bool(value);
                }
                ("spool", "path") => parsed.spool_path = parse_config_string(value),
                _ => {}
            }
        }
        parsed
    }
}

fn strip_config_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(before, _)| before)
}

fn parse_config_string(value: &str) -> Option<String> {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .map(str::to_owned)
}

fn parse_config_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
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
    let Some(config) = fs::read_to_string(config_path).ok() else {
        return "{\n  \"config_present\": false\n}\n".to_owned();
    };
    let parsed = ParsedConfig::parse(&config);
    let summary = serde_json::json!({
        "config_present": true,
        "mode": safe_mode_label(parsed.mode.as_deref()),
        "http_api_enabled": parsed.http_api_enabled.unwrap_or(false),
        "http_api_bind_loopback": parsed.http_api_bind.as_deref().is_some_and(socket_addr_is_loopback),
        "http_api_read_only": parsed.http_api_read_only.unwrap_or(false),
        "redact_before_storage": parsed.redact_before_storage.unwrap_or(false),
        "redact_before_logs": parsed.redact_before_logs.unwrap_or(false),
        "redact_before_api": parsed.redact_before_api.unwrap_or(false),
        "linux_privileged": parsed.linux_privileged.unwrap_or(false),
        "outbound_alerting_enabled": parsed.outbound_alerting_enabled.unwrap_or(false),
        "spool_configured": parsed.spool_path.is_some(),
    });
    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_owned()) + "\n"
}

fn safe_mode_label(mode: Option<&str>) -> &'static str {
    match mode {
        Some("passive") => "passive",
        Some("guard") => "guard",
        Some("enforcement") => "enforcement",
        _ => "unknown",
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

fn validate_evidence_file(path: Option<&Path>) -> Result<(), CliError> {
    let Some(path) = path else {
        return Ok(());
    };
    if !path.is_file() {
        return Err(CliError::Usage(
            "explicit evidence file is unreadable or not a regular file".to_owned(),
        ));
    }
    File::open(path).map(|_| ()).map_err(|_| {
        CliError::Usage("explicit evidence file is unreadable or not a regular file".to_owned())
    })
}

fn redact_evidence_file_to_string(path: &Path) -> Result<String, CliError> {
    let mut file = File::open(path).map_err(|_| {
        CliError::Usage("explicit evidence file is unreadable or not a regular file".to_owned())
    })?;
    let len = file.metadata()?.len();
    if len > MAX_EVIDENCE_BYTES {
        file.seek(SeekFrom::Start(len - MAX_EVIDENCE_BYTES))?;
    }
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    let lines = content.lines().collect::<Vec<_>>();
    let start = lines.len().saturating_sub(MAX_EVIDENCE_LINES);
    let bounded = lines[start..].join("\n");
    Ok(redact_text(&(bounded + "\n")).value)
}

fn diagnostics_manifest(files: &[String]) -> Result<String, CliError> {
    let manifest = serde_json::json!({
        "schema_version": 1,
        "bundle_type": "skynet-edr-diagnostics",
        "raw_events_included": false,
        "redaction_applied": true,
        "files": files
    });
    Ok(serde_json::to_string_pretty(&manifest)? + "\n")
}

fn write_private_file(path: &Path, content: &str) -> Result<(), CliError> {
    let mut file = private_create_new_file(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(unix)]
fn create_fresh_private_dir(path: &Path) -> Result<(), CliError> {
    if path.symlink_metadata().is_ok() {
        return Err(CliError::Usage(
            "output directory must not already exist; refusing to overwrite".to_owned(),
        ));
    }
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_fresh_private_dir(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        return Err(CliError::Usage(
            "output directory must not already exist; refusing to overwrite".to_owned(),
        ));
    }
    fs::create_dir(path)?;
    set_dir_private(path)
}

#[cfg(unix)]
fn private_create_new_file(path: &Path) -> Result<File, CliError> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(not(unix))]
fn private_create_new_file(path: &Path) -> Result<File, CliError> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    set_file_private(path)?;
    Ok(file)
}

#[cfg(not(unix))]
fn set_dir_private(_path: &Path) -> Result<(), CliError> {
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
