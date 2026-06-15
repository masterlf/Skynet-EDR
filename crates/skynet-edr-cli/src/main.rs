//! Command-line entry point for Skynet-EDR.

use std::{env, fs, process::ExitCode};

use skynet_edr_core::{ingest_hermes_events_json, Event, Incident, LocalStore, ProductInfo};

fn main() -> ExitCode {
    let args = env::args().collect::<Vec<_>>();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
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
        Some("store") => handle_store(args),
        Some("events") => handle_events(args),
        Some("incidents") => handle_incidents(args),
        Some(other) => Err(CliError::Usage(format!(
            "unknown command: {other}\ntry '{binary} --help'"
        ))),
    }
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
            let count = ingest_hermes_events_json(&store, &trace_json)?;
            println!("ingested {count} Hermes event(s)");
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

fn required_option<'a>(options: &'a [(&str, &str)], name: &str) -> Result<&'a str, CliError> {
    options
        .iter()
        .find_map(|(option_name, value)| (*option_name == name).then_some(*value))
        .ok_or_else(|| CliError::Usage(format!("missing required option: {name}")))
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
    println!("Usage: {binary} [status|store|events|incidents|--version|--help]");
    println!();
    println!("Commands:");
    println!("  status                              Print product status and default runtime mode");
    println!("  store init --db <path>              Initialize local SQLite storage");
    println!("  events ingest --db <path> --incident-json <file>");
    println!("                                      Ingest one incident JSON document and embedded events");
    println!("  events ingest-hermes --db <path> --trace-json <file>");
    println!("                                      Ingest read-only Hermes tool-call trace JSON");
    println!("  events list --db <path>            List stored events");
    println!("  events show <id> --db <path>       Print one event as JSON");
    println!("  events export --db <path> --format jsonl");
    println!("                                      Export events as one JSON object per line");
    println!("  incidents list --db <path>          List stored incidents");
    println!("  incidents show <id> --db <path>     Print one incident as JSON");
    println!("  incidents export --db <path> --format jsonl");
    println!("                                      Export incidents as one JSON object per line");
}

fn string_value(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), ToOwned::to_owned)
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    Storage(skynet_edr_core::StorageError),
    HermesIngest(skynet_edr_core::HermesIngestError),
    Json(serde_json::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::Storage(error) => write!(formatter, "{error}"),
            Self::HermesIngest(error) => write!(formatter, "{error}"),
            Self::Json(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
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
