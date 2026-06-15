//! Read-only localhost HTTP API safety tests.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use skynet_edr_core::{
    Event, EventId, EventSource, Incident, IncidentId, IncidentStatus, LocalStore,
    RedactionMetadata, Severity, SourceKind,
};
use skynet_edr_daemon::{
    handle_console_request, handle_http_request, HttpApiConfig, HttpMethod, HttpStatus,
};

fn temp_store() -> LocalStore {
    let db_path = std::env::temp_dir().join(format!(
        "skynet-edr-http-api-{}-{}.sqlite",
        std::process::id(),
        unique_suffix()
    ));
    LocalStore::open(db_path).expect("temporary local store opens")
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos()
}

fn stored_incident_with_sensitive_event() -> Incident {
    let source = EventSource {
        kind: SourceKind::Configuration,
        sensor: "linux-passive-fixture".to_owned(),
        integration: Some("hermes".to_owned()),
    };
    let event = Event {
        id: EventId::new("evt_http_api_redaction"),
        observed_at_unix_ms: 42,
        severity: Severity::High,
        source: source.clone(),
        title: "Config token drift".to_owned(),
        details: Some("token=FAKE_TOKEN_NEVER_EXPOSE path=/root/.hermes/auth.json".to_owned()),
        attributes: BTreeMap::from([
            ("rule_id".to_owned(), serde_json::json!("EDR-CONFIG-001")),
            (
                "path".to_owned(),
                serde_json::json!("/root/.hermes/auth.json"),
            ),
            (
                "secret_token".to_owned(),
                serde_json::json!("FAKE_TOKEN_NEVER_EXPOSE"),
            ),
        ]),
        redaction: RedactionMetadata {
            contains_sensitive_data: false,
            redacted_fields: Vec::new(),
        },
    };

    Incident {
        id: IncidentId::new("inc_http_api_redaction"),
        created_at_unix_ms: 42,
        updated_at_unix_ms: 43,
        status: IncidentStatus::Open,
        severity: Severity::High,
        title: "Incident token=FAKE_TOKEN_NEVER_EXPOSE <script>alert(1)</script>".to_owned(),
        summary: "Observed /root/.hermes/auth.json drift".to_owned(),
        source,
        events: vec![event],
        redaction: RedactionMetadata {
            contains_sensitive_data: false,
            redacted_fields: Vec::new(),
        },
    }
}

#[test]
fn default_http_api_binds_loopback_only() {
    let config = HttpApiConfig::default();

    assert_eq!(config.bind_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(!config.allow_mutations);
}

#[test]
fn http_api_rejects_non_loopback_bind_address() {
    let config = HttpApiConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
        store_path: None,
        allow_mutations: false,
    };

    let error = config.validate().expect_err("0.0.0.0 must fail closed");

    assert!(error.to_string().contains("loopback"));
}

#[test]
fn status_endpoint_returns_read_only_json() {
    let store = temp_store();

    let response = handle_http_request(&store, HttpMethod::Get, "/api/status")
        .expect("status endpoint responds");

    assert_eq!(response.status, HttpStatus::Ok);
    assert_eq!(response.content_type, "application/json");
    assert_eq!(response.body["read_only"], true);
    assert_eq!(response.body["product"], "Skynet-EDR");
    assert_eq!(response.body["incident_count"], 0);
}

#[test]
fn rules_sensors_and_config_drift_are_read_only_get_endpoints() {
    let store = temp_store();

    for path in ["/api/rules", "/api/sensors", "/api/config-drift"] {
        let response = handle_http_request(&store, HttpMethod::Get, path)
            .unwrap_or_else(|error| panic!("{path} should respond: {error}"));

        assert_eq!(response.status, HttpStatus::Ok);
        assert_eq!(response.content_type, "application/json");
        assert!(response.body.is_array());
    }
}

#[test]
fn http_api_rejects_mutating_methods_and_unknown_routes() {
    let store = temp_store();

    let mutation = handle_http_request(&store, HttpMethod::Post, "/api/incidents")
        .expect("mutating method on known route returns a structured response");
    let missing = handle_http_request(&store, HttpMethod::Get, "/api/response/pause-agent")
        .expect("unknown route returns a structured response");
    let unknown_mutation =
        handle_http_request(&store, HttpMethod::Post, "/api/response/pause-agent")
            .expect("unknown mutating route returns a structured response");

    assert_eq!(mutation.status, HttpStatus::MethodNotAllowed);
    assert_eq!(mutation.body["error"], "method_not_allowed");
    assert_eq!(missing.status, HttpStatus::NotFound);
    assert_eq!(missing.body["error"], "not_found");
    assert_eq!(unknown_mutation.status, HttpStatus::NotFound);
    assert_eq!(unknown_mutation.body["error"], "not_found");
}

#[test]
fn missing_incident_returns_not_found_not_storage_error() {
    let store = temp_store();

    let response = handle_http_request(&store, HttpMethod::Get, "/api/incidents/missing")
        .expect("missing incident returns structured response");

    assert_eq!(response.status, HttpStatus::NotFound);
    assert_eq!(response.body["error"], "not_found");
    assert_eq!(response.body["read_only"], true);
}

#[test]
fn incidents_and_config_drift_endpoints_redact_before_output() {
    let store = temp_store();
    store
        .insert_incident(&stored_incident_with_sensitive_event())
        .expect("incident persists through storage redaction boundary");

    let incidents = handle_http_request(&store, HttpMethod::Get, "/api/incidents")
        .expect("incidents endpoint responds");
    let incident = handle_http_request(
        &store,
        HttpMethod::Get,
        "/api/incidents/inc_http_api_redaction",
    )
    .expect("single incident endpoint responds");
    let drift = handle_http_request(&store, HttpMethod::Get, "/api/config-drift")
        .expect("config drift endpoint responds");

    assert_eq!(incidents.status, HttpStatus::Ok);
    assert_eq!(incident.status, HttpStatus::Ok);
    assert_eq!(drift.status, HttpStatus::Ok);

    for response in [incidents, incident, drift] {
        let body = response.body.to_string();
        assert!(!body.contains("FAKE_TOKEN_NEVER_EXPOSE"));
        assert!(!body.contains("/root/.hermes/auth.json"));
        assert!(body.contains("[REDACTED:"));
    }
}

#[test]
fn console_index_renders_local_read_only_visibility_pages() {
    let store = temp_store();
    store
        .insert_incident(&stored_incident_with_sensitive_event())
        .expect("incident persists for console timeline");

    let response = handle_console_request(&store, HttpMethod::Get, "/console")
        .expect("console index responds");
    let body = response.body;

    assert_eq!(response.status, HttpStatus::Ok);
    assert_eq!(response.content_type, "text/html; charset=utf-8");
    assert!(body.contains("Skynet-EDR Local Console"));
    assert!(body.contains("Read-only localhost visibility"));
    assert!(body.contains("Incident timeline"));
    assert!(body.contains("inc_http_api_redaction"));
    assert!(body.contains("/console/incidents/inc_http_api_redaction"));
    assert!(body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(body.contains("Rules"));
    assert!(body.contains("Sensors"));
    assert!(body.contains("Config drift"));
    assert!(!body.contains("<script"));
}

#[test]
fn console_incident_evidence_uses_redacted_api_output_and_escapes_html() {
    let store = temp_store();
    store
        .insert_incident(&stored_incident_with_sensitive_event())
        .expect("incident persists for console evidence");

    let response = handle_console_request(
        &store,
        HttpMethod::Get,
        "/console/incidents/inc_http_api_redaction",
    )
    .expect("console evidence view responds");
    let body = response.body;

    assert_eq!(response.status, HttpStatus::Ok);
    assert!(body.contains("Redacted evidence"));
    assert!(body.contains("[REDACTED:"));
    assert!(!body.contains("FAKE_TOKEN_NEVER_EXPOSE"));
    assert!(!body.contains("/root/.hermes/auth.json"));
    assert!(!body.contains("token=FAKE_TOKEN_NEVER_EXPOSE"));
}

#[test]
fn console_status_pages_are_read_only_get_only_and_do_not_add_response_actions() {
    let store = temp_store();

    for path in [
        "/console/rules",
        "/console/sensors",
        "/console/config-drift",
    ] {
        let response = handle_console_request(&store, HttpMethod::Get, path)
            .unwrap_or_else(|error| panic!("{path} should respond: {error}"));
        assert_eq!(response.status, HttpStatus::Ok);
        assert_eq!(response.content_type, "text/html; charset=utf-8");
        assert!(response.body.contains("Read-only"));
        assert!(!response.body.contains("Pause agent"));
        assert!(!response.body.contains("Quarantine"));
        assert!(!response.body.contains("POST"));
    }

    let mutation = handle_console_request(&store, HttpMethod::Post, "/console")
        .expect("mutating method returns structured console response");
    let unknown = handle_console_request(&store, HttpMethod::Get, "/console/response/pause-agent")
        .expect("unknown response action route returns structured console response");

    assert_eq!(mutation.status, HttpStatus::MethodNotAllowed);
    assert!(mutation.body.contains("method_not_allowed"));
    assert_eq!(unknown.status, HttpStatus::NotFound);
    assert!(unknown.body.contains("not_found"));
}
