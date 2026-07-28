(function () {
  "use strict";

  const SDK = window.__HERMES_PLUGIN_SDK__;
  const registry = window.__HERMES_PLUGINS__;
  if (!SDK || !SDK.React || !SDK.hooks || !SDK.components || typeof SDK.fetchJSON !== "function") return;
  if (!registry || typeof registry.register !== "function") return;

  const React = SDK.React;
  const { useState, useEffect, useCallback, useMemo, useRef } = SDK.hooks;
  const {
    Card,
    CardHeader,
    CardTitle,
    CardContent,
    Badge,
    Button,
    Input,
    Label,
    Select,
    SelectOption,
    Separator,
  } = SDK.components;
  const h = React.createElement;

  const API_ROOT = "/api/plugins/skynet-edr";
  const POLL_MS = 10000;
  const PAGE_LIMIT = 50;
  const MAX_OFFSET = Number.MAX_SAFE_INTEGER;
  const MAX_ID_LENGTH = 256;
  const MAX_ENCODED_ID_LENGTH = 3072;
  const MAX_TEXT_LENGTH = 4096;
  const MAX_TRACE_IDS = 10;
  const MAX_EVIDENCE_ITEMS = 50;
  const CONTRACT_ERROR = "Invalid read-only risk projection";
  const SEVERITIES = new Set(["critical", "high", "medium", "low", "informational"]);
  const STATUSES = new Set(["open", "investigating", "contained", "resolved", "dismissed"]);
  const SOURCE_KINDS = new Set(["sensor", "process", "file", "network", "mcp_tool", "configuration", "scheduled_task", "messaging"]);
  const ARTIFACT_KINDS = new Set(["email", "url", "git_repository", "code", "file", "message", "mcp", "terminal", "unknown"]);
  const TRUST_LEVELS = new Set(["authenticated_user", "runtime_policy", "untrusted_content", "tool_output", "agent_action", "sensor_observation"]);
  const ARTIFACT_LABELS = {
    email: "Email content",
    url: "URL content",
    git_repository: "Git repository",
    code: "Code content",
    file: "File content",
    message: "Message content",
    mcp: "MCP content",
    terminal: "Terminal output",
    unknown: "Unclassified artifact",
  };
  const SOURCE_PRESENTATION = {
    email: { label: "Email", glyph: "✉" },
    url: { label: "URL", glyph: "◎" },
    git_repository: { label: "Git", glyph: "⑂" },
    code: { label: "Code", glyph: "</>" },
    file: { label: "File", glyph: "▤" },
    message: { label: "Message", glyph: "◫" },
    mcp: { label: "MCP", glyph: "⬡" },
    terminal: { label: "Terminal", glyph: ">_" },
    unknown: { label: "Unknown", glyph: "?" },
  };
  const EVENT_TITLES = {
    "agent.tool.requested": "Tool request evidence",
    "agent.tool.completed": "Tool completion evidence",
    "agent.content.ingested": "Content ingestion evidence",
    "agent.network.egress": "Network egress evidence",
    "agent.file.accessed": "File access evidence",
    "agent.mcp.tool.requested": "MCP tool request evidence",
    "agent.config.changed": "Configuration change evidence",
    "agent.automation.scheduled": "Automation schedule evidence",
    "agent.approval.granted": "Approval or scope change evidence",
    "agent.llm.call.requested": "Model call request evidence",
    "agent.llm.call.completed": "Model call completion evidence",
  };
  const RISK_TITLES = {
    "EDR-MCP-001": "MCP network activity after untrusted content",
    "EDR-CONFIG-001": "Agent configuration drift detected",
    "EDR-CRON-001": "Risky unattended automation detected",
    "EDR-PI-001": "Privileged tool request after untrusted content",
    "EDR-MSG-001": "Suspicious message delivery activity",
    "EDR-NET-001": "Direct-IP egress activity",
    "EDR-SCOPE-001": "Privilege or scope expansion activity",
    "EDR-PERSIST-001": "Agent persistence change activity",
    "EDR-EXFIL-001": "Sensitive access followed by outbound delivery",
    "EDR-MALWARE-001": "Malware-like content supplied to AI runtime",
  };
  const INDICATOR_BOOL_KEYS = new Set([
    "network_indicator",
    "direct_ip",
    "delivery_indicator",
    "sensitive_access",
    "prompt_injection_indicator",
    "malware_indicator",
    "content_omitted",
    "result_omitted",
    "instruction_authority",
  ]);
  const INDICATOR_STRING_VALUES = {
    command_class: new Set(["network_egress", "file_read", "code_execution", "other"]),
    expected_disposition: new Set(["benign", "suspicious", "malicious", "unknown"]),
    drift_kind: new Set(["changed", "created", "deleted"]),
  };
  const MIN_WIDTH_ZERO_STYLE = { minWidth: 0 };
  const WRAP_ANYWHERE_STYLE = { minWidth: 0, overflowWrap: "anywhere", wordBreak: "break-word" };

  function isPlainObject(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
  }

  function hasKey(value, key) {
    return isPlainObject(value) && Object.prototype.hasOwnProperty.call(value, key);
  }

  function failContract() {
    throw new Error(CONTRACT_ERROR);
  }

  function boundedString(value, max) {
    const limit = max === undefined ? MAX_TEXT_LENGTH : max;
    return typeof value === "string" && value.length > 0 && Array.from(value).length <= limit;
  }

  function nullableBoundedString(value, max) {
    return value === null || boundedString(value, max);
  }

  function boundedId(value) {
    if (!boundedString(value, MAX_ID_LENGTH) || value === "." || value === "..") return false;
    try {
      return encodeURIComponent(value).length <= MAX_ENCODED_ID_LENGTH;
    } catch (_error) {
      return false;
    }
  }

  function safeIdentifier(value) {
    return typeof value === "string" && /^[A-Za-z0-9:._-]{1,128}$/.test(value) && value.trim() === value;
  }

  function nullableSafeIdentifier(value) {
    return value === null || safeIdentifier(value);
  }

  function enumValue(value, allowed) {
    return typeof value === "string" && allowed.has(value);
  }

  function boundedSafeInteger(value) {
    return Number.isSafeInteger(value) && value >= 0;
  }

  function boundedPageNumber(value, max) {
    return Number.isInteger(value) && value >= 0 && value <= (max === undefined ? MAX_OFFSET : max);
  }

  function validLocatorHash(value) {
    return value === null || (typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value));
  }

  function evidenceTitleFor(eventType) {
    return EVENT_TITLES[eventType] || "Security event evidence";
  }

  function riskTitleFor(ruleId) {
    return RISK_TITLES[ruleId] || "Security risk detected";
  }

  function riskSummaryFor(eventCount) {
    const noun = eventCount === 1 ? "event" : "events";
    return "Read-only projection of " + eventCount + " redacted evidence " + noun + ". Review sensor and artifact provenance plus allowlisted indicators.";
  }

  function validateSensor(value) {
    if (!isPlainObject(value)) failContract();
    ["kind", "sensor", "integration"].forEach(function (key) {
      if (!hasKey(value, key)) failContract();
    });
    if (!enumValue(value.kind, SOURCE_KINDS)) failContract();
    if (!safeIdentifier(value.sensor)) failContract();
    if (!nullableSafeIdentifier(value.integration)) failContract();
  }

  function validateArtifact(value) {
    if (!isPlainObject(value)) failContract();
    ["kind", "provider", "display_label", "locator_hash", "trust_level"].forEach(function (key) {
      if (!hasKey(value, key)) failContract();
    });
    if (!enumValue(value.kind, ARTIFACT_KINDS)) failContract();
    if (!nullableSafeIdentifier(value.provider)) failContract();
    if (value.display_label !== ARTIFACT_LABELS[value.kind]) failContract();
    if (!validLocatorHash(value.locator_hash)) failContract();
    if (!(value.trust_level === null || enumValue(value.trust_level, TRUST_LEVELS))) failContract();
  }

  function validateTraceIds(value) {
    if (!Array.isArray(value) || value.length > MAX_TRACE_IDS) failContract();
    const seen = new Set();
    value.forEach(function (trace) {
      if (!safeIdentifier(trace) || seen.has(trace)) failContract();
      seen.add(trace);
    });
  }

  function validateRiskBase(data) {
    if (!isPlainObject(data)) failContract();
    [
      "id", "severity", "confidence", "status", "rule_id", "title", "summary", "sensor", "artifact",
      "first_observed_at_unix_ms", "last_observed_at_unix_ms", "event_count", "trace_ids", "contains_sensitive_data",
    ].forEach(function (key) {
      if (!hasKey(data, key)) failContract();
    });
    if (!boundedId(data.id)) failContract();
    if (!enumValue(data.severity, SEVERITIES)) failContract();
    if (data.confidence !== null) failContract();
    if (!enumValue(data.status, STATUSES)) failContract();
    if (!nullableSafeIdentifier(data.rule_id)) failContract();
    if (!boundedString(data.title) || data.title !== riskTitleFor(data.rule_id)) failContract();
    if (!boundedString(data.summary)) failContract();
    validateSensor(data.sensor);
    validateArtifact(data.artifact);
    if (!boundedSafeInteger(data.first_observed_at_unix_ms)) failContract();
    if (!boundedSafeInteger(data.last_observed_at_unix_ms)) failContract();
    if (data.last_observed_at_unix_ms < data.first_observed_at_unix_ms) failContract();
    if (!boundedSafeInteger(data.event_count) || data.summary !== riskSummaryFor(data.event_count)) failContract();
    validateTraceIds(data.trace_ids);
    if (typeof data.contains_sensitive_data !== "boolean") failContract();
  }

  function validateIndicators(value) {
    if (!isPlainObject(value)) failContract();
    Object.entries(value).forEach(function (entry) {
      const key = entry[0];
      const item = entry[1];
      if (INDICATOR_BOOL_KEYS.has(key)) {
        if (typeof item !== "boolean") failContract();
        return;
      }
      const allowed = INDICATOR_STRING_VALUES[key];
      if (!allowed || !enumValue(item, allowed)) failContract();
    });
  }

  function validateRedaction(value) {
    if (!isPlainObject(value)) failContract();
    if (typeof value.contains_sensitive_data !== "boolean" || !boundedSafeInteger(value.redacted_count)) failContract();
  }

  function validateEvidence(value, seenEvents) {
    if (!isPlainObject(value)) failContract();
    ["event_id", "timestamp_unix_ms", "severity", "event_type", "title", "sensor", "artifact", "trust_level", "rule_id", "redaction", "indicators"].forEach(function (key) {
      if (!hasKey(value, key)) failContract();
    });
    if (!safeIdentifier(value.event_id) || seenEvents.has(value.event_id)) failContract();
    seenEvents.add(value.event_id);
    if (!boundedSafeInteger(value.timestamp_unix_ms)) failContract();
    if (!enumValue(value.severity, SEVERITIES)) failContract();
    if (!nullableSafeIdentifier(value.event_type) || value.title !== evidenceTitleFor(value.event_type)) failContract();
    validateSensor(value.sensor);
    validateArtifact(value.artifact);
    if (!(value.trust_level === null || enumValue(value.trust_level, TRUST_LEVELS))) failContract();
    if (!nullableSafeIdentifier(value.rule_id)) failContract();
    validateRedaction(value.redaction);
    validateIndicators(value.indicators);
  }

  function validateRiskPage(data, expectedOffset) {
    if (!isPlainObject(data) || data.schema_version !== "skynet.risk.v1" || data.read_only !== true || !Array.isArray(data.items)) failContract();
    const page = data.page;
    if (!isPlainObject(page) || page.limit !== PAGE_LIMIT) failContract();
    if (!boundedPageNumber(page.offset) || page.offset !== expectedOffset) failContract();
    if (!boundedPageNumber(page.returned, page.limit) || !boundedSafeInteger(page.total)) failContract();
    if (typeof page.has_more !== "boolean" || page.returned !== data.items.length) failContract();
    if (page.has_more !== (page.offset + page.returned < page.total)) failContract();
    if (page.has_more && page.returned <= 0) failContract();
    if (page.returned > 0 && page.offset + page.returned > page.total) failContract();
    const seen = new Set();
    data.items.forEach(function (item) {
      validateRiskBase(item);
      if (seen.has(item.id)) failContract();
      seen.add(item.id);
    });
    return data;
  }

  function validateRiskDetail(data, expectedId) {
    if (!isPlainObject(data) || data.schema_version !== "skynet.risk.v1" || data.read_only !== true) failContract();
    validateRiskBase(data);
    if (data.id !== expectedId) failContract();
    if (!Array.isArray(data.evidence) || data.evidence.length > MAX_EVIDENCE_ITEMS || data.evidence.length > data.event_count) failContract();
    const seenEvents = new Set();
    data.evidence.forEach(function (event) { validateEvidence(event, seenEvents); });
    return data;
  }

  function validateIngestionStatus(data) {
    if (!isPlainObject(data) || !Array.isArray(data.sources) || data.sources.length > 64) failContract();
    if (data.role_identity_assurance !== "authorized_uid_self_reported") failContract();
    if (data.state === "disabled") {
      const keys = Object.keys(data).sort();
      if (keys.join(",") !== "listener_live,role_identity_assurance,sources,state") failContract();
      if (data.listener_live !== false || data.sources.length !== 0) failContract();
      return;
    }
    if (!["healthy", "degraded"].includes(data.state) || typeof data.listener_live !== "boolean") failContract();
    if (!["fresh", "stale", "not_observed"].includes(data.transport_heartbeat_state)) failContract();
    if (!["fresh", "stale", "not_observed"].includes(data.hook_event_state) || data.hook_event_freshness_affects_state !== false) failContract();
    [
      "last_event_received_at_unix_ms", "last_event_received_age_ms",
      "last_event_committed_at_unix_ms", "last_event_committed_age_ms",
    ].forEach(function (key) {
      if (data[key] !== null && !boundedSafeInteger(data[key])) failContract();
    });
    if (!Array.isArray(data.required_reported_roles) || data.required_reported_roles.length > 3) failContract();
    const roles = new Set();
    data.required_reported_roles.forEach(function (required) {
      if (!isPlainObject(required) || !["gateway", "dashboard", "worker"].includes(required.runtime_role)) failContract();
      if (!["fresh", "stale", "absent"].includes(required.state) || roles.has(required.runtime_role)) failContract();
      roles.add(required.runtime_role);
    });
    const sourceIds = new Set();
    let contradictorySource = false;
    let anyReported = false;
    let anyFresh = false;
    const roleReports = new Map();
    data.sources.forEach(function (source) {
      if (!isPlainObject(source) || !Number.isInteger(source.authenticated_uid) || source.authenticated_uid < 0 || source.authenticated_uid > 4294967295) failContract();
      if (typeof source.source_id !== "string" || source.source_id.length > 160 || !/^[a-z0-9:-]+$/.test(source.source_id) || sourceIds.has(source.source_id)) failContract();
      if (!["gateway", "dashboard", "worker", "unknown", "legacy"].includes(source.runtime_role)) failContract();
      if (source.runtime_role === "legacy") {
        if (source.instance_id !== null) failContract();
      } else if (typeof source.instance_id !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(source.instance_id)) failContract();
      if (source.producer_reported_at_unix_ms !== null && !boundedSafeInteger(source.producer_reported_at_unix_ms)) failContract();
      if (source.producer_report_age_ms !== null && !boundedSafeInteger(source.producer_report_age_ms)) failContract();
      if ((source.producer_reported_at_unix_ms === null) !== (source.producer_report_age_ms === null)) failContract();
      if (!["available", "degraded", "stale", "unknown"].includes(source.transport_state)) failContract();
      if (source.backlog_bytes !== null && !boundedSafeInteger(source.backlog_bytes)) failContract();
      const errorCategories = ["frame_timeout", "storage", "transaction", "malformed_frame", "frame_size"];
      if (source.last_error_category === null) {
        if (source.last_error_at_unix_ms !== null || source.last_error_age_ms !== null) failContract();
      } else if (!errorCategories.includes(source.last_error_category)
          || !boundedSafeInteger(source.last_error_at_unix_ms)
          || !boundedSafeInteger(source.last_error_age_ms)) {
        failContract();
      }
      const recentSourceError = ["frame_timeout", "storage", "transaction"].includes(source.last_error_category)
        && source.last_error_age_ms <= 30000;
      const reported = source.producer_report_age_ms !== null;
      const fresh = reported && source.producer_report_age_ms <= 30000;
      if ((source.transport_state === "stale") !== (reported && !fresh)) failContract();
      if (!reported && source.transport_state !== "unknown") failContract();
      if (fresh && !["available", "degraded"].includes(source.transport_state)) failContract();
      anyReported ||= reported;
      anyFresh ||= fresh;
      if (reported) {
        const reports = roleReports.get(source.runtime_role) || [];
        reports.push({ fresh: fresh, available: source.transport_state === "available" && source.backlog_bytes === 0 });
        roleReports.set(source.runtime_role, reports);
      }
      contradictorySource ||= fresh && (source.transport_state === "degraded" || source.backlog_bytes > 0 || recentSourceError);
      sourceIds.add(source.source_id);
    });
    const expectedHeartbeat = anyFresh ? "fresh" : (anyReported ? "stale" : "not_observed");
    if (data.transport_heartbeat_state !== expectedHeartbeat) failContract();
    data.required_reported_roles.forEach(function (required) {
      const reports = roleReports.get(required.runtime_role) || [];
      const expected = reports.some(function (report) { return report.fresh && report.available; })
        ? "fresh" : (reports.length > 0 ? "stale" : "absent");
      if (required.state !== expected) failContract();
    });
    const eventExpected = data.last_event_received_age_ms === null
      ? "not_observed" : (data.last_event_received_age_ms <= 30000 ? "fresh" : "stale");
    if (data.hook_event_state !== eventExpected) failContract();
    const requiredDegraded = data.required_reported_roles.some(function (required) { return required.state !== "fresh"; });
    const healthyCoherent = data.listener_live === true
      && data.transport_heartbeat_state === "fresh"
      && !requiredDegraded
      && !contradictorySource;
    if (data.state === "healthy" && !healthyCoherent) failContract();
  }

  function validateStatus(data) {
    if (!isPlainObject(data) || data.read_only !== true) failContract();
    if (data.product !== "Skynet-EDR" || data.binary !== "skynet-edr" || data.run_mode !== "passive" || data.server !== "skynet-edr-mcp" || data.tool_count !== 6) failContract();
    if (!boundedSafeInteger(data.incident_count) || !boundedSafeInteger(data.event_count)) failContract();
    if (hasKey(data, "ingestion")) validateIngestionStatus(data.ingestion);
    return data;
  }

  function statusPath() {
    return API_ROOT + "/status";
  }

  function riskPagePath(offset) {
    if (!boundedPageNumber(offset)) failContract();
    return API_ROOT + "/risks?limit=" + PAGE_LIMIT + "&offset=" + offset;
  }

  function riskDetailPath(id) {
    if (!boundedId(id)) failContract();
    return API_ROOT + "/risks/" + encodeURIComponent(id);
  }

  function usePollingResource(loader, resourceKey, enabled) {
    const [state, setState] = useState(function () {
      return { key: resourceKey, data: null, loading: enabled, refreshing: false, error: false };
    });
    const [reloadToken, setReloadToken] = useState(0);
    const latestRequest = useRef(0);
    const reload = useCallback(function () {
      setReloadToken(function (value) { return value + 1; });
    }, []);

    useEffect(function () {
      if (!enabled) {
        latestRequest.current += 1;
        setState({ key: resourceKey, data: null, loading: false, refreshing: false, error: false });
        return undefined;
      }
      let active = true;
      function load() {
        const requestGeneration = latestRequest.current + 1;
        latestRequest.current = requestGeneration;
        setState(function (previous) {
          const cached = previous.key === resourceKey ? previous.data : null;
          const error = previous.key === resourceKey ? previous.error : false;
          return { key: resourceKey, data: cached, loading: cached === null, refreshing: cached !== null, error: error };
        });
        return Promise.resolve()
          .then(loader)
          .then(function (data) {
            if (active && requestGeneration === latestRequest.current) {
              setState({ key: resourceKey, data: data, loading: false, refreshing: false, error: false });
            }
          })
          .catch(function () {
            if (!active || requestGeneration !== latestRequest.current) return;
            setState(function (previous) {
              const cached = previous.key === resourceKey ? previous.data : null;
              return { key: resourceKey, data: cached, loading: false, refreshing: false, error: true };
            });
          });
      }
      load();
      const timer = setInterval(load, POLL_MS);
      return function () {
        active = false;
        latestRequest.current += 1;
        clearInterval(timer);
      };
    }, [loader, resourceKey, enabled, reloadToken]);

    const current = state.key === resourceKey ? state : { key: resourceKey, data: null, loading: enabled, refreshing: false, error: false };
    return { data: current.data, loading: current.loading, refreshing: current.refreshing, error: current.error, reload: reload };
  }

  function displayText(value, fallback) {
    if (value === null || value === undefined || value === "") return fallback === undefined ? "unknown" : fallback;
    return String(value);
  }

  function labelFor(value) {
    return displayText(value).replace(/_/g, " ");
  }

  function countText(value) {
    return Number.isFinite(value) ? String(value) : "0";
  }

  function formatTime(value) {
    if (!Number.isFinite(value)) return "unknown";
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) return "unknown";
    try {
      return date.toLocaleString();
    } catch (_error) {
      return "unknown";
    }
  }

  function severityVariant(value) {
    if (value === "critical" || value === "high") return "destructive";
    if (value === "medium") return "default";
    return "secondary";
  }

  function statusVariant(value) {
    if (value === "open" || value === "investigating") return "destructive";
    if (value === "contained") return "default";
    return "secondary";
  }

  function matchesFilter(value, selected) {
    return selected === "all" || displayText(value).toLowerCase() === selected;
  }

  function filterRisks(items, filters) {
    const query = displayText(filters.search, "").trim().toLowerCase();
    return items.filter(function (risk) {
      const haystack = [
        risk.id, risk.title, risk.summary, risk.rule_id, risk.severity, risk.status,
        risk.sensor.kind, risk.sensor.sensor, risk.sensor.integration,
        risk.artifact.kind, risk.artifact.display_label, risk.artifact.provider, risk.artifact.trust_level,
      ].map(function (value) { return displayText(value, ""); }).join(" ").toLowerCase();
      return (!query || haystack.includes(query))
        && matchesFilter(risk.severity, filters.severity)
        && matchesFilter(risk.status, filters.status)
        && matchesFilter(risk.artifact.kind, filters.artifactKind);
    });
  }

  function indicatorBadges(indicators) {
    const result = [];
    const boolLabels = {
      network_indicator: "Network",
      direct_ip: "Direct IP",
      delivery_indicator: "Delivery",
      sensitive_access: "Sensitive access",
      prompt_injection_indicator: "Prompt injection",
      malware_indicator: "Malware indicator",
      content_omitted: "Content omitted",
      result_omitted: "Result omitted",
      instruction_authority: "Instruction authority",
    };
    Object.keys(boolLabels).forEach(function (key) {
      if (indicators[key] === true) result.push(boolLabels[key]);
      if (key === "instruction_authority" && indicators[key] === false) result.push("No instruction authority");
    });
    const textLabels = {
      command_class: "Command class",
      expected_disposition: "Expected disposition",
      drift_kind: "Drift kind",
    };
    Object.keys(textLabels).forEach(function (key) {
      if (typeof indicators[key] === "string") result.push(textLabels[key] + ": " + labelFor(indicators[key]));
    });
    return result;
  }

  function sourcePresentation(kind) {
    return SOURCE_PRESENTATION[kind] || SOURCE_PRESENTATION.unknown;
  }

  function StateCard(props) {
    return h(Card, { role: props.role || "status", "aria-live": props.live || "polite", className: "border-border" },
      h(CardContent, { className: "py-8 text-center" },
        h("h3", { className: "text-base font-semibold" }, props.title),
        h("p", { className: "mt-2 text-sm text-muted-foreground" }, props.description)
      )
    );
  }

  function SourceBadge(props) {
    const presentation = sourcePresentation(props.kind);
    return h(Badge, { variant: "outline", title: ARTIFACT_LABELS[props.kind] || ARTIFACT_LABELS.unknown },
      presentation.glyph + " " + presentation.label
    );
  }

  function FilterBar(props) {
    const select = function (id, label, value, onChange, options) {
      return h("div", { className: "grid gap-1" },
        h(Label, { htmlFor: id }, label + " — current page"),
        h(Select, { id: id, value: value, onValueChange: onChange, "aria-label": label },
          options.map(function (option) { return h(SelectOption, { key: option[0], value: option[0] }, option[1]); })
        )
      );
    };
    return h("form", { "aria-label": "Current page filters", className: "grid gap-3 rounded-lg border bg-card p-4 md:grid-cols-2 xl:grid-cols-4", onSubmit: function (event) { event.preventDefault(); } },
      h("div", { className: "grid gap-1" },
        h(Label, { htmlFor: "skynet-risk-search" }, "Search current page"),
        h(Input, {
          id: "skynet-risk-search",
          type: "search",
          value: props.search,
          maxLength: 256,
          placeholder: "Title, rule, sensor or artifact",
          "aria-label": "Search current page risks",
          onChange: function (event) { props.onSearch(event.target.value); },
        })
      ),
      select("skynet-risk-severity", "Severity", props.severity, props.onSeverity, [
        ["all", "All severities"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["informational", "Informational"],
      ]),
      select("skynet-risk-status", "Status", props.status, props.onStatus, [
        ["all", "All statuses"], ["open", "Open"], ["investigating", "Investigating"], ["contained", "Contained"], ["resolved", "Resolved"], ["dismissed", "Dismissed"],
      ]),
      select("skynet-risk-artifact", "Source", props.artifactKind, props.onArtifactKind, [
        ["all", "All sources"], ["email", "Email"], ["url", "URL"], ["git_repository", "Git"], ["code", "Code"], ["file", "File"], ["message", "Message"], ["mcp", "MCP"], ["terminal", "Terminal"], ["unknown", "Unknown"],
      ])
    );
  }

  function Pagination(props) {
    const page = props.page;
    const start = page.returned > 0 ? page.offset + 1 : 0;
    const end = page.offset + page.returned;
    const range = page.returned === 0
      ? "Showing 0 of " + countText(page.total) + " risks"
      : "Showing " + countText(start) + "–" + countText(end) + " of " + countText(page.total) + " risks";
    return h("nav", { "aria-label": "Risk pages", className: "flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-card p-3" },
      h("div", { className: "text-sm text-muted-foreground", role: "status", "aria-live": "polite" },
        range + " · returned " + countText(page.returned)
      ),
      h("div", { className: "flex gap-2" },
        h(Button, { type: "button", variant: "outline", onClick: props.onPrevious, disabled: props.historyLength < 1 && page.offset <= 0, "aria-label": "Previous page" }, "Previous"),
        h(Button, { type: "button", variant: "outline", onClick: props.onNext, disabled: page.has_more !== true || page.offset >= MAX_OFFSET, "aria-label": "Next page" }, "Next")
      )
    );
  }

  function RiskRow(props) {
    const risk = props.risk;
    const buttonProps = {
      type: "button",
      ref: props.buttonRef,
      onClick: props.onSelect,
      "aria-expanded": props.selected,
      className: "grid w-full gap-2 p-4 text-left hover:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring " + (props.selected ? "bg-muted" : ""),
    };
    if (props.selected) buttonProps["aria-controls"] = "skynet-risk-detail-panel";
    return h("li", { className: "border-b last:border-b-0" },
      h("button", buttonProps,
        h("span", { className: "flex flex-wrap items-start justify-between gap-2" },
          h("span", { className: "font-semibold" }, risk.title),
          h(Badge, { variant: severityVariant(risk.severity) }, labelFor(risk.severity))
        ),
        h("span", { className: "flex flex-wrap gap-2" },
          h(SourceBadge, { kind: risk.artifact.kind }),
          h(Badge, { variant: statusVariant(risk.status) }, labelFor(risk.status)),
          h(Badge, { variant: "outline" }, "Rule " + displayText(risk.rule_id, "none"))
        ),
        h("span", { className: "text-xs text-muted-foreground" },
          "Sensor " + risk.sensor.sensor + " · events " + countText(risk.event_count) + " · last observed " + formatTime(risk.last_observed_at_unix_ms)
        )
      )
    );
  }

  function RiskList(props) {
    return h(Card, { className: "min-w-0 overflow-hidden" },
      h(CardHeader, null, h(CardTitle, { className: "text-base" }, "Current page risks")),
      h(CardContent, { className: "p-0" },
        h("ul", { "aria-label": "Current page risk list", className: "max-h-[65vh] overflow-y-auto" },
          props.items.map(function (risk) {
            return h(RiskRow, { key: risk.id, risk: risk, selected: props.selectedId === risk.id, buttonRef: function (node) { props.setButtonRef(risk.id, node); }, onSelect: function () { props.onSelect(risk.id); } });
          })
        )
      )
    );
  }

  function DefinitionBlock(props) {
    return h("section", { className: "rounded-lg border bg-muted/30 p-3", style: MIN_WIDTH_ZERO_STYLE },
      h("h4", { className: "mb-2 text-sm font-semibold" }, props.title),
      h("dl", { className: "grid text-sm", style: { minWidth: 0, rowGap: "0.375rem" } },
        props.rows.map(function (row) {
          return h("div", {
            key: row[0],
            className: "grid",
            style: { minWidth: 0, gridTemplateColumns: "7rem minmax(0, 1fr)", alignItems: "baseline", columnGap: "0.75rem" },
          },
            h("dt", { className: "text-muted-foreground", style: { whiteSpace: "nowrap" } }, row[0]),
            h("dd", { className: "m-0", style: WRAP_ANYWHERE_STYLE }, row[1])
          );
        })
      )
    );
  }

  function EvidenceTimeline(props) {
    return h("section", { "aria-labelledby": "skynet-evidence-heading", style: MIN_WIDTH_ZERO_STYLE },
      h("h4", { id: "skynet-evidence-heading", className: "mb-3 text-sm font-semibold" }, "Evidence timeline"),
      props.evidence.length === 0
        ? h("p", { className: "text-sm text-muted-foreground" }, "No bounded evidence entries returned for this risk.")
        : h("ol", { className: "grid min-w-0 gap-3", style: MIN_WIDTH_ZERO_STYLE }, props.evidence.map(function (event) {
          const badges = indicatorBadges(event.indicators);
          return h("li", { key: event.event_id, className: "rounded-lg border bg-card p-3", style: MIN_WIDTH_ZERO_STYLE },
            h("div", { className: "flex min-w-0 flex-wrap items-start justify-between gap-2", style: MIN_WIDTH_ZERO_STYLE },
              h("div", { className: "min-w-0", style: MIN_WIDTH_ZERO_STYLE },
                h("div", { className: "font-medium", style: WRAP_ANYWHERE_STYLE }, event.title),
                h("div", { className: "mt-1 text-xs text-muted-foreground", style: WRAP_ANYWHERE_STYLE }, formatTime(event.timestamp_unix_ms) + " · event " + event.event_id)
              ),
              h(Badge, { variant: severityVariant(event.severity) }, labelFor(event.severity))
            ),
            h("div", { className: "mt-2 flex min-w-0 flex-wrap gap-2", style: MIN_WIDTH_ZERO_STYLE },
              h(SourceBadge, { kind: event.artifact.kind }),
              h(Badge, { variant: "outline" }, "Type " + displayText(event.event_type)),
              h(Badge, { variant: "outline" }, "Trust " + labelFor(event.trust_level)),
              h(Badge, { variant: event.redaction.contains_sensitive_data ? "destructive" : "secondary" }, "Redactions " + countText(event.redaction.redacted_count)),
              (badges.length ? badges : ["No allowlisted indicators"]).map(function (label) {
                return h(Badge, { key: label, variant: "secondary" }, label);
              })
            ),
            h("p", { className: "mt-2 text-xs text-muted-foreground", style: WRAP_ANYWHERE_STYLE },
              "Rule " + displayText(event.rule_id, "none") + " · sensor " + event.sensor.kind + "/" + event.sensor.sensor + " · integration " + displayText(event.sensor.integration, "none")
            )
          );
        }))
    );
  }

  function RiskDetail(props) {
    const resource = props.resource;
    function panel(title, badges, body) {
      return h(Card, { id: "skynet-risk-detail-panel", role: "region", "aria-labelledby": "skynet-risk-detail-heading", className: "min-w-0" },
        h(CardHeader, null,
          h("div", { className: "flex flex-wrap items-start justify-between gap-2" },
            h(CardTitle, { id: "skynet-risk-detail-heading", className: "text-lg" }, title),
            h("div", { className: "flex flex-wrap gap-2" },
              badges,
              h(Button, { type: "button", variant: "outline", onClick: props.onClose, "aria-label": "Close selected risk detail" }, "Close detail")
            )
          )
        ),
        body
      );
    }
    if (resource.loading && resource.data === null) {
      return panel("Loading risk detail", null, h(CardContent, null,
        h("p", { className: "text-sm text-muted-foreground" }, "Loading the selected read-only projection.")
      ));
    }
    if (resource.error && resource.data === null) {
      return panel("Unable to load risk detail", null, h(CardContent, null,
        h("p", { role: "alert", "aria-live": "assertive", className: "text-sm text-muted-foreground" }, "The read-only backend did not return a valid risk detail.")
      ));
    }
    const risk = resource.data;
    if (!risk) return null;
    return panel(risk.title, [
      h(SourceBadge, { key: "source", kind: risk.artifact.kind }),
      h(Badge, { key: "severity", variant: severityVariant(risk.severity) }, labelFor(risk.severity)),
      h(Badge, { key: "status", variant: statusVariant(risk.status) }, labelFor(risk.status)),
    ], h(CardContent, { className: "grid min-w-0 gap-4", style: MIN_WIDTH_ZERO_STYLE },
      resource.error ? h("div", { role: "status", "aria-live": "polite", className: "rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm" }, "Stale detail: the latest refresh is unavailable; cached validated detail remains visible.") : null,
      h("p", { className: "text-sm text-muted-foreground", style: WRAP_ANYWHERE_STYLE }, risk.summary),
      h("section", { "aria-label": "Passive read-only context", className: "rounded-lg border p-3", style: MIN_WIDTH_ZERO_STYLE },
        h("h4", { className: "text-sm font-semibold" }, "Passive read-only context"),
        h("p", { className: "mt-1 text-sm text-muted-foreground" }, "This Web Dashboard view displays only validated redacted API projections. It provides refresh and navigation, never containment or mutation controls."),
        h("div", { className: "mt-2 flex min-w-0 flex-wrap gap-2", style: MIN_WIDTH_ZERO_STYLE },
          h(Badge, { variant: "outline" }, "Confidence: Not assessed"),
          h(Badge, { variant: risk.contains_sensitive_data ? "destructive" : "secondary" }, risk.contains_sensitive_data ? "Sensitive data redacted" : "No sensitive flag"),
          h(Badge, { variant: "secondary" }, "Events " + countText(risk.event_count))
        )
      ),
      h("div", { className: "grid min-w-0 gap-3 xl:grid-cols-2", style: MIN_WIDTH_ZERO_STYLE },
        h(DefinitionBlock, { title: "Artifact provenance", rows: [
          ["Kind", labelFor(risk.artifact.kind)],
          ["Label", risk.artifact.display_label],
          ["Provider", displayText(risk.artifact.provider, "none")],
          ["Trust", labelFor(risk.artifact.trust_level)],
        ] }),
        h(DefinitionBlock, { title: "Sensor provenance", rows: [
          ["Kind", labelFor(risk.sensor.kind)],
          ["Sensor", risk.sensor.sensor],
          ["Integration", displayText(risk.sensor.integration, "none")],
          ["First observed", formatTime(risk.first_observed_at_unix_ms)],
          ["Last observed", formatTime(risk.last_observed_at_unix_ms)],
        ] })
      ),
      h("section", { "aria-labelledby": "skynet-traces-heading", style: MIN_WIDTH_ZERO_STYLE },
        h("h4", { id: "skynet-traces-heading", className: "mb-2 text-sm font-semibold" }, "Trace IDs"),
        risk.trace_ids.length
          ? h("div", { className: "flex min-w-0 flex-wrap gap-2", style: MIN_WIDTH_ZERO_STYLE }, risk.trace_ids.map(function (trace) { return h(Badge, { key: trace, variant: "outline", style: WRAP_ANYWHERE_STYLE }, trace); }))
          : h("p", { className: "text-sm text-muted-foreground" }, "No trace IDs in this bounded projection.")
      ),
      h(Separator, null),
      h(EvidenceTimeline, { evidence: risk.evidence })
    ));

  }

  function backendHealth(status, page) {
    if ((status.loading && status.data === null) || (page.loading && page.data === null)) return "Checking read-only backend";
    if ((status.error && status.data === null) || (page.error && page.data === null)) return "Backend unavailable";
    if (status.error || page.error) return "Stale validated data";
    if (!status.data || !page.data) return "Backend not verified";
    return "Passive projection online";
  }

  function IngestionHealthPanel(props) {
    const ingestion = props.ingestion;
    if (!ingestion) return null;
    const disabled = ingestion.state === "disabled";
    const required = disabled || ingestion.required_reported_roles.length === 0
      ? "none configured"
      : ingestion.required_reported_roles.map(function (role) { return role.runtime_role + ": " + role.state; }).join(", ");
    const rows = [
      ["Listener", ingestion.listener_live ? "live" : "stopped"],
      ["Transport", disabled ? "disabled" : ingestion.transport_heartbeat_state],
      ["Required reported roles", required],
      ["Hook freshness", disabled ? "disabled" : ingestion.hook_event_state],
      ["Role assurance", "Authorized-UID self-reported attribution"],
    ];
    return h("section", { role: "status", "aria-live": "polite", className: "rounded-lg border bg-card p-3" },
      h("h3", { className: "text-sm font-semibold" }, "Telemetry " + ingestion.state),
      h("dl", { className: "mt-2 grid gap-1 text-sm" }, rows.map(function (row) {
        return h("div", { key: row[0], className: "flex flex-wrap gap-2" },
          h("dt", { className: "text-muted-foreground" }, row[0]),
          h("dd", null, row[1])
        );
      })),
      h("p", { className: "mt-2 text-xs text-muted-foreground" }, "Runtime role and instance are operational attribution reported by an authorized UID, not process attestation; same-UID compromise or mistaken global assignment can forge them.")
    );
  }

  function RiskExplorer() {
    const [selectedId, setSelectedId] = useState(null);
    const [navigation, setNavigation] = useState(function () { return { offset: 0, history: [] }; });
    const [search, setSearch] = useState("");
    const [severity, setSeverity] = useState("all");
    const [statusFilter, setStatusFilter] = useState("all");
    const [artifactKind, setArtifactKind] = useState("all");
    const rowRefs = useRef(Object.create(null));

    const statusLoader = useCallback(function () {
      return SDK.fetchJSON(statusPath()).then(validateStatus);
    }, []);
    const pageLoader = useCallback(function () {
      const expectedOffset = navigation.offset;
      return SDK.fetchJSON(riskPagePath(expectedOffset)).then(function (data) { return validateRiskPage(data, expectedOffset); });
    }, [navigation.offset]);
    const detailLoader = useCallback(function () {
      const expectedId = selectedId;
      return SDK.fetchJSON(riskDetailPath(expectedId)).then(function (data) { return validateRiskDetail(data, expectedId); });
    }, [selectedId]);

    const health = usePollingResource(statusLoader, "status", true);
    const risks = usePollingResource(pageLoader, "page:" + navigation.offset, true);
    const detail = usePollingResource(detailLoader, "detail:" + displayText(selectedId, "none"), Boolean(selectedId));

    const pageItems = risks.data ? risks.data.items : [];
    const visibleItems = useMemo(function () {
      return filterRisks(pageItems, { search: search, severity: severity, status: statusFilter, artifactKind: artifactKind });
    }, [pageItems, search, severity, statusFilter, artifactKind]);

    const setButtonRef = useCallback(function (id, node) {
      if (node) {
        rowRefs.current[id] = node;
      } else {
        delete rowRefs.current[id];
      }
    }, []);

    const focusRiskRow = useCallback(function (id) {
      const node = id ? rowRefs.current[id] : null;
      if (!node || typeof node.focus !== "function") return;
      if (typeof document !== "undefined" && document && typeof document.contains === "function" && !document.contains(node)) return;
      node.focus();
    }, []);

    const closeSelectedDetail = useCallback(function () {
      const closedId = selectedId;
      if (!closedId) return;
      setSelectedId(null);
      focusRiskRow(closedId);
    }, [focusRiskRow, selectedId]);

    useEffect(function () {
      if (!selectedId || typeof document === "undefined" || !document || typeof document.addEventListener !== "function") return undefined;
      function onKeyDown(event) {
        if (!event || event.key !== "Escape") return;
        if (typeof event.preventDefault === "function") event.preventDefault();
        closeSelectedDetail();
      }
      document.addEventListener("keydown", onKeyDown);
      return function () {
        if (typeof document.removeEventListener === "function") document.removeEventListener("keydown", onKeyDown);
      };
    }, [closeSelectedDetail, selectedId]);

    function resetForFilter(setter, value) {
      setter(value);
      setNavigation({ offset: 0, history: [] });
      setSelectedId(null);
    }

    function goNext() {
      if (!risks.data || risks.data.page.has_more !== true) return;
      const page = risks.data.page;
      const next = Math.min(MAX_OFFSET, page.offset + page.returned);
      setNavigation(function (previous) { return { offset: next, history: previous.history.concat([page.offset]) }; });
      setSelectedId(null);
    }

    function goPrevious() {
      setNavigation(function (previous) {
        if (previous.history.length === 0) return previous;
        return { offset: previous.history[previous.history.length - 1], history: previous.history.slice(0, -1) };
      });
      setSelectedId(null);
    }

    function refreshAll() {
      health.reload();
      risks.reload();
      if (selectedId) detail.reload();
    }

    const initialLoading = risks.loading && risks.data === null;
    const initialError = risks.error && risks.data === null;
    const stale = risks.error && risks.data !== null;
    const noServerRows = risks.data && pageItems.length === 0;
    const noFilterRows = risks.data && pageItems.length > 0 && visibleItems.length === 0;
    const refreshing = health.refreshing || risks.refreshing || detail.refreshing;

    return h("section", { "aria-labelledby": "skynet-risk-heading", className: "grid gap-4" },
      h("header", { className: "flex flex-wrap items-start justify-between gap-4" },
        h("div", { className: "max-w-3xl" },
          h("div", { className: "mb-2 flex flex-wrap gap-2" },
            h(Badge, { variant: "outline" }, "Passive · Read only"),
            h(Badge, { variant: health.error || risks.error ? "destructive" : "secondary" }, backendHealth(health, risks))
          ),
          h("h2", { id: "skynet-risk-heading", className: "text-2xl font-semibold tracking-tight" }, "Skynet-EDR Risk Explorer"),
          h("p", { className: "mt-2 text-sm text-muted-foreground" }, "Redacted skynet.risk.v1 projections from the local Skynet-EDR service. Search and filters apply to the current server page. Raw prompts, commands, destinations, paths and arbitrary attributes are never rendered.")
        ),
        h(Button, { type: "button", variant: "outline", onClick: refreshAll, disabled: refreshing, "aria-label": "Refresh Risk Explorer" }, refreshing ? "Refreshing…" : "Refresh")
      ),
      health.data && health.data.ingestion ? h(IngestionHealthPanel, { ingestion: health.data.ingestion }) : null,
      risks.data ? h(Pagination, { page: risks.data.page, historyLength: navigation.history.length, onPrevious: goPrevious, onNext: goNext }) : null,
      h(FilterBar, {
        search: search,
        severity: severity,
        status: statusFilter,
        artifactKind: artifactKind,
        onSearch: function (value) { resetForFilter(setSearch, value); },
        onSeverity: function (value) { resetForFilter(setSeverity, value); },
        onStatus: function (value) { resetForFilter(setStatusFilter, value); },
        onArtifactKind: function (value) { resetForFilter(setArtifactKind, value); },
      }),
      initialLoading ? h(StateCard, { title: "Loading read-only risk projections", description: "Checking the authenticated local plugin API." }) : null,
      initialError ? h(StateCard, { role: "alert", live: "assertive", title: "Unable to load risks", description: "The read-only backend did not return a valid risk page." }) : null,
      stale ? h("div", { role: "status", "aria-live": "polite", className: "rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm" }, "Stale data: the latest refresh is unavailable. Cached validated rows remain visible.") : null,
      noServerRows ? h(StateCard, { title: "No risks recorded", description: "The current server page contains no risk projections." }) : null,
      noFilterRows ? h(StateCard, { title: "No current-page matches", description: "Risks exist on this server page, but none match the active filters." }) : null,
      risks.data && visibleItems.length > 0 ? h("div", { className: "grid min-w-0 gap-4 xl:grid-cols-[minmax(20rem,0.85fr)_minmax(24rem,1.15fr)]" },
        h(RiskList, { items: visibleItems, selectedId: selectedId, setButtonRef: setButtonRef, onSelect: function (id) { setSelectedId(function (current) { return current === id ? null : id; }); } }),
        selectedId
          ? h(RiskDetail, { resource: detail, onClose: closeSelectedDetail })
          : h(StateCard, { title: "Select a risk", description: "Inspect its read-only context, source-aware provenance, traces and evidence timeline." })
      ) : null
    );
  }

  registry.register("skynet-edr", RiskExplorer);
})();
