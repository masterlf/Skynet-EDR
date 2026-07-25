import React from 'react';
import { jsx, jsxs } from 'react/jsx-runtime';
import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  PALETTE_AREA,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  ScrollArea,
  SearchField,
  Skeleton,
  fmtDateTime,
  host,
  useQuery,
} from '@hermes/plugin-sdk';

const POLL_MS = 10000;
const PAGE_PATH = '/skynet-edr/risks';
const TRACE_LIMIT = 10;
const PAGE_LIMIT = 50;
const MAX_OFFSET = Number.MAX_SAFE_INTEGER;
const MAX_ID_LENGTH = 256;
const MAX_ENCODED_ID_LENGTH = 3072;
const MAX_TEXT_LENGTH = 4096;
const MAX_TRACE_IDS = 10;
const MAX_EVIDENCE_ITEMS = 50;
const CONTRACT_ERROR = 'Invalid read-only risk projection';
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'informational']);
const STATUSES = new Set(['open', 'investigating', 'contained', 'resolved', 'dismissed']);
const SOURCE_KINDS = new Set(['sensor', 'process', 'file', 'network', 'mcp_tool', 'configuration', 'scheduled_task', 'messaging']);
const ARTIFACT_KINDS = new Set(['email', 'url', 'git_repository', 'code', 'file', 'message', 'mcp', 'terminal', 'unknown']);
const TRUST_LEVELS = new Set(['authenticated_user', 'runtime_policy', 'untrusted_content', 'tool_output', 'agent_action', 'sensor_observation']);
const ARTIFACT_LABELS = { email: 'Email content', url: 'URL content', git_repository: 'Git repository', code: 'Code content', file: 'File content', message: 'Message content', mcp: 'MCP content', terminal: 'Terminal output', unknown: 'Unclassified artifact' };
const EVENT_TITLES = { 'agent.tool.requested': 'Tool request evidence', 'agent.tool.completed': 'Tool completion evidence', 'agent.content.ingested': 'Content ingestion evidence', 'agent.network.egress': 'Network egress evidence', 'agent.file.accessed': 'File access evidence', 'agent.mcp.tool.requested': 'MCP tool request evidence', 'agent.config.changed': 'Configuration change evidence', 'agent.automation.scheduled': 'Automation schedule evidence', 'agent.approval.granted': 'Approval or scope change evidence', 'agent.llm.call.requested': 'Model call request evidence', 'agent.llm.call.completed': 'Model call completion evidence' };
const RISK_TITLES = { 'EDR-MCP-001': 'MCP network activity after untrusted content', 'EDR-CONFIG-001': 'Agent configuration drift detected', 'EDR-CRON-001': 'Risky unattended automation detected', 'EDR-PI-001': 'Privileged tool request after untrusted content', 'EDR-MSG-001': 'Suspicious message delivery activity', 'EDR-NET-001': 'Direct-IP egress activity', 'EDR-SCOPE-001': 'Privilege or scope expansion activity', 'EDR-PERSIST-001': 'Agent persistence change activity', 'EDR-EXFIL-001': 'Sensitive access followed by outbound delivery', 'EDR-MALWARE-001': 'Malware-like content supplied to AI runtime' };
const INDICATOR_BOOL_KEYS = new Set(['network_indicator', 'direct_ip', 'delivery_indicator', 'sensitive_access', 'prompt_injection_indicator', 'malware_indicator', 'content_omitted', 'result_omitted', 'instruction_authority']);
const INDICATOR_STRING_VALUES = {
  command_class: new Set(['network_egress', 'file_read', 'code_execution', 'other']),
  expected_disposition: new Set(['benign', 'suspicious', 'malicious', 'unknown']),
  drift_kind: new Set(['changed', 'created', 'deleted']),
};

function text(value, fallback = 'unknown') {
  if (value === null || value === undefined || value === '') return fallback;
  return String(value);
}

function titleText(value, fallback = 'Untitled risk') {
  return text(value, fallback);
}

function option(value, label) {
  return jsx('option', { value, children: label });
}

function labelFor(value) {
  return text(value).replace(/_/g, ' ');
}

function countText(value) {
  return Number.isFinite(value) ? String(value) : '0';
}

function badgeVariantForSeverity(severity) {
  switch (severity) {
    case 'critical':
      return 'destructive';
    case 'high':
      return 'warn';
    case 'medium':
      return 'default';
    case 'low':
    case 'informational':
      return 'muted';
    default:
      return 'outline';
  }
}

function badgeVariantForStatus(status) {
  switch (status) {
    case 'open':
    case 'investigating':
      return 'warn';
    case 'contained':
      return 'default';
    case 'resolved':
    case 'dismissed':
      return 'muted';
    default:
      return 'outline';
  }
}

function matchesFilter(value, selected) {
  return selected === 'all' || text(value).toLowerCase() === selected;
}

function filterRisks(risks, filters) {
  const query = text(filters.search, '').trim().toLowerCase();
  return risks.filter((risk) => {
    const haystack = [
      risk.id,
      risk.title,
      risk.summary,
      risk.rule_id,
      risk.severity,
      risk.status,
      risk.sensor?.kind,
      risk.sensor?.sensor,
      risk.sensor?.integration,
      risk.artifact?.kind,
      risk.artifact?.display_label,
      risk.artifact?.provider,
      risk.artifact?.trust_level,
    ].map((value) => text(value, '')).join(' ').toLowerCase();
    return (!query || haystack.includes(query))
      && matchesFilter(risk.severity, filters.severity)
      && matchesFilter(risk.status, filters.status)
      && matchesFilter(risk.artifact?.kind, filters.artifactKind);
  });
}

function formatTime(value) {
  if (!Number.isFinite(value)) return 'unknown';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'unknown';
  return fmtDateTime.format(new Date(value));
}

function indicatorBadges(indicators) {
  if (!indicators || typeof indicators !== 'object') return [];
  const badges = [];
  const boolMap = [
    ['network_indicator', 'Network'],
    ['direct_ip', 'Direct IP'],
    ['delivery_indicator', 'Delivery'],
    ['sensitive_access', 'Sensitive access'],
    ['prompt_injection_indicator', 'Prompt injection'],
    ['malware_indicator', 'Malware indicator'],
    ['content_omitted', 'Content omitted'],
    ['result_omitted', 'Result omitted'],
    ['instruction_authority', 'Instruction authority'],
  ];
  boolMap.forEach(([key, label]) => {
    if (indicators[key] === true) badges.push({ label, value: 'true', tone: key === 'instruction_authority' ? 'destructive' : 'warn' });
    if (indicators[key] === false && key === 'instruction_authority') badges.push({ label, value: 'false', tone: 'muted' });
  });
  const stringMap = [
    ['command_class', 'Command class'],
    ['expected_disposition', 'Expected disposition'],
    ['drift_kind', 'Drift kind'],
  ];
  stringMap.forEach(([key, label]) => {
    if (typeof indicators[key] === 'string' && indicators[key]) badges.push({ label, value: labelFor(indicators[key]), tone: 'outline' });
  });
  return badges;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function hasKey(value, key) {
  return isPlainObject(value) && Object.prototype.hasOwnProperty.call(value, key);
}

function boundedPageNumber(value, max = MAX_OFFSET) {
  return Number.isInteger(value) && value >= 0 && value <= max;
}

function boundedSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function failContract() {
  throw new Error(CONTRACT_ERROR);
}

function boundedString(value, max = MAX_TEXT_LENGTH) {
  return typeof value === 'string' && value.length > 0 && Array.from(value).length <= max;
}

function nullableBoundedString(value, max = MAX_TEXT_LENGTH) {
  return value === null || boundedString(value, max);
}

function boundedId(value) {
  if (!boundedString(value, MAX_ID_LENGTH)) return false;
  try {
    return encodeURIComponent(value).length <= MAX_ENCODED_ID_LENGTH;
  } catch (_error) {
    return false;
  }
}

function enumValue(value, allowed) {
  return typeof value === 'string' && allowed.has(value);
}

function safeIdentifier(value) {
  return typeof value === 'string' && /^[A-Za-z0-9:._-]{1,128}$/.test(value.trim()) && value.trim() === value;
}

function nullableSafeIdentifier(value) {
  return value === null || safeIdentifier(value);
}

function validLocatorHash(value) {
  return value === null || /^sha256:[0-9a-f]{64}$/.test(value);
}

function evidenceTitleFor(eventType) {
  return EVENT_TITLES[eventType] || 'Security event evidence';
}

function riskTitleFor(ruleId) {
  return RISK_TITLES[ruleId] || 'Security risk detected';
}

function riskSummaryFor(eventCount) {
  const noun = eventCount === 1 ? 'event' : 'events';
  return 'Read-only projection of ' + eventCount + ' redacted evidence ' + noun + '. Review sensor and artifact provenance plus allowlisted indicators.';
}

function validateSensor(value) {
  if (!isPlainObject(value)) failContract();
  for (const key of ['kind', 'sensor', 'integration']) if (!hasKey(value, key)) failContract();
  if (!enumValue(value.kind, SOURCE_KINDS)) failContract();
  if (!safeIdentifier(value.sensor)) failContract();
  if (!nullableSafeIdentifier(value.integration)) failContract();
}

function validateArtifact(value) {
  if (!isPlainObject(value)) failContract();
  for (const key of ['kind', 'provider', 'display_label', 'locator_hash', 'trust_level']) if (!hasKey(value, key)) failContract();
  if (!enumValue(value.kind, ARTIFACT_KINDS)) failContract();
  if (!nullableSafeIdentifier(value.provider)) failContract();
  if (value.display_label !== ARTIFACT_LABELS[value.kind]) failContract();
  if (!validLocatorHash(value.locator_hash)) failContract();
  if (!(value.trust_level === null || enumValue(value.trust_level, TRUST_LEVELS))) failContract();
}

function validateTraceIds(value) {
  if (!Array.isArray(value) || value.length > MAX_TRACE_IDS) failContract();
  const seen = new Set();
  value.forEach((trace) => {
    if (!safeIdentifier(trace) || seen.has(trace)) failContract();
    seen.add(trace);
  });
}

function validateRiskBase(data) {
  for (const key of ['id', 'severity', 'confidence', 'status', 'rule_id', 'title', 'summary', 'sensor', 'artifact', 'first_observed_at_unix_ms', 'last_observed_at_unix_ms', 'event_count', 'trace_ids', 'contains_sensitive_data']) if (!hasKey(data, key)) failContract();
  if (!boundedId(data.id)) failContract();
  if (!enumValue(data.severity, SEVERITIES)) failContract();
  if (data.confidence !== null) failContract();
  if (!enumValue(data.status, STATUSES)) failContract();
  if (!nullableSafeIdentifier(data.rule_id)) failContract();
  if (!boundedString(data.title)) failContract();
  if (data.title !== riskTitleFor(data.rule_id)) failContract();
  if (!boundedString(data.summary)) failContract();
  validateSensor(data.sensor);
  validateArtifact(data.artifact);
  if (!boundedSafeInteger(data.first_observed_at_unix_ms)) failContract();
  if (!boundedSafeInteger(data.last_observed_at_unix_ms)) failContract();
  if (data.last_observed_at_unix_ms < data.first_observed_at_unix_ms) failContract();
  if (!boundedSafeInteger(data.event_count)) failContract();
  if (data.summary !== riskSummaryFor(data.event_count)) failContract();
  validateTraceIds(data.trace_ids);
  if (typeof data.contains_sensitive_data !== 'boolean') failContract();
}

function validateIndicators(value) {
  if (!isPlainObject(value)) failContract();
  Object.entries(value).forEach(([key, val]) => {
    if (INDICATOR_BOOL_KEYS.has(key)) {
      if (typeof val !== 'boolean') failContract();
      return;
    }
    const allowed = INDICATOR_STRING_VALUES[key];
    if (!allowed || !enumValue(val, allowed)) failContract();
  });
}

function validateRedaction(value) {
  if (!isPlainObject(value)) failContract();
  if (typeof value.contains_sensitive_data !== 'boolean') failContract();
  if (!boundedSafeInteger(value.redacted_count)) failContract();
}

function validateEvidence(value, seenEvents) {
  if (!isPlainObject(value)) failContract();
  for (const key of ['event_id', 'timestamp_unix_ms', 'severity', 'event_type', 'title', 'sensor', 'artifact', 'trust_level', 'rule_id', 'redaction', 'indicators']) if (!hasKey(value, key)) failContract();
  if (!safeIdentifier(value.event_id) || seenEvents.has(value.event_id)) failContract();
  seenEvents.add(value.event_id);
  if (!boundedSafeInteger(value.timestamp_unix_ms)) failContract();
  if (!enumValue(value.severity, SEVERITIES)) failContract();
  if (!nullableSafeIdentifier(value.event_type)) failContract();
  if (value.title !== evidenceTitleFor(value.event_type)) failContract();
  validateSensor(value.sensor);
  validateArtifact(value.artifact);
  if (!(value.trust_level === null || enumValue(value.trust_level, TRUST_LEVELS))) failContract();
  if (!nullableSafeIdentifier(value.rule_id)) failContract();
  validateRedaction(value.redaction);
  validateIndicators(value.indicators);
}

function validateRiskPage(data, expectedOffset) {
  if (!isPlainObject(data) || data.schema_version !== 'skynet.risk.v1' || data.read_only !== true || !Array.isArray(data.items)) failContract();
  const page = data.page;
  if (!isPlainObject(page)) failContract();
  if (page.limit !== PAGE_LIMIT) failContract();
  if (!boundedPageNumber(page.offset) || page.offset !== expectedOffset) failContract();
  if (!boundedPageNumber(page.returned, page.limit)) failContract();
  if (!boundedSafeInteger(page.total)) failContract();
  if (typeof page.has_more !== 'boolean') failContract();
  if (page.returned !== data.items.length) failContract();
  if (page.has_more !== (page.offset + page.returned < page.total)) failContract();
  if (page.has_more === true && page.returned <= 0) failContract();
  if (page.returned > 0 && page.offset + page.returned > page.total) failContract();
  const seen = new Set();
  data.items.forEach((item) => {
    if (!isPlainObject(item)) failContract();
    validateRiskBase(item);
    if (seen.has(item.id)) failContract();
    seen.add(item.id);
  });
  return data;
}

function validateRiskDetail(data, expectedId) {
  if (!isPlainObject(data) || data.schema_version !== 'skynet.risk.v1' || data.read_only !== true) failContract();
  validateRiskBase(data);
  if (data.id !== expectedId) failContract();
  if (!Array.isArray(data.evidence) || data.evidence.length > MAX_EVIDENCE_ITEMS || data.evidence.length > data.event_count) failContract();
  const seenEvents = new Set();
  data.evidence.forEach((event) => validateEvidence(event, seenEvents));
  return data;
}

function validateStatus(data) {
  if (!isPlainObject(data) || data.read_only !== true) failContract();
  if (data.product !== 'Skynet-EDR' || data.binary !== 'skynet-edr' || data.run_mode !== 'passive' || data.server !== 'skynet-edr-mcp' || data.tool_count !== 6) failContract();
  for (const key of ['incident_count', 'event_count']) {
    if (!boundedSafeInteger(data[key])) failContract();
  }
  return data;
}

function previousOffset(offset) {
  if (!Number.isFinite(offset)) return 0;
  return Math.max(0, Math.min(MAX_OFFSET, Math.floor(offset / PAGE_LIMIT) * PAGE_LIMIT) - PAGE_LIMIT);
}

function nextOffset(page) {
  const offset = Number.isFinite(page?.offset) ? page.offset : 0;
  const returned = Number.isFinite(page?.returned) ? page.returned : PAGE_LIMIT;
  if (page?.has_more !== true) return Math.max(0, Math.min(MAX_OFFSET, offset));
  return Math.max(0, Math.min(MAX_OFFSET, offset + returned));
}

function initialPageNavigationState() {
  return { offset: 0, history: [] };
}

function recordNextPage(state, page) {
  const offset = Number.isFinite(page?.offset) ? Math.max(0, Math.min(MAX_OFFSET, Math.floor(page.offset))) : state.offset;
  const next = nextOffset(page);
  return { offset: next, history: [...(Array.isArray(state.history) ? state.history : []), offset] };
}

function recordPreviousPage(state) {
  const history = Array.isArray(state.history) ? state.history : [];
  if (history.length > 0) {
    const previous = history[history.length - 1];
    return { offset: previous, history: history.slice(0, -1) };
  }
  return { offset: previousOffset(state.offset), history: [] };
}

function resetPageNavigation(_state) {
  return initialPageNavigationState();
}

function encodeRiskPathSegment(id) {
  if (id === '.') return '%2E';
  if (id === '..') return '%2E%2E';
  return encodeURIComponent(id);
}

function riskDetailPath(id) {
  return '/risks/' + encodeRiskPathSegment(id);
}

function pageMeta(data) {
  return data?.page || { returned: 0, total: 0, limit: PAGE_LIMIT, offset: 0, has_more: false };
}

function pageRangeText(meta) {
  if (!meta || meta.returned < 1) return 'Showing 0 of ' + countText(meta?.total) + ' risks';
  const start = meta.offset + 1;
  const end = meta.offset + meta.returned;
  return 'Showing ' + countText(start) + '–' + countText(end) + ' of ' + countText(meta.total) + ' risks';
}

function backendState(status, risks) {
  if (status.isLoading || risks.isLoading) return 'Backend health: checking read-only loopback';
  if (status.error || risks.error) return 'Backend health: unavailable or invalid response';
  try {
    validateStatus(status.data);
    validateRiskPage(risks.data, risks.data?.page?.offset);
    return 'Backend health: passive read-only projection online';
  } catch (_error) {
    return 'Backend health: response received, read-only flag not asserted';
  }
}

function riskPagePath(offset) {
  const boundedOffset = Number.isFinite(offset) ? Math.max(0, Math.min(MAX_OFFSET, Math.floor(offset))) : 0;
  return '/risks?limit=' + PAGE_LIMIT + '&offset=' + boundedOffset;
}

function RiskExplorer({ ctx }) {
  const [selectedId, setSelectedId] = React.useState(null);
  const [offset, setOffset] = React.useState(0);
  const [offsetHistory, setOffsetHistory] = React.useState([]);
  const [search, setSearch] = React.useState('');
  const [severity, setSeverity] = React.useState('all');
  const [status, setStatus] = React.useState('all');
  const [artifactKind, setArtifactKind] = React.useState('all');
  const risks = useQuery({
    queryKey: ['skynet-edr', 'risks', offset],
    queryFn: () => Promise.resolve(ctx.rest(riskPagePath(offset))).then((data) => validateRiskPage(data, offset)),
    refetchInterval: POLL_MS,
  });
  const health = useQuery({
    queryKey: ['skynet-edr', 'status'],
    queryFn: () => Promise.resolve(ctx.rest('/status')).then(validateStatus),
    refetchInterval: POLL_MS,
  });
  const detail = useQuery({
    queryKey: ['skynet-edr', 'risk', selectedId],
    queryFn: () => Promise.resolve(ctx.rest(riskDetailPath(selectedId))).then((data) => validateRiskDetail(data, selectedId)),
    enabled: Boolean(selectedId),
    refetchInterval: POLL_MS,
  });
  const resetPageForFilter = (setter) => (value) => {
    setter(value);
    setOffset(0);
    setOffsetHistory([]);
    setSelectedId(null);
  };
  const changePage = (next, history = offsetHistory) => {
    setOffset(next);
    setOffsetHistory(history);
    setSelectedId(null);
  };
  const goNext = () => {
    const state = recordNextPage({ offset, history: offsetHistory }, meta);
    changePage(state.offset, state.history);
  };
  const goPrevious = () => {
    const state = recordPreviousPage({ offset, history: offsetHistory });
    changePage(state.offset, state.history);
  };
  const riskPageAvailable = Boolean(risks.data);
  const pageItems = riskPageAvailable && Array.isArray(risks.data.items) ? risks.data.items : [];
  const items = riskPageAvailable ? filterRisks(pageItems, { search, severity, status, artifactKind }) : [];
  const meta = pageMeta(risks.data);
  const hasPageRisks = riskPageAvailable && pageItems.length > 0;
  const noFilterMatch = hasPageRisks && !items.length;
  const isFetching = risks.isFetching || health.isFetching;
  const initialLoading = risks.isLoading && !riskPageAvailable;
  const initialError = !risks.isLoading && risks.error && !riskPageAvailable;
  const staleError = risks.error && riskPageAvailable;
  return jsxs('section', { 'aria-label': 'Skynet-EDR Risk Explorer', style: styles.shell, children: [
    jsxs('header', { style: styles.header, children: [
      jsxs('div', { style: styles.titleBlock, children: [
        jsxs('div', { style: styles.eyebrowRow, children: [
          jsx(Badge, { variant: 'outline', children: 'Passive · Read only' }),
          jsx(Badge, { variant: health.error || risks.error ? 'destructive' : 'muted', children: backendState(health, risks) }),
        ] }),
        jsx('h2', { style: styles.heading, children: 'Skynet-EDR Risk Explorer' }),
        jsx('p', { style: styles.muted, children: 'Current server page risk triage from redacted skynet.risk.v1 projections. Search and filters apply only to the loaded server page. Raw prompts, commands, destinations and local paths are not rendered.' }),
      ] }),
      jsx(Button, { type: 'button', variant: 'outline', onClick: () => { risks.refetch(); health.refetch(); if (selectedId) detail.refetch(); }, disabled: isFetching, children: isFetching ? 'Refreshing…' : 'Refresh' }),
    ] }),
    riskPageAvailable ? jsx(PageMetadata, { meta, loadedCount: pageItems.length, visibleCount: items.length, onPrevious: goPrevious, onNext: goNext }) : null,
    jsx(Filters, { search, setSearch: resetPageForFilter(setSearch), severity, setSeverity: resetPageForFilter(setSeverity), status, setStatus: resetPageForFilter(setStatus), artifactKind, setArtifactKind: resetPageForFilter(setArtifactKind) }),
    initialLoading ? jsx(LoadingState, {}) : null,
    initialError ? jsx(ErrorState, { title: 'Unable to load risks', description: 'The read-only backend did not return a valid risk page.' }) : null,
    staleError ? jsx('div', { role: 'status', 'aria-live': 'polite', style: styles.warning, children: 'Stale data: the latest refresh is unavailable. This warning is generic and cached validated rows remain visible.' }) : null,
    riskPageAvailable && !hasPageRisks ? jsx(EmptyState, { title: 'No risks recorded', description: 'The loaded current server page contains no risk projections.' }) : null,
    riskPageAvailable && noFilterMatch ? jsx(EmptyState, { title: 'No current-page matches', description: 'The current server page has risks, but none match the active filters or search.' }) : null,
    riskPageAvailable && items.length ? jsxs('div', { style: styles.workspace, children: [
      jsx(RiskList, { items, selectedId, setSelectedId }),
      selectedId ? jsx(RiskDetail, { detail }) : jsx(EmptyState, { title: 'Select a risk', description: 'Open an item to inspect read-only context, provenance, traces and bounded evidence.' }),
    ] }) : null,
  ] });
}

function PageMetadata({ meta, loadedCount, visibleCount, onPrevious, onNext }) {
  return jsxs('aside', { 'aria-label': 'Page metadata', style: styles.metaGrid, children: [
    jsx(MetaCard, { label: 'Current page returned', value: countText(meta.returned), note: 'API returned count' }),
    jsx(MetaCard, { label: 'Current page visible', value: countText(visibleCount), note: 'after current-page filters' }),
    jsx(MetaCard, { label: 'Current page loaded', value: countText(loadedCount), note: 'items available locally' }),
    jsx(MetaCard, { label: 'Total reported by API', value: countText(meta.total), note: 'server-reported total' }),
    jsx(MetaCard, { label: 'Page range', value: pageRangeText(meta), note: 'server pagination window' }),
    jsx(MetaCard, { label: 'Has more', value: meta.has_more ? 'yes' : 'no', note: 'server page control' }),
    jsxs('div', { style: styles.pager, children: [
      jsx(Button, { type: 'button', variant: 'outline', onClick: onPrevious, disabled: meta.offset <= 0, 'aria-label': 'Previous page', children: 'Previous' }),
      jsx(Button, { type: 'button', variant: 'outline', onClick: onNext, disabled: meta.has_more !== true || meta.offset >= MAX_OFFSET, 'aria-label': 'Next page', children: 'Next' }),
    ] }),
  ] });
}

function MetaCard({ label, value, note }) {
  return jsxs('div', { style: styles.metaCard, children: [
    jsx('div', { style: styles.kicker, children: label }),
    jsx('div', { style: styles.metaValue, children: value }),
    jsx('div', { style: styles.tertiary, children: note }),
  ] });
}

function Filters({ search, setSearch, severity, setSeverity, status, setStatus, artifactKind, setArtifactKind }) {
  return jsxs('form', { 'aria-label': 'Current page filters', style: styles.filters, onSubmit: (event) => event.preventDefault(), children: [
    jsx('div', { style: styles.field, children: jsxs('span', { style: styles.fieldBody, children: [
      jsx('span', { style: styles.label, children: 'Search current page' }),
      jsx(SearchField, { value: search, onChange: setSearch, placeholder: 'Search title, rule, sensor or artifact', 'aria-label': 'Search current page risks' }),
    ] }) }),
    jsx(SelectField, { label: 'Severity', value: severity, onChange: setSeverity, children: [option('all', 'All severities'), option('critical', 'Critical'), option('high', 'High'), option('medium', 'Medium'), option('low', 'Low'), option('informational', 'Informational')] }),
    jsx(SelectField, { label: 'Status', value: status, onChange: setStatus, children: [option('all', 'All statuses'), option('open', 'Open'), option('investigating', 'Investigating'), option('contained', 'Contained'), option('resolved', 'Resolved'), option('dismissed', 'Dismissed')] }),
    jsx(SelectField, { label: 'Artifact kind', value: artifactKind, onChange: setArtifactKind, children: [option('all', 'All artifacts'), option('email', 'Email'), option('url', 'URL'), option('git_repository', 'Git repository'), option('code', 'Code'), option('file', 'File'), option('message', 'Message'), option('mcp', 'MCP'), option('terminal', 'Terminal'), option('unknown', 'Unknown')] }),
  ] });
}

function SelectField({ label, value, onChange, children }) {
  return jsx('label', { style: styles.field, children: jsxs('span', { style: styles.fieldBody, children: [
    jsx('span', { style: styles.label, children: label + ' — current page' }),
    jsx('select', { value, onChange: (event) => onChange(event.target.value), style: styles.select, children }),
  ] }) });
}

function LoadingState() {
  return jsxs('div', { role: 'status', 'aria-live': 'polite', style: styles.loading, children: [
    jsx('span', { style: styles.visuallyHidden, children: 'Loading read-only risk projections' }),
    jsx(Skeleton, { style: styles.skeletonTall }),
    jsx(Skeleton, { style: styles.skeletonShort }),
  ] });
}

function RiskList({ items, selectedId, setSelectedId }) {
  return jsx('section', { 'aria-label': 'Current page risk list', style: styles.panel, children: jsx(ScrollArea, { style: styles.list, children: jsx('ul', { style: styles.listInner, children: items.map((risk) => jsx(RiskRow, { risk, selected: selectedId === risk.id, onSelect: () => setSelectedId(risk.id) }, risk.id)) }) }) });
}

function RiskRow({ risk, selected, onSelect }) {
  return jsx('li', { style: styles.listItem, children: jsx('button', { type: 'button', 'aria-pressed': selected, onClick: onSelect, style: selected ? styles.rowSelected : styles.row, children: [
    jsxs('span', { style: styles.rowTop, children: [
      jsx('span', { style: styles.rowTitle, children: titleText(risk.title) }),
      jsx(Badge, { variant: badgeVariantForSeverity(risk.severity), children: labelFor(risk.severity) }),
    ] }),
    jsxs('span', { style: styles.badgeLine, children: [
      jsx(Badge, { variant: badgeVariantForStatus(risk.status), children: labelFor(risk.status) }),
      jsx(Badge, { variant: 'outline', children: 'rule ' + text(risk.rule_id, 'none') }),
      jsx(Badge, { variant: 'muted', children: text(risk.artifact?.kind) + ' · ' + text(risk.artifact?.display_label) }),
    ] }),
    jsxs('span', { style: styles.rowMeta, children: [
      'sensor ', text(risk.sensor?.sensor), ' · integration ', text(risk.sensor?.integration, 'none'), ' · events ', countText(risk.event_count), ' · last observed ', formatTime(risk.last_observed_at_unix_ms),
    ] }),
  ] }) });
}

function RiskDetail({ detail }) {
  const hasCachedDetail = Boolean(detail.data);
  if (detail.isLoading && !hasCachedDetail) return jsxs('section', { 'aria-label': 'Risk detail loading', role: 'status', 'aria-live': 'polite', style: styles.detail, children: [jsx('span', { style: styles.visuallyHidden, children: 'Loading selected risk detail' }), jsx(Skeleton, { style: styles.skeletonTall })] });
  if (detail.error && !hasCachedDetail) return jsx('section', { 'aria-label': 'Risk detail error', style: styles.detail, children: jsx(ErrorState, { title: 'Unable to load risk detail', description: 'The read-only backend returned an error for this risk.' }) });
  const risk = detail.data;
  if (!risk) return null;
  const staleDetail = detail.error && hasCachedDetail;
  const evidence = Array.isArray(risk.evidence) ? risk.evidence : [];
  const traces = Array.isArray(risk.trace_ids) ? risk.trace_ids.slice(0, TRACE_LIMIT) : [];
  return jsxs('article', { 'aria-label': 'Risk detail', style: styles.detail, children: [
    jsxs('header', { style: styles.detailHeader, children: [
      jsx('h3', { style: styles.detailTitle, children: titleText(risk.title) }),
      jsxs('div', { style: styles.badgeLine, children: [
        jsx(Badge, { variant: badgeVariantForSeverity(risk.severity), children: labelFor(risk.severity) }),
        jsx(Badge, { variant: badgeVariantForStatus(risk.status), children: labelFor(risk.status) }),
        jsx(Badge, { variant: 'outline', children: text(risk.rule_id, 'rule none') }),
      ] }),
    ] }),
    jsx('p', { style: styles.summary, children: text(risk.summary, 'No operator summary available.') }),
    jsxs('section', { 'aria-label': 'Passive read-only context', style: styles.contextPanel, children: [
      jsx('div', { style: styles.kicker, children: 'read-only context' }),
      jsx('p', { style: styles.muted, children: 'This Desktop view is passive. It displays only redacted API projections and provides refresh/navigation, not containment or mutation controls.' }),
      staleDetail ? jsx('div', { role: 'status', 'aria-live': 'polite', style: styles.warning, children: 'Stale detail: the latest refresh is unavailable; cached validated detail remains visible.' }) : null,
      jsxs('div', { style: styles.badgeLine, children: [
        jsx(Badge, { variant: 'outline', children: 'confidence Not assessed' }),
        jsx(Badge, { variant: risk.contains_sensitive_data ? 'warn' : 'muted', children: risk.contains_sensitive_data ? 'redacted sensitive data' : 'no sensitive flag' }),
        jsx(Badge, { variant: 'muted', children: 'events ' + countText(risk.event_count) }),
      ] }),
    ] }),
    jsxs('div', { style: styles.provenanceGrid, children: [
      jsx(ProvenanceBlock, { title: 'Artifact provenance', rows: [
        ['Kind', labelFor(risk.artifact?.kind)],
        ['Label', text(risk.artifact?.display_label)],
        ['Provider', text(risk.artifact?.provider, 'none')],
        ['Trust', labelFor(risk.artifact?.trust_level)],
      ] }),
      jsx(ProvenanceBlock, { title: 'Sensor provenance', rows: [
        ['Kind', labelFor(risk.sensor?.kind)],
        ['Sensor', text(risk.sensor?.sensor)],
        ['Integration', text(risk.sensor?.integration, 'none')],
        ['First observed', formatTime(risk.first_observed_at_unix_ms)],
        ['Last observed', formatTime(risk.last_observed_at_unix_ms)],
      ] }),
    ] }),
    jsx(TraceList, { traces, total: Array.isArray(risk.trace_ids) ? risk.trace_ids.length : 0 }),
    jsx(EvidenceList, { evidence }),
  ] });
}

function ProvenanceBlock({ title, rows }) {
  return jsxs('section', { style: styles.provenanceBlock, children: [
    jsx('h4', { style: styles.blockTitle, children: title }),
    jsx('dl', { style: styles.dl, children: rows.map(([label, value]) => jsxs('div', { style: styles.dlRow, children: [
      jsx('dt', { style: styles.dt, children: label }),
      jsx('dd', { style: styles.dd, children: value }),
    ] }, label)) }),
  ] });
}

function TraceList({ traces, total }) {
  return jsxs('section', { 'aria-label': 'Trace identifiers', style: styles.provenanceBlock, children: [
    jsx('h4', { style: styles.blockTitle, children: 'Trace IDs' }),
    traces.length ? jsx('div', { style: styles.badgeLine, children: traces.map((trace) => jsx(Badge, { variant: 'outline', children: trace }, trace)) }) : jsx('p', { style: styles.muted, children: 'No trace IDs in this bounded projection.' }),
    jsx('p', { style: styles.tertiary, children: 'Showing ' + countText(traces.length) + ' of ' + countText(total) + ' trace IDs, capped at ' + countText(TRACE_LIMIT) + '.' }),
  ] });
}

function EvidenceList({ evidence }) {
  return jsxs('section', { 'aria-label': 'Evidence timeline', style: styles.evidencePanel, children: [
    jsx('h4', { style: styles.blockTitle, children: 'Evidence timeline' }),
    evidence.length ? jsx('ol', { style: styles.evidenceList, children: evidence.map((event) => jsx(EvidenceItem, { event }, text(event.event_id))) }) : jsx('p', { style: styles.muted, children: 'No bounded evidence entries returned for this risk.' }),
  ] });
}

function EvidenceItem({ event }) {
  const badges = indicatorBadges(event.indicators);
  return jsxs('li', { style: styles.evidenceItem, children: [
    jsxs('div', { style: styles.evidenceTop, children: [
      jsx('span', { style: styles.kicker, children: formatTime(event.timestamp_unix_ms) + ' · event ' + text(event.event_id) }),
      jsx(Badge, { variant: badgeVariantForSeverity(event.severity), children: labelFor(event.severity) }),
    ] }),
    jsx('div', { style: styles.evidenceTitle, children: titleText(event.title, 'Untitled event') }),
    jsxs('div', { style: styles.rowMeta, children: ['type ', text(event.event_type, 'unknown'), ' · trust ', labelFor(event.trust_level), ' · redaction count ', countText(event.redaction?.redacted_count)] }),
    jsxs('div', { style: styles.rowMeta, children: [
      'rule ', text(event.rule_id, 'none'),
      ' · sensor ', text(event.sensor?.kind), '/', text(event.sensor?.sensor), ' · integration ', text(event.sensor?.integration, 'none'),
      ' · artifact ', text(event.artifact?.kind), '/', text(event.artifact?.display_label), ' · provider ', text(event.artifact?.provider, 'none'), ' · trust ', labelFor(event.artifact?.trust_level),
    ] }),
    jsxs('div', { style: styles.badgeLine, children: [
      jsx(Badge, { variant: event.redaction?.contains_sensitive_data ? 'warn' : 'muted', children: event.redaction?.contains_sensitive_data ? 'contains redactions' : 'no redaction flag' }),
      ...(badges.length ? badges.map((badge) => jsx(Badge, { variant: badge.tone, children: badge.label + (badge.value === 'true' ? '' : ' · ' + badge.value) }, badge.label + badge.value)) : [jsx(Badge, { variant: 'muted', children: 'no allowlisted indicators' }, 'no-indicators')]),
    ] }),
  ] });
}

const styles = {
  shell: { minHeight: '100%', display: 'grid', alignContent: 'start', gap: '1rem', padding: '1rem', color: 'var(--ui-text-primary)', background: 'var(--ui-surface-background)' },
  header: { display: 'flex', justifyContent: 'space-between', gap: '1rem', alignItems: 'flex-start', flexWrap: 'wrap' },
  titleBlock: { display: 'grid', gap: '0.4rem', minWidth: 'min(28rem, 100%)' },
  eyebrowRow: { display: 'flex', gap: '0.4rem', flexWrap: 'wrap', alignItems: 'center' },
  heading: { margin: 0, color: 'var(--ui-text-primary)', fontSize: '1.35rem', lineHeight: 1.15, letterSpacing: '-0.02em' },
  detailTitle: { margin: 0, color: 'var(--ui-text-primary)', fontSize: '1.05rem', lineHeight: 1.25 },
  muted: { margin: 0, color: 'var(--ui-text-secondary)', lineHeight: 1.45 },
  tertiary: { color: 'var(--ui-text-tertiary)', fontSize: '0.72rem', lineHeight: 1.35 },
  metaGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(8.5rem, 1fr))', gap: '0.5rem' },
  metaCard: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: 'var(--radius-md, 0.375rem)', padding: '0.65rem', background: 'var(--ui-bg-card)', minWidth: 0 },
  kicker: { color: 'var(--ui-text-tertiary)', fontSize: '0.68rem', letterSpacing: '0.04em', textTransform: 'uppercase' },
  metaValue: { color: 'var(--ui-text-primary)', fontSize: '1.05rem', fontWeight: 650, lineHeight: 1.2, marginTop: '0.2rem' },
  filters: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(11rem, 1fr))', gap: '0.65rem', alignItems: 'end', border: '1px solid var(--ui-stroke-secondary)', borderRadius: 'var(--radius-lg, 0.5rem)', padding: '0.75rem', background: 'var(--ui-bg-editor)' },
  field: { minWidth: 0 },
  fieldBody: { display: 'grid', gap: '0.25rem', minWidth: 0 },
  label: { color: 'var(--ui-text-tertiary)', fontSize: '0.72rem' },
  select: { width: '100%', color: 'var(--ui-text-primary)', background: 'var(--ui-bg-input)', border: '1px solid var(--ui-stroke-primary)', borderRadius: 'var(--radius-md, 0.375rem)', padding: '0.42rem 0.5rem', minHeight: '2rem' },
  loading: { display: 'grid', gap: '0.5rem' },
  warning: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: 'var(--radius-md, 0.375rem)', padding: '0.65rem', color: 'var(--ui-text-primary)', background: 'var(--ui-bg-card)' },
  pager: { display: 'flex', gap: '0.45rem', flexWrap: 'wrap', alignItems: 'center', border: '1px solid var(--ui-stroke-secondary)', borderRadius: 'var(--radius-md, 0.375rem)', padding: '0.65rem', background: 'var(--ui-bg-card)' },
  visuallyHidden: { position: 'absolute', width: '1px', height: '1px', padding: 0, margin: '-1px', overflow: 'hidden', clip: 'rect(0, 0, 0, 0)', whiteSpace: 'nowrap', border: 0 },
  skeletonTall: { minHeight: '8rem', background: 'var(--ui-bg-card)' },
  skeletonShort: { minHeight: '3rem', background: 'var(--ui-bg-quaternary)' },
  workspace: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 24rem), 1fr))', gap: '0.85rem', alignItems: 'start', minHeight: 0 },
  panel: { minWidth: 0, border: '1px solid var(--ui-stroke-secondary)', borderRadius: 'var(--radius-lg, 0.5rem)', background: 'var(--ui-bg-elevated)', overflow: 'hidden' },
  list: { maxHeight: 'min(42rem, 62vh)' },
  listInner: { display: 'grid', gap: 0, margin: 0, padding: 0, listStyle: 'none' },
  listItem: { margin: 0, padding: 0 },
  row: { display: 'grid', gap: '0.42rem', width: '100%', textAlign: 'left', padding: '0.78rem', color: 'var(--ui-text-primary)', background: 'var(--ui-control-hover-background)', border: 0, borderBottom: '1px solid var(--ui-stroke-secondary)' },
  rowSelected: { display: 'grid', gap: '0.42rem', width: '100%', textAlign: 'left', padding: '0.78rem', color: 'var(--ui-text-primary)', background: 'var(--ui-control-active-background)', border: 0, borderLeft: '3px solid var(--ui-base)', borderBottom: '1px solid var(--ui-stroke-primary)' },
  rowTop: { display: 'flex', justifyContent: 'space-between', gap: '0.65rem', alignItems: 'start' },
  rowTitle: { fontWeight: 650, lineHeight: 1.3 },
  badgeLine: { display: 'flex', gap: '0.35rem', flexWrap: 'wrap', alignItems: 'center' },
  rowMeta: { color: 'var(--ui-text-secondary)', fontSize: '0.74rem', lineHeight: 1.35 },
  detail: { minWidth: 0, display: 'grid', gap: '0.85rem', border: '1px solid var(--ui-stroke-secondary)', borderRadius: 'var(--radius-lg, 0.5rem)', padding: '0.95rem', background: 'var(--ui-bg-elevated)' },
  detailHeader: { display: 'grid', gap: '0.45rem' },
  summary: { margin: 0, color: 'var(--ui-text-secondary)', lineHeight: 1.5 },
  contextPanel: { display: 'grid', gap: '0.5rem', border: '1px solid var(--ui-stroke-secondary)', borderRadius: 'var(--radius-md, 0.375rem)', padding: '0.75rem', background: 'var(--ui-bg-card)' },
  provenanceGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14rem, 1fr))', gap: '0.7rem' },
  provenanceBlock: { display: 'grid', gap: '0.55rem', border: '1px solid var(--ui-stroke-secondary)', borderRadius: 'var(--radius-md, 0.375rem)', padding: '0.75rem', background: 'var(--ui-bg-editor)' },
  blockTitle: { margin: 0, color: 'var(--ui-text-primary)', fontSize: '0.82rem' },
  dl: { display: 'grid', gap: '0.38rem', margin: 0 },
  dlRow: { display: 'grid', gridTemplateColumns: 'minmax(6.5rem, 0.72fr) minmax(0, 1fr)', gap: '0.6rem' },
  dt: { color: 'var(--ui-text-tertiary)', fontSize: '0.72rem' },
  dd: { margin: 0, color: 'var(--ui-text-primary)', minWidth: 0, overflowWrap: 'anywhere' },
  evidencePanel: { display: 'grid', gap: '0.6rem' },
  evidenceList: { display: 'grid', gap: '0.55rem', margin: 0, padding: 0, listStyle: 'none' },
  evidenceItem: { display: 'grid', gap: '0.42rem', border: '1px solid var(--ui-stroke-secondary)', borderRadius: 'var(--radius-md, 0.375rem)', padding: '0.7rem', background: 'var(--ui-bg-card)' },
  evidenceTop: { display: 'flex', justifyContent: 'space-between', gap: '0.5rem', alignItems: 'center' },
  evidenceTitle: { color: 'var(--ui-text-primary)', fontWeight: 600 },
};

export const __desktopTest = {
  validateRiskPage,
  initialPageNavigationState,
  recordNextPage,
  recordPreviousPage,
  resetPageNavigation,
  riskDetailPath,
};

export default {
  id: 'skynet-edr',
  name: 'Skynet-EDR Risk Explorer',
  defaultEnabled: true,
  register(ctx) {
    ctx.registerMany([
      { id: 'page', area: ROUTES_AREA, data: { path: PAGE_PATH }, render: () => jsx(RiskExplorer, { ctx }) },
      { id: 'nav', area: SIDEBAR_NAV_AREA, data: { path: PAGE_PATH, label: 'Skynet-EDR', codicon: 'shield' } },
      { id: 'open-risks', area: PALETTE_AREA, data: { id: 'skynet-edr.open-risks', label: 'Open Skynet-EDR risks', keywords: ['security', 'risk', 'edr'], run: () => host.navigate('/skynet-edr/risks') } },
    ]);
  },
};