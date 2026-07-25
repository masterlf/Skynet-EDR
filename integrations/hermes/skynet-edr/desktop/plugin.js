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

function pageMeta(data) {
  return data?.page || { returned: 0, total: 0, limit: 50, offset: 0, has_more: false };
}

function backendState(status, risks) {
  if (status.isLoading || risks.isLoading) return 'Backend health: checking read-only loopback';
  if (status.error || risks.error) return 'Backend health: unavailable or invalid response';
  if (status.data?.read_only === true || risks.data?.read_only === true) return 'Backend health: passive read-only projection online';
  return 'Backend health: response received, read-only flag not asserted';
}

function RiskExplorer({ ctx }) {
  const [selectedId, setSelectedId] = React.useState(null);
  const [search, setSearch] = React.useState('');
  const [severity, setSeverity] = React.useState('all');
  const [status, setStatus] = React.useState('all');
  const [artifactKind, setArtifactKind] = React.useState('all');
  const risks = useQuery({
    queryKey: ['skynet-edr', 'risks'],
    queryFn: () => ctx.rest('/risks?limit=50&offset=0'),
    refetchInterval: POLL_MS,
  });
  const health = useQuery({
    queryKey: ['skynet-edr', 'status'],
    queryFn: () => ctx.rest('/status'),
    refetchInterval: POLL_MS,
  });
  const detail = useQuery({
    queryKey: ['skynet-edr', 'risk', selectedId],
    queryFn: () => ctx.rest('/risks/' + encodeURIComponent(selectedId)),
    enabled: Boolean(selectedId),
    refetchInterval: POLL_MS,
  });
  const pageItems = Array.isArray(risks.data?.items) ? risks.data.items : [];
  const items = risks.isLoading || risks.error ? [] : filterRisks(pageItems, { search, severity, status, artifactKind });
  const meta = pageMeta(risks.data);
  const hasPageRisks = pageItems.length > 0;
  const noFilterMatch = hasPageRisks && !items.length;
  const isFetching = risks.isFetching || health.isFetching;
  return jsxs('section', { 'aria-label': 'Skynet-EDR Risk Explorer', style: styles.shell, children: [
    jsxs('header', { style: styles.header, children: [
      jsxs('div', { style: styles.titleBlock, children: [
        jsxs('div', { style: styles.eyebrowRow, children: [
          jsx(Badge, { variant: 'outline', children: 'Passive · Read only' }),
          jsx(Badge, { variant: health.error || risks.error ? 'destructive' : 'muted', children: backendState(health, risks) }),
        ] }),
        jsx('h2', { style: styles.heading, children: 'Skynet-EDR Risk Explorer' }),
        jsx('p', { style: styles.muted, children: 'Current page risk triage from redacted skynet.risk.v1 projections. Raw prompts, commands, destinations and local paths are not rendered.' }),
      ] }),
      jsx(Button, { type: 'button', variant: 'outline', onClick: () => { risks.refetch(); health.refetch(); }, disabled: isFetching, children: isFetching ? 'Refreshing…' : 'Refresh' }),
    ] }),
    jsx(PageMetadata, { meta, loadedCount: pageItems.length, visibleCount: items.length }),
    jsx(Filters, { search, setSearch, severity, setSeverity, status, setStatus, artifactKind, setArtifactKind }),
    risks.isLoading ? jsx(LoadingState, {}) : null,
    !risks.isLoading && risks.error ? jsx(ErrorState, { title: 'Unable to load risks', description: 'The read-only backend did not return a valid risk page.' }) : null,
    !risks.isLoading && !risks.error && !hasPageRisks ? jsx(EmptyState, { title: 'No risks recorded', description: 'The loaded current page contains no risk projections.' }) : null,
    !risks.isLoading && !risks.error && noFilterMatch ? jsx(EmptyState, { title: 'No current-page matches', description: 'The current page has risks, but none match the active filters or search.' }) : null,
    !risks.isLoading && !risks.error && items.length ? jsxs('div', { style: styles.workspace, children: [
      jsx(RiskList, { items, selectedId, setSelectedId }),
      selectedId ? jsx(RiskDetail, { detail }) : jsx(EmptyState, { title: 'Select a risk', description: 'Open an item to inspect read-only context, provenance, traces and bounded evidence.' }),
    ] }) : null,
  ] });
}

function PageMetadata({ meta, loadedCount, visibleCount }) {
  return jsxs('aside', { 'aria-label': 'Page metadata', style: styles.metaGrid, children: [
    jsx(MetaCard, { label: 'Current page returned', value: countText(meta.returned), note: 'API returned count' }),
    jsx(MetaCard, { label: 'Current page visible', value: countText(visibleCount), note: 'after current-page filters' }),
    jsx(MetaCard, { label: 'Current page loaded', value: countText(loadedCount), note: 'items available locally' }),
    jsx(MetaCard, { label: 'Total reported by API', value: countText(meta.total), note: 'server-reported total' }),
    jsx(MetaCard, { label: 'Limit / offset', value: countText(meta.limit) + ' / ' + countText(meta.offset), note: 'pagination metadata' }),
    jsx(MetaCard, { label: 'Has more', value: meta.has_more ? 'yes' : 'no', note: 'no local page control' }),
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
    jsx('label', { style: styles.field, children: jsxs('span', { style: styles.fieldBody, children: [
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
  return jsxs('div', { style: styles.loading, children: [
    jsx(Skeleton, { style: styles.skeletonTall }),
    jsx(Skeleton, { style: styles.skeletonShort }),
  ] });
}

function RiskList({ items, selectedId, setSelectedId }) {
  return jsx('section', { 'aria-label': 'Current page risk list', style: styles.panel, children: jsx(ScrollArea, { style: styles.list, children: jsx('div', { role: 'list', style: styles.listInner, children: items.map((risk) => jsx(RiskRow, { risk, selected: selectedId === risk.id, onSelect: () => setSelectedId(risk.id) }, risk.id)) }) }) });
}

function RiskRow({ risk, selected, onSelect }) {
  return jsxs('button', { type: 'button', role: 'listitem', 'aria-pressed': selected, onClick: onSelect, style: selected ? styles.rowSelected : styles.row, children: [
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
  ] });
}

function RiskDetail({ detail }) {
  if (detail.isLoading) return jsx('section', { 'aria-label': 'Risk detail loading', style: styles.detail, children: jsx(Skeleton, { style: styles.skeletonTall }) });
  if (detail.error) return jsx('section', { 'aria-label': 'Risk detail error', style: styles.detail, children: jsx(ErrorState, { title: 'Unable to load risk detail', description: 'The read-only backend returned an error for this risk.' }) });
  const risk = detail.data;
  if (!risk) return null;
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
      jsxs('div', { style: styles.badgeLine, children: [
        jsx(Badge, { variant: 'outline', children: 'confidence ' + (risk.confidence === null || risk.confidence === undefined ? 'Not assessed' : text(risk.confidence)) }),
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
        ['Locator digest', risk.artifact?.locator_hash ? 'sha256 digest present' : 'none'],
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
      jsx('span', { style: styles.kicker, children: formatTime(event.timestamp_unix_ms) }),
      jsx(Badge, { variant: badgeVariantForSeverity(event.severity), children: labelFor(event.severity) }),
    ] }),
    jsx('div', { style: styles.evidenceTitle, children: titleText(event.title, 'Untitled event') }),
    jsxs('div', { style: styles.rowMeta, children: ['type ', text(event.event_type, 'unknown'), ' · trust ', labelFor(event.trust_level), ' · redaction count ', countText(event.redaction?.redacted_count)] }),
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
  skeletonTall: { minHeight: '8rem', background: 'var(--ui-bg-card)' },
  skeletonShort: { minHeight: '3rem', background: 'var(--ui-bg-quaternary)' },
  workspace: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 24rem), 1fr))', gap: '0.85rem', alignItems: 'start', minHeight: 0 },
  panel: { minWidth: 0, border: '1px solid var(--ui-stroke-secondary)', borderRadius: 'var(--radius-lg, 0.5rem)', background: 'var(--ui-bg-elevated)', overflow: 'hidden' },
  list: { maxHeight: 'min(42rem, 62vh)' },
  listInner: { display: 'grid' },
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