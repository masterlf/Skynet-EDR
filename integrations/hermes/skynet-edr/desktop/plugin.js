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

function text(value, fallback = 'unknown') {
  if (value === null || value === undefined || value === '') return fallback;
  return String(value);
}

function option(value, label) {
  return jsx('option', { value, children: label });
}

function matchesFilter(value, selected) {
  return selected === 'all' || text(value).toLowerCase() === selected;
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
  const detail = useQuery({
    queryKey: ['skynet-edr', 'risk', selectedId],
    queryFn: () => ctx.rest('/risks/' + encodeURIComponent(selectedId)),
    enabled: Boolean(selectedId),
    refetchInterval: POLL_MS,
  });
  const query = search.trim().toLowerCase();
  const items = (risks.data?.items || []).filter((risk) => {
    const haystack = [risk.id, risk.title, risk.summary, risk.rule_id, risk.sensor?.sensor, risk.sensor?.integration, risk.artifact?.kind].map(text).join(' ').toLowerCase();
    return (!query || haystack.includes(query))
      && matchesFilter(risk.severity, severity)
      && matchesFilter(risk.status, status)
      && matchesFilter(risk.artifact?.kind, artifactKind);
  });
  return jsxs('section', { 'aria-label': 'Skynet-EDR Risk Explorer', style: styles.shell, children: [
    jsxs('header', { style: styles.header, children: [
      jsxs('div', { children: [
        jsx('h2', { style: styles.heading, children: 'Skynet-EDR Risk Explorer' }),
        jsx('p', { style: styles.muted, children: 'Read-only current-page risk projection. Raw prompts, commands, URLs and paths are not rendered.' }),
      ] }),
      jsx(Button, { type: 'button', onClick: () => risks.refetch(), children: 'Refresh' }),
    ] }),
    jsxs('div', { style: styles.filters, children: [
      jsx(SearchField, { value: search, onChange: setSearch, placeholder: 'Search current page' }),
      jsxs('select', { value: severity, onChange: (event) => setSeverity(event.target.value), style: styles.select, children: [option('all', 'All severities'), option('critical', 'Critical'), option('high', 'High'), option('medium', 'Medium'), option('low', 'Low'), option('informational', 'Informational')] }),
      jsxs('select', { value: status, onChange: (event) => setStatus(event.target.value), style: styles.select, children: [option('all', 'All statuses'), option('open', 'Open'), option('closed', 'Closed')] }),
      jsxs('select', { value: artifactKind, onChange: (event) => setArtifactKind(event.target.value), style: styles.select, children: [option('all', 'All artifacts'), option('url', 'URL'), option('file', 'File'), option('terminal', 'Terminal'), option('mcp', 'MCP'), option('unknown', 'Unknown')] }),
    ] }),
    risks.isLoading ? jsx(Skeleton, { style: styles.skeleton }) : null,
    risks.error ? jsx(ErrorState, { title: 'Unable to load risks', description: 'The read-only backend did not return a valid risk page.' }) : null,
    !risks.isLoading && !items.length ? jsx(EmptyState, { title: 'No risks recorded', description: 'No current-page risk projection matched these filters.' }) : null,
    jsx(ScrollArea, { style: styles.list, children: jsx('div', { role: 'list', children: items.map((risk) => jsx(RiskRow, { risk, selected: selectedId === risk.id, onSelect: () => setSelectedId(risk.id) }, risk.id)) }) }),
    selectedId ? jsx(RiskDetail, { detail }) : null,
  ] });
}

function RiskRow({ risk, selected, onSelect }) {
  return jsxs('button', { type: 'button', role: 'listitem', 'aria-pressed': selected, onClick: onSelect, style: selected ? styles.rowSelected : styles.row, children: [
    jsxs('span', { style: styles.rowTitle, children: [text(risk.title), ' ', jsx(Badge, { children: text(risk.severity) })] }),
    jsxs('span', { style: styles.muted, children: [text(risk.status), ' · rule ', text(risk.rule_id, 'none'), ' · ', text(risk.sensor?.integration), ' · ', text(risk.artifact?.display_label), ' · events ', text(risk.event_count), ' · updated ', formatTime(risk.last_observed_at_unix_ms)] }),
  ] });
}

function RiskDetail({ detail }) {
  if (detail.isLoading) return jsx(Skeleton, { style: styles.skeleton });
  if (detail.error) return jsx(ErrorState, { title: 'Unable to load risk detail', description: 'The read-only backend returned an error for this risk.' });
  const risk = detail.data;
  if (!risk) return null;
  const evidence = risk.evidence || [];
  return jsxs('article', { 'aria-label': 'Risk detail', style: styles.detail, children: [
    jsx('h3', { style: styles.heading, children: text(risk.title) }),
    jsx('p', { style: styles.muted, children: text(risk.summary) }),
    jsxs('p', { children: ['Artifact: ', text(risk.artifact?.kind), ' / ', text(risk.artifact?.display_label)] }),
    jsxs('p', { children: ['Sensor: ', text(risk.sensor?.kind), ' / ', text(risk.sensor?.sensor)] }),
    jsxs('p', { children: ['Traces: ', (risk.trace_ids || []).join(', ') || 'none'] }),
    jsx('ul', { style: styles.evidence, children: evidence.map((event) => jsx('li', { children: jsxs('span', { children: [
      formatTime(event.timestamp_unix_ms), ' · ', text(event.severity), ' · ', text(event.event_type), ' · ', text(event.title), ' · redacted ', text(event.redaction?.redacted_count), ' · indicators ', JSON.stringify(event.indicators || {}),
    ] }) }, event.event_id)) }),
  ] });
}

function formatTime(value) {
  if (typeof value !== 'number') return 'unknown';
  return fmtDateTime(value);
}

const styles = {
  shell: { display: 'grid', gap: 'var(--space-3, 0.75rem)', padding: 'var(--space-4, 1rem)', color: 'var(--ui-text)' },
  header: { display: 'flex', justifyContent: 'space-between', gap: 'var(--space-3, 0.75rem)', alignItems: 'flex-start' },
  heading: { margin: 0 },
  muted: { color: 'var(--ui-text-secondary)' },
  filters: { display: 'grid', gridTemplateColumns: 'minmax(12rem, 1fr) repeat(3, minmax(8rem, 10rem))', gap: 'var(--space-2, 0.5rem)' },
  select: { color: 'var(--ui-text)', background: 'var(--ui-surface)', border: '1px solid var(--ui-stroke-secondary)', borderRadius: 'var(--radius-md, 0.375rem)', padding: '0.4rem' },
  skeleton: { minHeight: '4rem' },
  list: { maxHeight: '22rem', border: '1px solid var(--ui-stroke-secondary)', borderRadius: 'var(--radius-md, 0.375rem)' },
  row: { display: 'grid', gap: '0.25rem', width: '100%', textAlign: 'left', padding: '0.75rem', color: 'var(--ui-text)', background: 'transparent', border: 0, borderBottom: '1px solid var(--ui-stroke-secondary)' },
  rowSelected: { display: 'grid', gap: '0.25rem', width: '100%', textAlign: 'left', padding: '0.75rem', color: 'var(--ui-text)', background: 'var(--ui-accent-soft)', border: 0, borderBottom: '1px solid var(--ui-stroke-secondary)' },
  rowTitle: { display: 'flex', justifyContent: 'space-between', gap: 'var(--space-2, 0.5rem)' },
  detail: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: 'var(--radius-md, 0.375rem)', padding: 'var(--space-3, 0.75rem)' },
  evidence: { display: 'grid', gap: '0.5rem' },
};

export default {
  id: 'skynet-edr',
  name: 'Skynet-EDR Risk Explorer',
  defaultEnabled: true,
  register(ctx) {
    ctx.registerMany([
      { id: 'page', area: ROUTES_AREA, data: { path: PAGE_PATH }, render: () => jsx(RiskExplorer, { ctx }) },
      { id: 'nav', area: SIDEBAR_NAV_AREA, data: { path: PAGE_PATH, label: 'Skynet-EDR', codicon: 'shield' } },
      { id: 'open-risks', area: PALETTE_AREA, data: { title: 'Open Skynet-EDR risks', keywords: ['security', 'risk', 'edr'] }, run: () => host.navigate('/skynet-edr/risks') },
    ]);
  },
};
