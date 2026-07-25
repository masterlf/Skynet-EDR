import React from 'react';
import { jsx, jsxs } from 'react/jsx-runtime';
import { definePlugin, useQuery } from '@hermes/plugin-sdk';

const POLL_MS = 10000;

function text(value, fallback = 'unknown') {
  if (value === null || value === undefined || value === '') return fallback;
  return String(value);
}

function RiskExplorer({ ctx }) {
  const [selectedId, setSelectedId] = React.useState(null);
  const risks = useQuery({
    queryKey: ['skynet-edr', 'risks'],
    queryFn: () => ctx.rest('/risks?limit=50&offset=0'),
    refetchInterval: 10000,
  });
  const detail = useQuery({
    queryKey: ['skynet-edr', 'risk', selectedId],
    queryFn: () => ctx.rest('/risks/' + encodeURIComponent(selectedId)),
    enabled: Boolean(selectedId),
    refetchInterval: POLL_MS,
  });
  const items = risks.data?.items || [];
  return jsxs('section', { 'aria-label': 'Skynet-EDR Risk Explorer', children: [
    jsxs('header', { children: [
      jsx('h2', { children: 'Skynet-EDR Risk Explorer' }),
      jsx('p', { children: 'Read-only current-page risk projection. Raw prompts, commands, URLs and paths are not rendered.' }),
      jsx('button', { type: 'button', onClick: () => risks.refetch(), children: 'Refresh' }),
    ] }),
    risks.isLoading ? jsx('p', { children: 'Loading risks…' }) : null,
    risks.error ? jsx('p', { role: 'alert', children: 'Unable to load risks from the read-only backend.' }) : null,
    !risks.isLoading && !items.length ? jsx('p', { children: 'No risks recorded.' }) : null,
    jsx('div', { role: 'list', children: items.map((risk) => jsx('button', {
      type: 'button',
      role: 'listitem',
      'aria-pressed': selectedId === risk.id,
      onClick: () => setSelectedId(risk.id),
      children: [
        text(risk.severity), ' · ', text(risk.status), ' · ', text(risk.title), ' · rule ',
        text(risk.rule_id, 'none'), ' · ', text(risk.sensor?.integration), ' · ',
        text(risk.artifact?.kind), ' / ', text(risk.artifact?.display_label), ' · events ',
        text(risk.event_count), ' · updated ', text(risk.last_observed_at_unix_ms),
      ],
    }, risk.id)) }),
    selectedId ? jsx(RiskDetail, { detail }) : null,
  ] });
}

function RiskDetail({ detail }) {
  if (detail.isLoading) return jsx('p', { children: 'Loading detail…' });
  if (detail.error) return jsx('p', { role: 'alert', children: 'Unable to load risk detail.' });
  const risk = detail.data;
  if (!risk) return null;
  const evidence = risk.evidence || [];
  return jsxs('article', { 'aria-label': 'Risk detail', children: [
    jsx('h3', { children: text(risk.title) }),
    jsx('p', { children: text(risk.summary) }),
    jsx('p', { children: ['Artifact: ', text(risk.artifact?.kind), ' / ', text(risk.artifact?.display_label)] }),
    jsx('p', { children: ['Sensor: ', text(risk.sensor?.kind), ' / ', text(risk.sensor?.sensor)] }),
    jsx('p', { children: ['Traces: ', (risk.trace_ids || []).join(', ') || 'none'] }),
    jsx('ul', { children: evidence.map((event) => jsx('li', { children: [
      text(event.timestamp_unix_ms), ' · ', text(event.severity), ' · ', text(event.event_type),
      ' · ', text(event.title), ' · redacted ', text(event.redaction?.redacted_count),
      ' · indicators ', JSON.stringify(event.indicators || {}),
    ] }, event.event_id)) }),
  ] });
}

export default definePlugin({
  id: 'skynet-edr',
  name: 'Skynet-EDR Risk Explorer',
  activate(ctx) {
    ctx.registerRoute('/skynet-edr/risks', () => jsx(RiskExplorer, { ctx }));
    ctx.registerSidebarItem({ id: 'skynet-edr', label: 'Skynet-EDR', route: '/skynet-edr/risks' });
    ctx.registerCommand({ id: 'skynet-edr.open-risks', title: 'Open Skynet-EDR risks', run: () => ctx.navigate('/skynet-edr/risks') });
  },
});
