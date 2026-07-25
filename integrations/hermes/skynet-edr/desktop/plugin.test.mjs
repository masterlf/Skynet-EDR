import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

function loadDesktopTestApi() {
  let source = readFileSync(new URL('./plugin.js', import.meta.url), 'utf8');
  source = source.replace(/^import React from 'react';\n/, "const React = { useState(initial) { return [initial, () => {}]; } };\n");
  source = source.replace(/^import \{[\s\S]*?\} from '@hermes\/plugin-sdk';\n/m, "const jsx = (...args) => ({ jsx: args }); const jsxs = jsx; const Badge = Button = EmptyState = ErrorState = ScrollArea = SearchField = Skeleton = function Stub() {}; const PALETTE_AREA = ROUTES_AREA = SIDEBAR_NAV_AREA = 'area'; const fmtDateTime = (value) => String(value); const host = { navigate() {} }; const useQuery = () => ({});\n");
  source = source.replace(/export default \{[\s\S]*?\n\};\s*$/m, '');
  source = source.replace(/export const __desktopTest = /, 'globalThis.__desktopTest = ');
  const context = { globalThis: {}, console };
  vm.createContext(context);
  vm.runInContext(source, context, { filename: 'plugin.js' });
  assert.ok(context.globalThis.__desktopTest, '__desktopTest API must be exported');
  return context.globalThis.__desktopTest;
}

function risk(id = 'inc-test') {
  return {
    id,
    severity: 'high',
    confidence: null,
    status: 'open',
    rule_id: 'EDR-MCP-001',
    title: 'MCP network activity after untrusted content',
    summary: 'Read-only projection of 1 redacted evidence event. Review sensor and artifact provenance plus allowlisted indicators.',
    sensor: { kind: 'mcp_tool', sensor: 'sensor-test', integration: 'hermes' },
    artifact: { kind: 'mcp', provider: null, display_label: 'MCP content', locator_hash: null, trust_level: 'tool_output' },
    first_observed_at_unix_ms: 1,
    last_observed_at_unix_ms: 2,
    event_count: 1,
    trace_ids: [],
    contains_sensitive_data: false,
  };
}

function page({ offset = 0, returned = 1, total = 2, has_more = true } = {}) {
  return {
    schema_version: 'skynet.risk.v1',
    read_only: true,
    items: Array.from({ length: returned }, (_, index) => risk(`inc-${offset}-${index}`)),
    page: { limit: 50, offset, returned, total, has_more },
  };
}

test('validateRiskPage accepts coherent partial non-terminal page and rejects zero-progress has_more', () => {
  const api = loadDesktopTestApi();
  assert.equal(api.validateRiskPage(page({ offset: 50, returned: 1, total: 100, has_more: true }), 50).page.returned, 1);
  assert.throws(() => api.validateRiskPage(page({ offset: 50, returned: 0, total: 100, has_more: true }), 50), /Invalid read-only risk projection/);
});

test('page history returns to exact pre-next offset after partial page and handles normal 50-row navigation', () => {
  const api = loadDesktopTestApi();
  let state = api.initialPageNavigationState();
  state = api.recordNextPage(state, { offset: 50, returned: 1, has_more: true });
  assert.equal(state.offset, 51);
  state = api.recordPreviousPage(state);
  assert.equal(state.offset, 50);

  state = api.initialPageNavigationState();
  state = api.recordNextPage(state, { offset: 0, returned: 50, has_more: true });
  assert.equal(state.offset, 50);
  state = api.recordPreviousPage(state);
  assert.equal(state.offset, 0);

  state = api.initialPageNavigationState();
  for (let offset = 0; offset < 70; offset += 1) {
    state = api.recordNextPage(state, { offset, returned: 1, has_more: true });
  }
  for (let expected = 69; expected >= 0; expected -= 1) {
    state = api.recordPreviousPage(state);
    assert.equal(state.offset, expected);
  }
});

test('filter reset clears page history and risk detail path only accepts routable ids', () => {
  const api = loadDesktopTestApi();
  let state = api.recordNextPage(api.initialPageNavigationState(), { offset: 50, returned: 1, has_more: true });
  state = api.resetPageNavigation(state);
  assert.deepEqual(state, api.initialPageNavigationState());
  assert.throws(() => api.riskDetailPath('.'), /Invalid read-only risk projection/);
  assert.throws(() => api.riskDetailPath('..'), /Invalid read-only risk projection/);
  assert.equal(api.riskDetailPath('a/b c'), '/risks/a%2Fb%20c');
});

test('validateRiskPage fails closed on raw dot ids but preserves WHATWG-routable opaque ids', () => {
  const api = loadDesktopTestApi();
  assert.throws(() => api.validateRiskPage({ ...page(), items: [risk('.')] }, 0), /Invalid read-only risk projection/);
  assert.throws(() => api.validateRiskPage({ ...page(), items: [risk('..')] }, 0), /Invalid read-only risk projection/);
  assert.equal(api.validateRiskPage({ ...page(), items: [risk('inc/../secret')] }, 0).items[0].id, 'inc/../secret');
  assert.notEqual(new URL('/risks/%2E', 'https://example.invalid/base').pathname, '/risks/%2E');
});
