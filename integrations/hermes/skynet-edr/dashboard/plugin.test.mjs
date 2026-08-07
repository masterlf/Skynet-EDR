import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const pluginUrl = new URL('./plugin.js', import.meta.url);
const manifestUrl = new URL('./manifest.json', import.meta.url);
const source = readFileSync(pluginUrl, 'utf8');

function canonicalRisk(id = 'risk-1') {
  return {
    id,
    severity: 'high',
    confidence: null,
    status: 'open',
    rule_id: 'EDR-MCP-001',
    title: 'MCP network activity after untrusted content',
    summary: 'Read-only projection of 1 redacted evidence event. Review sensor and artifact provenance plus allowlisted indicators.',
    sensor: { kind: 'mcp_tool', sensor: 'hermes', integration: 'hermes' },
    artifact: { kind: 'mcp', provider: null, display_label: 'MCP content', locator_hash: null, trust_level: 'tool_output' },
    first_observed_at_unix_ms: 1,
    last_observed_at_unix_ms: 2,
    event_count: 1,
    trace_ids: ['trace-1'],
    contains_sensitive_data: false,
  };
}

function canonicalPage({ items = [canonicalRisk()], offset = 0, total = items.length, hasMore = false } = {}) {
  return {
    schema_version: 'skynet.risk.v1',
    read_only: true,
    items,
    page: { limit: 50, offset, returned: items.length, total, has_more: hasMore },
  };
}

function canonicalDetail(id = 'risk-1') {
  return {
    ...canonicalRisk(id),
    schema_version: 'skynet.risk.v1',
    read_only: true,
    evidence: [{
      event_id: 'evt-1',
      timestamp_unix_ms: 2,
      severity: 'high',
      event_type: 'agent.mcp.tool.requested',
      title: 'MCP tool request evidence',
      sensor: { kind: 'mcp_tool', sensor: 'hermes', integration: 'hermes' },
      artifact: { kind: 'mcp', provider: null, display_label: 'MCP content', locator_hash: null, trust_level: 'tool_output' },
      trust_level: 'tool_output',
      rule_id: 'EDR-MCP-001',
      redaction: { contains_sensitive_data: false, redacted_count: 0 },
      indicators: { network_indicator: true, command_class: 'network_egress' },
    }],
  };
}

const canonicalStatus = {
  product: 'Skynet-EDR',
  binary: 'skynet-edr',
  version: '0.5.0',
  run_mode: 'passive',
  server: 'skynet-edr-mcp',
  read_only: true,
  tool_count: 6,
  incident_count: 1,
  event_count: 1,
};

const canonicalRules = {
  schema_version: 'skynet.rules.v1',
  read_only: true,
  compiled_active: true,
  items: [{
    id: 'EDR-MALWARE-001',
    name: 'Malware-like content sent to AI runtime',
    severity: 'high',
    source_kinds: ['process', 'messaging', 'file', 'network', 'mcp_tool'],
    description: 'Detects allowlisted safe malware-test indicators in omitted Hermes tool output.',
    read_only: true,
    compiled_active: true,
  }],
};

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function createHarness(plans = {}) {
  const stateSlots = [];
  const hookSlots = [];
  const pendingEffects = [];
  const intervals = [];
  const calls = [];
  const registrations = [];
  const listeners = new Map();
  let hookIndex = 0;
  let component;

  function sameDeps(left, right) {
    return Array.isArray(left) && Array.isArray(right)
      && left.length === right.length
      && left.every((value, index) => Object.is(value, right[index]));
  }

  const hooks = {
    useState(initial) {
      const index = hookIndex++;
      if (!(index in stateSlots)) stateSlots[index] = typeof initial === 'function' ? initial() : initial;
      return [stateSlots[index], (next) => {
        stateSlots[index] = typeof next === 'function' ? next(stateSlots[index]) : next;
      }];
    },
    useEffect(effect, deps) {
      const index = hookIndex++;
      const previous = hookSlots[index];
      if (!previous || !sameDeps(previous.deps, deps)) {
        pendingEffects.push({ index, effect, deps });
      }
    },
    useCallback(callback, deps) {
      const index = hookIndex++;
      const previous = hookSlots[index];
      if (previous && sameDeps(previous.deps, deps)) return previous.value;
      hookSlots[index] = { deps, value: callback };
      return callback;
    },
    useMemo(factory, deps) {
      const index = hookIndex++;
      const previous = hookSlots[index];
      if (previous && sameDeps(previous.deps, deps)) return previous.value;
      const value = factory();
      hookSlots[index] = { deps, value };
      return value;
    },
    useRef(initial) {
      const index = hookIndex++;
      if (!hookSlots[index]) hookSlots[index] = { value: { current: initial } };
      return hookSlots[index].value;
    },
    useContext() { hookIndex += 1; return null; },
    createContext(value) { return { value }; },
  };

  const React = {
    createElement(type, props, ...children) {
      const merged = { ...(props || {}), children: children.length <= 1 ? children[0] : children };
      if (typeof type === 'function') return type(merged);
      return { type, props: merged };
    },
  };
  const components = {};
  for (const name of ['Card', 'CardHeader', 'CardTitle', 'CardContent', 'Input', 'Label', 'Select', 'SelectOption', 'Separator', 'Tabs', 'TabsList', 'TabsTrigger']) {
    components[name] = name;
  }
  components.Badge = function Badge(props) {
    assert.equal(Object.hasOwn(props, 'variant'), false, 'Badge does not support variant');
    assert.ok(['default', 'destructive', 'outline', 'secondary', 'success', 'warning'].includes(props.tone || 'default'), `unsupported Badge tone: ${props.tone}`);
    return { type: 'Badge', props };
  };
  components.Button = function Button(props) {
    assert.equal(Object.hasOwn(props, 'variant'), false, 'Button does not support variant');
    for (const name of ['ghost', 'outlined', 'destructive', 'invert']) {
      assert.ok(props[name] === undefined || typeof props[name] === 'boolean', `Button ${name} must be boolean`);
    }
    return { type: 'Button', props };
  };

  async function materialize(next) {
    if (next instanceof Error) throw next;
    const value = await (typeof next === 'function' ? next() : next);
    return structuredClone(value);
  }

  async function fetchJSON(...args) {
    calls.push(args);
    const path = args[0];
    const plan = plans[path];
    if (Array.isArray(plan)) {
      if (plan.length === 0) throw new Error('no response');
      return materialize(plan.shift());
    }
    if (plan === undefined) throw new Error('no response');
    return materialize(plan);
  }

  const context = {
    console,
    Promise,
    setInterval(callback, delay) {
      const record = { callback, delay, active: true };
      intervals.push(record);
      return record;
    },
    clearInterval(record) { if (record) record.active = false; },
    document: {
      addEventListener(type, callback) { listeners.set(type, callback); },
      removeEventListener(type, callback) { if (listeners.get(type) === callback) listeners.delete(type); },
      contains(node) { return Boolean(node && node.visible !== false); },
    },
    window: {
      __HERMES_PLUGIN_SDK__: { React, hooks, components, fetchJSON },
      __HERMES_PLUGINS__: {
        register(name, registeredComponent) {
          registrations.push([name, registeredComponent]);
          component = registeredComponent;
        },
      },
    },
  };
  vm.createContext(context);
  vm.runInContext(source, context, { filename: 'dashboard/plugin.js' });

  function render() {
    hookIndex = 0;
    pendingEffects.length = 0;
    assert.equal(typeof component, 'function');
    return component();
  }

  async function flushEffects() {
    const effects = pendingEffects.splice(0);
    for (const item of effects) {
      const previous = hookSlots[item.index];
      if (previous && typeof previous.cleanup === 'function') previous.cleanup();
      const cleanup = item.effect();
      hookSlots[item.index] = { deps: item.deps, cleanup };
    }
    await new Promise((resolve) => setImmediate(resolve));
    await Promise.resolve();
  }

  async function runInterval(index = 0) {
    const live = intervals.filter((record) => record.active);
    assert.ok(live[index], `missing active interval ${index}`);
    await live[index].callback();
    await new Promise((resolve) => setImmediate(resolve));
  }

  function dispatchDocument(type, event) {
    const listener = listeners.get(type);
    assert.equal(typeof listener, 'function', `missing document listener: ${type}`);
    listener(event);
  }

  return { calls, registrations, intervals, render, flushEffects, runInterval, dispatchDocument };
}

function childrenOf(node) {
  if (!node || typeof node !== 'object') return [];
  const children = node.props?.children;
  return Array.isArray(children) ? children : children === undefined || children === null ? [] : [children];
}

function walk(node, visit) {
  if (node === null || node === undefined || typeof node === 'boolean') return;
  if (Array.isArray(node)) return node.forEach((entry) => walk(entry, visit));
  if (typeof node !== 'object') return;
  visit(node);
  childrenOf(node).forEach((child) => walk(child, visit));
}

function textOf(node) {
  if (node === null || node === undefined || typeof node === 'boolean') return '';
  if (Array.isArray(node)) return node.map(textOf).join(' ');
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  return childrenOf(node).map(textOf).join(' ');
}

function findButton(node, label) {
  let result;
  walk(node, (entry) => {
    if (!result && (entry.type === 'button' || entry.type === 'Button') && textOf(entry).includes(label)) result = entry;
  });
  assert.ok(result, `button not found: ${label}\n${textOf(node)}`);
  return result;
}

function findNode(node, predicate, description) {
  let result;
  walk(node, (entry) => {
    if (!result && predicate(entry)) result = entry;
  });
  assert.ok(result, `node not found: ${description}\n${textOf(node)}`);
  return result;
}

test('manifest exposes the exact visible route and sha384-pins the IIFE', () => {
  const manifest = JSON.parse(readFileSync(manifestUrl, 'utf8'));
  const expected = `sha384-${createHash('sha384').update(source).digest('base64')}`;
  assert.equal(manifest.name, 'skynet-edr');
  assert.equal(manifest.label, 'Skynet-EDR');
  assert.equal(manifest.icon, 'Shield');
  assert.deepEqual(manifest.tab, { path: '/skynet-edr/risks', position: 'after:logs', hidden: false });
  assert.equal(manifest.entry, 'plugin.js');
  assert.equal(manifest.api, 'plugin_api.py');
  assert.equal(manifest.integrity, expected);
});

test('IIFE registers exactly skynet-edr and only uses authenticated scoped JSON GETs', async () => {
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
  });
  assert.equal(harness.registrations.length, 1);
  assert.equal(harness.registrations[0][0], 'skynet-edr');
  harness.render();
  await harness.flushEffects();
  assert.ok(harness.calls.length >= 2);
  for (const args of harness.calls) {
    assert.equal(args.length, 1, 'fetchJSON must not receive method/options');
    assert.match(args[0], /^\/api\/plugins\/skynet-edr\/(?:status|rules|risks(?:\?limit=50&offset=\d+|\/[A-Za-z0-9%._~-]+)?)$/);
  }
  assert.ok(harness.intervals.some(({ delay }) => delay === 10000), '10s polling must be installed');
  for (const forbidden of ['innerHTML', 'dangerouslySetInnerHTML', 'XMLHttpRequest', 'WebSocket(', 'href:', 'src:', 'markdown', 'fetch(']) {
    assert.equal(source.includes(forbidden), false, `forbidden rendering/network sink: ${forbidden}`);
  }
  for (const mutation of ['POST', 'PUT', 'PATCH', 'DELETE']) assert.equal(source.includes(mutation), false);
});

test('status validator accepts bounded runtime health and rejects hostile attribution', async () => {
  const valid = structuredClone(canonicalStatus);
  valid.ingestion = {
    state: 'healthy', role_identity_assurance: 'authorized_uid_self_reported', listener_live: true, transport_heartbeat_state: 'fresh',
    hook_event_state: 'not_observed', hook_event_freshness_affects_state: false,
    last_event_received_at_unix_ms: null, last_event_received_age_ms: null,
    last_event_committed_at_unix_ms: null, last_event_committed_age_ms: null,
    required_reported_roles: [{ runtime_role: 'gateway', state: 'fresh' }],
    sources: [{
      source_id: 'uid:1000:gateway:gate-a1', authenticated_uid: 1000,
      runtime_role: 'gateway', instance_id: 'gate-a1', producer_reported_at_unix_ms: 1,
      producer_report_age_ms: 0, transport_state: 'available', backlog_bytes: 0,
      last_error_category: null, last_error_at_unix_ms: null, last_error_age_ms: null,
    }],
  };
  let harness = createHarness({
    '/api/plugins/skynet-edr/status': valid,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
  });
  harness.render();
  await harness.flushEffects();
  const healthyText = textOf(harness.render());
  assert.match(healthyText, /Passive projection online/);
  assert.match(healthyText, /Telemetry healthy/);
  assert.match(healthyText, /Listener live/);
  assert.match(healthyText, /Required reported roles gateway: fresh/);
  assert.match(healthyText, /Authorized-UID self-reported attribution/);

  const hostile = structuredClone(valid);
  hostile.ingestion.sources[0].instance_id = '/proc/self/cmdline';
  harness = createHarness({
    '/api/plugins/skynet-edr/status': hostile,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
  });
  harness.render();
  await harness.flushEffects();
  assert.match(textOf(harness.render()), /Backend unavailable/);
  assert.doesNotMatch(textOf(harness.render()), /cmdline/);
});

test('status validator rejects contradictory healthy ingestion objects', async () => {
  const base = structuredClone(canonicalStatus);
  base.ingestion = {
    state: 'healthy', role_identity_assurance: 'authorized_uid_self_reported',
    listener_live: true, transport_heartbeat_state: 'fresh',
    hook_event_state: 'not_observed', hook_event_freshness_affects_state: false,
    last_event_received_at_unix_ms: null, last_event_received_age_ms: null,
    last_event_committed_at_unix_ms: null, last_event_committed_age_ms: null,
    required_reported_roles: [{ runtime_role: 'gateway', state: 'fresh' }],
    sources: [{
      source_id: 'uid:1000:gateway:gate-a1', authenticated_uid: 1000,
      runtime_role: 'gateway', instance_id: 'gate-a1', producer_reported_at_unix_ms: 1,
      producer_report_age_ms: 0, transport_state: 'available', backlog_bytes: 0,
      last_error_category: null, last_error_at_unix_ms: null, last_error_age_ms: null,
    }],
  };
  const contradictions = [
    (value) => { value.ingestion.listener_live = false; },
    (value) => { value.ingestion.transport_heartbeat_state = 'stale'; },
    (value) => { value.ingestion.required_reported_roles[0].state = 'absent'; },
    (value) => { value.ingestion.sources[0].transport_state = 'degraded'; },
    (value) => {
      value.ingestion.sources[0].last_error_category = 'storage';
      value.ingestion.sources[0].last_error_at_unix_ms = 1;
      value.ingestion.sources[0].last_error_age_ms = 0;
    },
    (value) => { value.ingestion.role_identity_assurance = 'attested'; },
  ];
  for (const contradict of contradictions) {
    const value = structuredClone(base);
    contradict(value);
    const harness = createHarness({
      '/api/plugins/skynet-edr/status': value,
      '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
    });
    harness.render();
    await harness.flushEffects();
    assert.match(textOf(harness.render()), /Backend unavailable/);
  }

  const degraded = structuredClone(base);
  degraded.ingestion.state = 'degraded';
  degraded.ingestion.listener_live = false;
  const degradedHarness = createHarness({
    '/api/plugins/skynet-edr/status': degraded,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
  });
  degradedHarness.render();
  await degradedHarness.flushEffects();
  assert.match(textOf(degradedHarness.render()), /Passive projection online/);
});

test('disabled ingestion schema is exact and visibly separate from backend availability', async () => {
  const disabled = structuredClone(canonicalStatus);
  disabled.ingestion = {
    state: 'disabled', role_identity_assurance: 'authorized_uid_self_reported',
    listener_live: false, sources: [],
  };
  let harness = createHarness({
    '/api/plugins/skynet-edr/status': disabled,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
  });
  harness.render();
  await harness.flushEffects();
  const text = textOf(harness.render());
  assert.match(text, /Passive projection online/);
  assert.match(text, /Telemetry disabled/);
  assert.match(text, /Listener stopped/);

  const extra = structuredClone(disabled);
  extra.ingestion.transport_heartbeat_state = 'not_observed';
  harness = createHarness({
    '/api/plugins/skynet-edr/status': extra,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
  });
  harness.render();
  await harness.flushEffects();
  assert.match(textOf(harness.render()), /Backend unavailable/);
});

test('renders loading, empty and generic fail-closed error states', async () => {
  let harness = createHarness({});
  let tree = harness.render();
  assert.match(textOf(tree), /Loading read-only risk projections/);

  harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage({ items: [], total: 0 }),
  });
  harness.render();
  await harness.flushEffects();
  tree = harness.render();
  assert.match(textOf(tree), /No risks recorded/);

  harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': { read_only: false, items: [{ title: '<script>hostile</script>' }] },
  });
  harness.render();
  await harness.flushEffects();
  tree = harness.render();
  assert.match(textOf(tree), /Unable to load risks/);
  assert.doesNotMatch(textOf(tree), /hostile|script/);
});

test('keeps validated rows visible as stale when a poll fails', async () => {
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': [canonicalStatus, canonicalStatus],
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': [canonicalPage(), new Error('private upstream detail')],
  });
  harness.render();
  await harness.flushEffects();
  let tree = harness.render();
  assert.match(textOf(tree), /MCP network activity/);
  const riskInterval = harness.intervals.find((record) => record.active && record.delay === 10000 && harness.intervals.indexOf(record) > 0) || harness.intervals[0];
  await riskInterval.callback();
  await new Promise((resolve) => setImmediate(resolve));
  tree = harness.render();
  assert.match(textOf(tree), /Stale data/);
  assert.match(textOf(tree), /MCP network activity/);
  assert.doesNotMatch(textOf(tree), /private upstream detail/);
});

test('renders source-aware list, detail provenance and evidence timeline as text', async () => {
  const risk = canonicalRisk('inc/opaque');
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage({ items: [risk] }),
    '/api/plugins/skynet-edr/risks/inc%2Fopaque': canonicalDetail('inc/opaque'),
  });
  harness.render();
  await harness.flushEffects();
  let tree = harness.render();
  assert.match(textOf(tree), /MCP content|MCP/);
  findButton(tree, 'MCP network activity').props.onClick();
  harness.render();
  await harness.flushEffects();
  tree = harness.render();
  const text = textOf(tree);
  assert.match(text, /Artifact provenance/);
  assert.match(text, /Sensor provenance/);
  assert.match(text, /Evidence timeline/);
  assert.match(text, /MCP tool request evidence/);
  assert.match(text, /Network/);
  assert.ok(harness.calls.some((args) => args[0] === '/api/plugins/skynet-edr/risks/inc%2Fopaque'));
});

test('risk rows expose expanded state and selected row click toggles detail closed', async () => {
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
    '/api/plugins/skynet-edr/risks/risk-1': canonicalDetail(),
  });
  harness.render();
  await harness.flushEffects();
  let tree = harness.render();
  let row = findButton(tree, 'MCP network activity');
  assert.equal(row.props['aria-expanded'], false);
  assert.equal(row.props['aria-controls'], undefined);

  row.props.onClick();
  harness.render();
  await harness.flushEffects();
  tree = harness.render();
  row = findButton(tree, 'MCP network activity');
  assert.equal(row.props['aria-expanded'], true);
  assert.equal(row.props['aria-controls'], 'skynet-risk-detail-panel');
  const panel = findNode(tree, (node) => node.props?.id === 'skynet-risk-detail-panel', 'risk detail panel');
  assert.equal(panel.props.role, 'region');
  assert.equal(panel.props['aria-labelledby'], 'skynet-risk-detail-heading');
  findNode(panel, (node) => node.props?.id === 'skynet-risk-detail-heading', 'risk detail heading');

  row.props.onClick();
  tree = harness.render();
  assert.doesNotMatch(textOf(tree), /Artifact provenance/);
  assert.equal(findButton(tree, 'MCP network activity').props['aria-expanded'], false);
  assert.equal(findButton(tree, 'MCP network activity').props['aria-controls'], undefined);
});

test('visible close detail button collapses detail and returns focus to selected row', async () => {
  let focusCount = 0;
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
    '/api/plugins/skynet-edr/risks/risk-1': canonicalDetail(),
  });
  harness.render();
  await harness.flushEffects();
  findButton(harness.render(), 'MCP network activity').props.onClick();
  harness.render();
  await harness.flushEffects();
  let tree = harness.render();
  const row = findButton(tree, 'MCP network activity');
  row.props.ref({ focus() { focusCount += 1; } });
  const close = findButton(tree, 'Close detail');
  assert.equal(close.props['aria-label'], 'Close selected risk detail');
  close.props.onClick();
  tree = harness.render();
  assert.doesNotMatch(textOf(tree), /Artifact provenance/);
  assert.equal(focusCount, 1);
});

test('close detail does not focus a row after its callback ref unmounts', async () => {
  let focusCount = 0;
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
    '/api/plugins/skynet-edr/risks/risk-1': canonicalDetail(),
  });
  harness.render();
  await harness.flushEffects();
  findButton(harness.render(), 'MCP network activity').props.onClick();
  harness.render();
  await harness.flushEffects();
  const tree = harness.render();
  const row = findButton(tree, 'MCP network activity');
  row.props.ref({ focus() { focusCount += 1; } });
  row.props.ref(null);
  findButton(tree, 'Close detail').props.onClick();
  assert.equal(focusCount, 0);
});

test('Escape collapses selected detail and returns focus to the visible row', async () => {
  let focusCount = 0;
  let prevented = false;
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
    '/api/plugins/skynet-edr/risks/risk-1': canonicalDetail(),
  });
  harness.render();
  await harness.flushEffects();
  findButton(harness.render(), 'MCP network activity').props.onClick();
  harness.render();
  await harness.flushEffects();
  let tree = harness.render();
  const row = findButton(tree, 'MCP network activity');
  row.props.ref({ focus() { focusCount += 1; } });
  harness.dispatchDocument('keydown', { key: 'Escape', preventDefault() { prevented = true; } });
  tree = harness.render();
  assert.doesNotMatch(textOf(tree), /Artifact provenance/);
  assert.equal(prevented, true);
  assert.equal(focusCount, 1);
});

test('renders provenance definitions as compact label-value rows', async () => {
  const risk = canonicalRisk('compact-risk');
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage({ items: [risk] }),
    '/api/plugins/skynet-edr/risks/compact-risk': canonicalDetail('compact-risk'),
  });
  harness.render();
  await harness.flushEffects();
  let tree = harness.render();
  findButton(tree, 'MCP network activity').props.onClick();
  harness.render();
  await harness.flushEffects();
  tree = harness.render();

  for (const title of ['Artifact provenance', 'Sensor provenance']) {
    const section = findNode(
      tree,
      (node) => node.type === 'section' && textOf(node).includes(title),
      `${title} section`,
    );
    const list = findNode(section, (node) => node.type === 'dl', `${title} definition list`);
    const rows = childrenOf(list);
    assert.ok(rows.length >= 4);
    for (const row of rows) {
      const cells = childrenOf(row);
      assert.equal(cells[0].type, 'dt');
      assert.equal(cells[1].type, 'dd');
      assert.equal(row.props.style.gridTemplateColumns, '7rem minmax(0, 1fr)');
      assert.equal(row.props.style.alignItems, 'baseline');
      assert.equal(cells[1].props.style.minWidth, 0);
      assert.equal(cells[1].props.style.overflowWrap, 'anywhere');
    }
  }
});

test('detail timeline and hostile long identifiers release intrinsic width and wrap deterministically', async () => {
  const trace = 'trace-' + 'a'.repeat(122);
  const eventId = 'evt-' + 'b'.repeat(124);
  const risk = canonicalRisk('wrap-risk');
  risk.trace_ids = [trace];
  const detail = canonicalDetail('wrap-risk');
  detail.trace_ids = [trace];
  detail.evidence[0].event_id = eventId;
  detail.evidence[0].sensor.sensor = 'sensor-' + 'c'.repeat(121);
  detail.evidence[0].sensor.integration = 'integration-' + 'd'.repeat(116);
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage({ items: [risk] }),
    '/api/plugins/skynet-edr/risks/wrap-risk': detail,
  });
  harness.render();
  await harness.flushEffects();
  findButton(harness.render(), 'MCP network activity').props.onClick();
  harness.render();
  await harness.flushEffects();
  const tree = harness.render();
  const panel = findNode(tree, (node) => node.props?.id === 'skynet-risk-detail-panel', 'risk detail panel');
  const content = findNode(panel, (node) => node.type === 'CardContent' && textOf(node).includes(eventId), 'risk detail content');
  assert.equal(content.props.className, 'grid min-w-0 gap-4');
  assert.equal(content.props.style.minWidth, 0);

  const traceSection = findNode(panel, (node) => node.type === 'section' && node.props?.['aria-labelledby'] === 'skynet-traces-heading', 'trace section');
  assert.equal(traceSection.props.style.minWidth, 0);
  const traceList = findNode(traceSection, (node) => node.type === 'div' && textOf(node).includes(trace), 'trace badge list');
  assert.equal(traceList.props.style.minWidth, 0);
  const traceBadge = findNode(traceList, (node) => node.type === 'Badge' && textOf(node).includes(trace), 'trace badge');
  assert.equal(traceBadge.props.style.minWidth, 0);
  assert.equal(traceBadge.props.style.overflowWrap, 'anywhere');
  assert.equal(traceBadge.props.style.wordBreak, 'break-word');

  const timeline = findNode(panel, (node) => node.type === 'section' && node.props?.['aria-labelledby'] === 'skynet-evidence-heading', 'evidence timeline');
  assert.equal(timeline.props.style.minWidth, 0);
  const list = findNode(timeline, (node) => node.type === 'ol', 'timeline list');
  assert.equal(list.props.className, 'grid min-w-0 gap-3');
  assert.equal(list.props.style.minWidth, 0);
  const item = findNode(list, (node) => node.type === 'li' && textOf(node).includes(eventId), 'timeline item');
  assert.equal(item.props.style.minWidth, 0);
  const meta = findNode(
    item,
    (node) => node.type === 'div' && node.props?.className === 'mt-1 text-xs text-muted-foreground' && textOf(node).includes('event ' + eventId),
    'timeline event id metadata',
  );
  assert.equal(meta.props.style.minWidth, 0);
  assert.equal(meta.props.style.overflowWrap, 'anywhere');
  assert.equal(meta.props.style.wordBreak, 'break-word');
  const provenance = findNode(item, (node) => node.type === 'p' && textOf(node).includes('sensor mcp_tool/'), 'timeline provenance metadata');
  assert.equal(provenance.props.style.minWidth, 0);
  assert.equal(provenance.props.style.overflowWrap, 'anywhere');
  assert.equal(provenance.props.style.wordBreak, 'break-word');
});

test('renders every allowlisted source kind with fixed source-aware text', async () => {
  const labels = {
    email: 'Email content',
    url: 'URL content',
    git_repository: 'Git repository',
    code: 'Code content',
    file: 'File content',
    message: 'Message content',
    mcp: 'MCP content',
    terminal: 'Terminal output',
    unknown: 'Unclassified artifact',
  };
  const items = Object.entries(labels).map(([kind, displayLabel], index) => ({
    ...canonicalRisk(`risk-${index}`),
    artifact: { kind, provider: null, display_label: displayLabel, locator_hash: null, trust_level: 'tool_output' },
  }));
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage({ items, total: items.length }),
  });
  harness.render();
  await harness.flushEffects();
  const text = textOf(harness.render());
  for (const label of ['Email', 'URL', 'Git', 'Code', 'File', 'Message', 'MCP', 'Terminal', 'Unknown']) {
    assert.match(text, new RegExp(`\\b${label}\\b`));
  }
});

test('pagination advances by exact page.returned and honors page.has_more', async () => {
  const first = canonicalPage({ items: [canonicalRisk('risk-0')], offset: 0, total: 2, hasMore: true });
  const second = canonicalPage({ items: [canonicalRisk('risk-1')], offset: 1, total: 2, hasMore: false });
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': first,
    '/api/plugins/skynet-edr/risks?limit=50&offset=1': second,
  });
  harness.render();
  await harness.flushEffects();
  let tree = harness.render();
  const next = findButton(tree, 'Next');
  assert.equal(next.props.disabled, false);
  next.props.onClick();
  harness.render();
  await harness.flushEffects();
  tree = harness.render();
  assert.ok(harness.calls.some((args) => args[0] === '/api/plugins/skynet-edr/risks?limit=50&offset=1'));
  assert.equal(findButton(tree, 'Next').props.disabled, true);
});

test('stale list warning remains visible while a retry is in flight', async () => {
  const blocked = deferred();
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': [canonicalPage(), new Error('offline'), () => blocked.promise],
  });
  harness.render();
  await harness.flushEffects();
  await harness.runInterval(1);
  let tree = harness.render();
  assert.match(textOf(tree), /Stale data/);
  const retry = harness.runInterval(1);
  await new Promise((resolve) => setImmediate(resolve));
  tree = harness.render();
  assert.match(textOf(tree), /Stale data/);
  assert.match(textOf(tree), /Stale validated data/);
  blocked.resolve(canonicalPage());
  await retry;
});

test('older list response cannot overwrite a newer validated poll', async () => {
  const older = deferred();
  const newer = deferred();
  const oldRisk = canonicalRisk('risk-old');
  const newRisk = canonicalRisk('risk-new');
  oldRisk.sensor.sensor = 'old-sensor';
  newRisk.sensor.sensor = 'new-sensor';
  const oldPage = canonicalPage({ items: [oldRisk] });
  const newPage = canonicalPage({ items: [newRisk] });
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': [canonicalPage(), () => older.promise, () => newer.promise],
  });
  harness.render();
  await harness.flushEffects();
  const oldRequest = harness.runInterval(1);
  const newRequest = harness.runInterval(1);
  newer.resolve(newPage);
  await newRequest;
  assert.match(textOf(harness.render()), /new-sensor/);
  older.resolve(oldPage);
  await oldRequest;
  const text = textOf(harness.render());
  assert.match(text, /new-sensor/);
  assert.doesNotMatch(text, /old-sensor/);
});

test('stale detail remains visible while its retry is in flight', async () => {
  const blocked = deferred();
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
    '/api/plugins/skynet-edr/risks/risk-1': [canonicalDetail(), new Error('offline'), () => blocked.promise],
  });
  harness.render();
  await harness.flushEffects();
  findButton(harness.render(), 'MCP network activity').props.onClick();
  harness.render();
  await harness.flushEffects();
  await harness.runInterval(2);
  assert.match(textOf(harness.render()), /Stale detail/);
  const retry = harness.runInterval(2);
  await new Promise((resolve) => setImmediate(resolve));
  assert.match(textOf(harness.render()), /Stale detail/);
  blocked.resolve(canonicalDetail());
  await retry;
});

test('mismatched detail identity fails closed', async () => {
  const mismatched = canonicalDetail('other-risk');
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
    '/api/plugins/skynet-edr/risks/risk-1': mismatched,
  });
  harness.render();
  await harness.flushEffects();
  findButton(harness.render(), 'MCP network activity').props.onClick();
  harness.render();
  await harness.flushEffects();
  const text = textOf(harness.render());
  assert.match(text, /Unable to load risk detail/);
});

test('empty page renders a coherent zero range even after a nonzero offset', async () => {
  const first = canonicalPage({ items: [canonicalRisk()], offset: 0, total: 2, hasMore: true });
  const emptyAfterShrink = canonicalPage({ items: [], offset: 1, total: 0, hasMore: false });
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': first,
    '/api/plugins/skynet-edr/risks?limit=50&offset=1': emptyAfterShrink,
  });
  harness.render();
  await harness.flushEffects();
  findButton(harness.render(), 'Next').props.onClick();
  harness.render();
  await harness.flushEffects();
  const text = textOf(harness.render());
  assert.match(text, /Showing 0 of 0 risks/);
  assert.doesNotMatch(text, /Showing 0–0/);
});

test('detail navigation invalidates an older request for another risk', async () => {
  const firstBlocked = deferred();
  const first = canonicalRisk('risk-a');
  const second = canonicalRisk('risk-b');
  second.rule_id = 'EDR-CONFIG-001';
  second.title = 'Agent configuration drift detected';
  const secondDetail = { ...canonicalDetail('risk-b'), ...second };
  secondDetail.sensor = { ...secondDetail.sensor, sensor: 'second-detail-sensor' };
  const firstDetail = canonicalDetail('risk-a');
  firstDetail.sensor = { ...firstDetail.sensor, sensor: 'first-detail-sensor' };
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage({ items: [first, second], total: 2 }),
    '/api/plugins/skynet-edr/risks/risk-a': () => firstBlocked.promise,
    '/api/plugins/skynet-edr/risks/risk-b': secondDetail,
  });
  harness.render();
  await harness.flushEffects();
  findButton(harness.render(), 'MCP network activity').props.onClick();
  harness.render();
  await harness.flushEffects();
  findButton(harness.render(), 'Agent configuration drift').props.onClick();
  harness.render();
  await harness.flushEffects();
  assert.match(textOf(harness.render()), /second-detail-sensor/);
  firstBlocked.resolve(firstDetail);
  await new Promise((resolve) => setImmediate(resolve));
  const text = textOf(harness.render());
  assert.match(text, /second-detail-sensor/);
  assert.doesNotMatch(text, /first-detail-sensor/);
});

test('opaque routable IDs are encoded and dot segments or lone surrogates fail closed', async () => {
  for (const id of ['inc/../x', '\0', 'é', '😀', '%2e', '.%2e']) {
    const path = `/api/plugins/skynet-edr/risks/${encodeURIComponent(id)}`;
    const harness = createHarness({
      '/api/plugins/skynet-edr/status': canonicalStatus,
      '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage({ items: [canonicalRisk(id)] }),
      [path]: canonicalDetail(id),
    });
    harness.render();
    await harness.flushEffects();
    findButton(harness.render(), 'MCP network activity').props.onClick();
    harness.render();
    await harness.flushEffects();
    assert.ok(harness.calls.some((args) => args[0] === path), `missing encoded detail request for ${JSON.stringify(id)}`);
  }

  for (const id of ['.', '..', '\uD800']) {
    const harness = createHarness({
      '/api/plugins/skynet-edr/status': canonicalStatus,
      '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage({ items: [canonicalRisk(id)] }),
    });
    harness.render();
    await harness.flushEffects();
    assert.match(textOf(harness.render()), /Unable to load risks/);
    assert.equal(harness.calls.some((args) => args[0].includes('/risks/')), false);
  }
});

test('nested schema duplicates and incoherent pagination fail closed', async () => {
  const duplicateTraces = canonicalRisk('duplicate-traces');
  duplicateTraces.trace_ids = ['trace-1', 'trace-1'];
  const duplicateItem = canonicalRisk('duplicate-item');
  const badPagination = canonicalPage();
  badPagination.page.has_more = true;
  const cases = [
    canonicalPage({ items: [duplicateTraces] }),
    canonicalPage({ items: [duplicateItem, { ...duplicateItem }], total: 2 }),
    badPagination,
  ];
  for (const page of cases) {
    const harness = createHarness({
      '/api/plugins/skynet-edr/status': canonicalStatus,
      '/api/plugins/skynet-edr/risks?limit=50&offset=0': page,
    });
    harness.render();
    await harness.flushEffects();
    assert.match(textOf(harness.render()), /Unable to load risks/);
  }
});

test('Previous follows exact history and a filter reset returns to offset zero', async () => {
  const first = canonicalPage({ items: [canonicalRisk('risk-0')], offset: 0, total: 2, hasMore: true });
  const second = canonicalPage({ items: [canonicalRisk('risk-1')], offset: 1, total: 2, hasMore: false });
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': first,
    '/api/plugins/skynet-edr/risks?limit=50&offset=1': second,
  });
  harness.render();
  await harness.flushEffects();
  findButton(harness.render(), 'Next').props.onClick();
  harness.render();
  await harness.flushEffects();
  findButton(harness.render(), 'Previous').props.onClick();
  harness.render();
  await harness.flushEffects();
  let riskCalls = harness.calls.map((args) => args[0]).filter((path) => path.includes('/risks?'));
  assert.equal(riskCalls.at(-1), '/api/plugins/skynet-edr/risks?limit=50&offset=0');

  findButton(harness.render(), 'Next').props.onClick();
  harness.render();
  await harness.flushEffects();
  const search = findNode(harness.render(), (entry) => entry.type === 'Input' && entry.props.id === 'skynet-risk-search', 'risk search input');
  search.props.onChange({ target: { value: 'mcp' } });
  harness.render();
  await harness.flushEffects();
  riskCalls = harness.calls.map((args) => args[0]).filter((path) => path.includes('/risks?'));
  assert.equal(riskCalls.at(-1), '/api/plugins/skynet-edr/risks?limit=50&offset=0');
});

test('dashboard uses only the installed host Badge and Button styling contracts', () => {
  assert.doesNotMatch(source, /h\((?:Badge|Button),\s*\{[^}]*\bvariant\s*:/);
});

test('every destructive badge removes the host translucent fill for AA contrast', async () => {
  assert.doesNotMatch(source, /h\(Badge,\s*\{[^}\n]*tone:\s*[^}\n]*"destructive"/);
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage({ items: [{ ...canonicalRisk(), severity: 'critical' }] }),
  });
  harness.render();
  await harness.flushEffects();

  const destructive = [];
  walk(harness.render(), (node) => {
    if (node.type === 'Badge' && node.props?.tone === 'destructive') destructive.push(node);
  });
  assert.ok(destructive.length >= 1, 'fixture must render a destructive critical-severity badge');
  for (const badge of destructive) assert.equal(badge.props.style?.backgroundColor, 'transparent');
});

test('header uses semantic host badge tones for engine and mode status', async () => {
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
  });
  const checkingTree = harness.render();
  assert.equal(findNode(checkingTree, (node) => textOf(node) === 'Engine checking', 'checking engine indicator').props.tone, 'outline');
  assert.equal(findNode(checkingTree, (node) => textOf(node) === 'Mode unavailable', 'checking mode indicator').props.tone, 'outline');
  await harness.flushEffects();
  const tree = harness.render();
  assert.match(textOf(tree), /EDR 0\.5\.0/);
  const online = findNode(tree, (node) => textOf(node) === 'Engine Online', 'online engine indicator');
  assert.equal(online.props.tone, 'success');
  assert.equal(online.props.className, undefined);
  const passive = findNode(tree, (node) => textOf(node) === 'Passive mode', 'passive mode indicator');
  assert.equal(passive.props.tone, 'warning');
  assert.equal(passive.props.className, undefined);
  const high = findNode(tree, (node) => node.type === 'Badge' && textOf(node) === 'high', 'high severity indicator');
  assert.equal(high.props.tone, 'outline');
  assert.equal(high.props.style.color, 'color-mix(in srgb, #f97316 72%, var(--midground))');
  assert.equal(high.props.style.borderColor, 'color-mix(in srgb, #f97316 72%, var(--midground))');
  assert.equal(high.props.style.backgroundColor, 'transparent');
  const open = findNode(tree, (node) => node.type === 'Badge' && textOf(node) === 'open', 'open status indicator');
  assert.equal(open.props.tone, 'outline');
  assert.equal(open.props.style, undefined);
  assert.equal(findButton(tree, 'Refresh').props.outlined, true);
  assert.equal(findButton(tree, 'Previous').props.outlined, true);
  assert.equal(findButton(tree, 'Next').props.outlined, true);

  const activeHarness = createHarness({
    '/api/plugins/skynet-edr/status': { ...canonicalStatus, run_mode: 'active' },
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
  });
  activeHarness.render();
  await activeHarness.flushEffects();
  const active = findNode(activeHarness.render(), (node) => textOf(node) === 'Active mode', 'active mode indicator');
  assert.equal(active.props.tone, 'success');
  assert.equal(active.props.className, undefined);

  const invalid = { ...canonicalStatus, version: '<script>bad</script>' };
  const invalidHarness = createHarness({
    '/api/plugins/skynet-edr/status': invalid,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
  });
  invalidHarness.render();
  await invalidHarness.flushEffects();
  const invalidTree = invalidHarness.render();
  const offline = findNode(invalidTree, (node) => textOf(node) === 'Engine Offline', 'offline engine indicator');
  assert.equal(offline.props.tone, 'destructive');
  assert.equal(offline.props.className, undefined);
  assert.equal(offline.props.style.backgroundColor, 'transparent');
  assert.equal(findNode(invalidTree, (node) => textOf(node) === 'Mode unavailable', 'unavailable mode indicator').props.tone, 'outline');
  assert.equal(findNode(invalidTree, (node) => textOf(node) === 'EDR version unavailable', 'unavailable version indicator').props.tone, 'outline');
  assert.doesNotMatch(textOf(invalidTree), /script|bad/);
});

test('severity badges use the requested critical red, high orange, medium yellow and low blue palette', async () => {
  const items = ['critical', 'high', 'medium', 'low'].map((severity, index) => ({
    ...canonicalRisk(`risk-${severity}`),
    severity,
    last_observed_at_unix_ms: index + 2,
  }));
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage({ items }),
  });
  harness.render();
  await harness.flushEffects();
  const tree = harness.render();
  const critical = findNode(tree, (node) => node.type === 'Badge' && textOf(node) === 'critical', 'critical severity');
  const high = findNode(tree, (node) => node.type === 'Badge' && textOf(node) === 'high', 'high severity');
  const medium = findNode(tree, (node) => node.type === 'Badge' && textOf(node) === 'medium', 'medium severity');
  const low = findNode(tree, (node) => node.type === 'Badge' && textOf(node) === 'low', 'low severity');
  assert.equal(critical.props.tone, 'destructive');
  assert.equal(high.props.style.color, 'color-mix(in srgb, #f97316 72%, var(--midground))');
  assert.equal(medium.props.style.color, 'color-mix(in srgb, #eab308 72%, var(--midground))');
  assert.equal(low.props.style.color, 'color-mix(in srgb, #3b82f6 72%, var(--midground))');
});

test('risk detail distinguishes incident detection rule from contributing events without standalone rules', async () => {
  const risk = {
    ...canonicalDetail(),
    rule_id: 'EDR-EXFIL-001',
    title: 'Sensitive access followed by outbound delivery',
    evidence: canonicalDetail().evidence.map((event) => ({ ...event, rule_id: null })),
  };
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage({ items: [risk] }),
    '/api/plugins/skynet-edr/risks/risk-1': risk,
  });
  harness.render();
  await harness.flushEffects();
  findButton(harness.render(), 'Sensitive access followed by outbound delivery').props.onClick();
  harness.render();
  await harness.flushEffects();
  const text = textOf(harness.render());
  assert.match(text, /Detection rule EDR-EXFIL-001/);
  assert.match(text, /Contributing event · no standalone rule/);
  assert.doesNotMatch(text, /Rule none/);
});

test('a failed latest status poll marks the engine offline while telemetry data stays separate', async () => {
  const degraded = { ...canonicalStatus, ingestion: { state: 'disabled', role_identity_assurance: 'authorized_uid_self_reported', listener_live: false, sources: [] } };
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': [degraded, new Error('private failure')],
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': [canonicalPage(), canonicalPage()],
  });
  harness.render();
  await harness.flushEffects();
  await harness.runInterval(0);
  const tree = harness.render();
  const offline = findNode(tree, (node) => textOf(node) === 'Engine Offline', 'stale offline engine indicator');
  assert.equal(offline.props.tone, 'destructive');
  assert.equal(offline.props.className, undefined);
  assert.equal(offline.props.style.backgroundColor, 'transparent');
  assert.match(textOf(tree), /EDR version unavailable/);
  assert.match(textOf(tree), /Mode unavailable/);
  assert.doesNotMatch(textOf(tree), /EDR 0\.5\.0|Passive mode/);
  assert.match(textOf(tree), /Telemetry disabled/);
  assert.doesNotMatch(textOf(tree), /private failure/);
});

test('top-level tabs and panels have stable complete ARIA relationships and selected styling', async () => {
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
    '/api/plugins/skynet-edr/rules': canonicalRules,
  });
  harness.render();
  await harness.flushEffects();
  let tree = harness.render();
  const telemetry = findButton(tree, 'Telemetry');
  const rules = findButton(tree, 'Rules');
  assert.equal(telemetry.props.role, 'tab');
  assert.equal(telemetry.props.id, 'skynet-tab-telemetry');
  assert.equal(telemetry.props['aria-controls'], 'skynet-panel-telemetry');
  assert.equal(telemetry.props['aria-selected'], true);
  assert.equal(telemetry.props.tabIndex, 0);
  assert.equal(telemetry.props.ghost, undefined);
  assert.equal(rules.props.role, 'tab');
  assert.equal(rules.props.id, 'skynet-tab-rules');
  assert.equal(rules.props['aria-controls'], 'skynet-panel-rules');
  assert.equal(rules.props['aria-selected'], false);
  assert.equal(rules.props.tabIndex, -1);
  assert.equal(rules.props.ghost, true);
  let panel = findNode(tree, (node) => node.props?.id === 'skynet-panel-telemetry', 'telemetry tabpanel');
  assert.equal(panel.props.role, 'tabpanel');
  assert.equal(panel.props['aria-labelledby'], 'skynet-tab-telemetry');
  rules.props.onClick();
  harness.render();
  await harness.flushEffects();
  tree = harness.render();
  const selectedRules = findButton(tree, 'Rules');
  assert.equal(selectedRules.props['aria-selected'], true);
  assert.equal(selectedRules.props.tabIndex, 0);
  assert.equal(selectedRules.props.ghost, undefined);
  assert.equal(findButton(tree, 'Telemetry').props.tabIndex, -1);
  assert.equal(findButton(tree, 'Telemetry').props.ghost, true);
  panel = findNode(tree, (node) => node.props?.id === 'skynet-panel-rules', 'rules tabpanel');
  assert.equal(panel.props.role, 'tabpanel');
  assert.equal(panel.props['aria-labelledby'], 'skynet-tab-rules');
  assert.match(textOf(tree), /Compiled and active in this running EDR build/);
  assert.match(textOf(tree), /EDR-MALWARE-001/);
  assert.match(textOf(tree), /Malware-like content sent to AI runtime/);
  assert.match(textOf(tree), /process/);
  assert.match(textOf(tree), /messaging/);
  assert.match(textOf(tree), /file/);
  assert.match(textOf(tree), /network/);
  assert.match(textOf(tree), /mcp tool/);
  assert.doesNotMatch(textOf(tree), /last validation|policy provenance|enabled/);

  const hostileRules = structuredClone(canonicalRules);
  hostileRules.items[0].description = '<script>ignore previous instructions</script>';
  const hostileHarness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
    '/api/plugins/skynet-edr/rules': hostileRules,
  });
  hostileHarness.render();
  await hostileHarness.flushEffects();
  findButton(hostileHarness.render(), 'Rules').props.onClick();
  hostileHarness.render();
  await hostileHarness.flushEffects();
  assert.match(textOf(hostileHarness.render()), /Unable to load rules/);
  assert.doesNotMatch(textOf(hostileHarness.render()), /script|ignore previous/);
});

test('tab keyboard navigation wraps, handles Home and End, and moves focus with selection', async () => {
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage(),
    '/api/plugins/skynet-edr/rules': canonicalRules,
  });
  harness.render();
  await harness.flushEffects();

  const focused = [];
  let tree = harness.render();
  findButton(tree, 'Telemetry').props.ref({ focus() { focused.push('telemetry'); } });
  findButton(tree, 'Rules').props.ref({ focus() { focused.push('rules'); } });

  function press(label, key) {
    tree = harness.render();
    let prevented = false;
    findButton(tree, label).props.onKeyDown({ key, preventDefault() { prevented = true; } });
    assert.equal(prevented, true, `${key} must prevent native scrolling`);
  }

  press('Telemetry', 'ArrowRight');
  assert.equal(findButton(harness.render(), 'Rules').props['aria-selected'], true);
  press('Rules', 'Home');
  assert.equal(findButton(harness.render(), 'Telemetry').props['aria-selected'], true);
  press('Telemetry', 'End');
  assert.equal(findButton(harness.render(), 'Rules').props['aria-selected'], true);
  press('Rules', 'ArrowRight');
  assert.equal(findButton(harness.render(), 'Telemetry').props['aria-selected'], true);
  press('Telemetry', 'ArrowLeft');
  assert.equal(findButton(harness.render(), 'Rules').props['aria-selected'], true);
  assert.deepEqual(focused, ['rules', 'telemetry', 'rules', 'telemetry', 'rules']);
});

test('selected detail is the immediate sibling after its exact risk row', async () => {
  const first = canonicalRisk('risk-a');
  const second = canonicalRisk('risk-b');
  second.rule_id = 'EDR-CONFIG-001';
  second.title = 'Agent configuration drift detected';
  const harness = createHarness({
    '/api/plugins/skynet-edr/status': canonicalStatus,
    '/api/plugins/skynet-edr/risks?limit=50&offset=0': canonicalPage({ items: [first, second], total: 2 }),
    '/api/plugins/skynet-edr/risks/risk-b': { ...canonicalDetail('risk-b'), ...second },
  });
  harness.render();
  await harness.flushEffects();
  findButton(harness.render(), 'Agent configuration drift detected').props.onClick();
  harness.render();
  await harness.flushEffects();
  const tree = harness.render();
  const list = findNode(tree, (node) => node.type === 'ul' && node.props?.['aria-label'] === 'Current page risk list', 'risk list');
  const children = childrenOf(list);
  assert.equal(children.length, 3);
  assert.match(textOf(children[1]), /Agent configuration drift detected/);
  assert.equal(children[2].props?.['data-detail-for'], 'risk-b');
  assert.match(textOf(children[2]), /Artifact provenance/);
});
