#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';

const [url, lane, manifestPath, browserRuntime] = process.argv.slice(2);
if (!url || !['normal', 'alert-delivery'].includes(lane) || !manifestPath || !browserRuntime) {
  throw new Error('usage: hermes-browser-smoke.mjs URL LANE MANIFEST BROWSER_RUNTIME');
}
if (!url.startsWith('http://127.0.0.1:') || url.includes(':8787')) {
  throw new Error('browser target must be the loopback Hermes origin, never the daemon');
}
const requireFromRuntime = createRequire(join(browserRuntime, 'package.json'));
const { chromium } = requireFromRuntime('playwright');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
if (manifest.schema !== 1 || manifest.payload_version !== '0.6.0') {
  throw new Error('installed package manifest version mismatch');
}
function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, v]) => [k, canonicalize(v)]));
  }
  return value;
}
const generation = createHash('sha256').update(JSON.stringify(canonicalize(manifest.files))).digest('hex');
if (manifest.generation !== generation) throw new Error('installed package manifest generation mismatch');
const pluginRoot = dirname(manifestPath) + '/skynet-edr';
for (const [relative, record] of Object.entries(manifest.files)) {
  const bytes = readFileSync(join(pluginRoot, relative));
  if (bytes.length !== record.size || createHash('sha256').update(bytes).digest('hex') !== record.sha256) {
    throw new Error(`installed package payload mismatch: ${relative}`);
  }
}
const dashboard = JSON.parse(readFileSync(join(pluginRoot, 'dashboard/manifest.json'), 'utf8'));
const sri = 'sha384-' + createHash('sha384').update(readFileSync(join(pluginRoot, 'dashboard/plugin.js'))).digest('base64');
if (dashboard.integrity !== sri || dashboard.version !== manifest.payload_version) {
  throw new Error('dashboard bundle identity mismatch');
}

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  const failures = [];
  page.on('request', (request) => {
    if (request.url().includes(':8787')) failures.push('browser attempted direct daemon access');
  });
  page.on('console', (message) => { if (message.type() === 'error') failures.push(`console: ${message.text()}`); });
  page.on('pageerror', (error) => failures.push(`pageerror: ${error.message}`));
  await page.goto(url, { waitUntil: 'networkidle', timeout: 60_000 });
  for (const text of ['EDR 0.6.0', 'Engine Online', 'Backend available', 'Passive mode']) {
    await page.getByText(text, { exact: true }).waitFor({ timeout: 30_000 });
  }
  const telemetry = lane === 'normal' ? 'Telemetry disabled' : 'Telemetry degraded';
  await page.getByText(telemetry, { exact: false }).waitFor({ timeout: 30_000 });
  const heading = await page.getByText('Skynet-EDR Risk Explorer', { exact: true }).count();
  if (heading !== 1) throw new Error('packaged dashboard plugin did not register exactly once');
  if (failures.length) throw new Error(failures.join('; '));
  process.stdout.write(JSON.stringify({ generation, lane, status: 'PASS' }) + '\n');
} finally {
  await browser.close();
}
