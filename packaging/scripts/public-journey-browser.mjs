#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { installAuthenticatedOriginProxy } from './hermes-browser-origin-proxy.mjs';

const [runtime, bindingPath] = process.argv.slice(2);
const token = process.env.HERMES_DASHBOARD_SESSION_TOKEN;
const url = 'http://127.0.0.1:9119/skynet-edr/risks';
if (!runtime || !bindingPath || !token || token.length < 32 || token.length > 256 || /\s/.test(token)) {
  throw new Error('invalid public journey browser inputs');
}
const binding = JSON.parse(readFileSync(bindingPath, 'utf8'));
if (binding.rule_id !== 'EDR-MALWARE-001' || !/^inc:EDR-MALWARE-001:[a-f0-9]{64}$/.test(binding.incident_id)
    || typeof binding.event_id !== 'string' || !/^[A-Za-z0-9_:-]{1,256}$/.test(binding.event_id)) {
  throw new Error('invalid incident binding');
}
const require = createRequire(join(runtime, 'package.json'));
const { chromium } = require('playwright');
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ serviceWorkers: 'block' });
try {
  const failures = [];
  await installAuthenticatedOriginProxy(context, url, token, failures);
  const page = await context.newPage();
  page.on('pageerror', () => failures.push('browser runtime error'));
  page.on('request', request => {
    if (new URL(request.url()).port === '8787') failures.push('direct daemon access');
  });
  await page.goto(url, { waitUntil: 'networkidle', timeout: 60_000 });
  await page.getByText('Engine Online', { exact: true }).waitFor({ timeout: 30_000 });
  await page.getByText('Telemetry healthy', { exact: false }).waitFor({ timeout: 30_000 });
  const list = page.getByRole('list', { name: 'Current page risk list' });
  const row = list.getByRole('button').filter({ hasText: 'Detection rule EDR-MALWARE-001' });
  await row.waitFor({ timeout: 30_000 });
  if (await row.count() !== 1) throw new Error('expected one rendered simulation incident');
  const responsePromise = page.waitForResponse(response => {
    const target = new URL(response.url());
    return target.origin === new URL(url).origin
      && decodeURIComponent(target.pathname) === '/api/plugins/skynet-edr/risks/' + binding.incident_id;
  }, { timeout: 30_000 });
  await row.click();
  const response = await responsePromise;
  const detail = await response.json();
  if (response.status() !== 200 || detail.id !== binding.incident_id || detail.rule_id !== binding.rule_id
      || detail.severity !== 'high' || detail.evidence?.length !== 1
      || detail.evidence[0].event_id !== binding.event_id) {
    throw new Error('browser response does not match persisted evidence');
  }
  const panel = page.getByRole('region', { name: 'Malware-like content supplied to AI runtime' });
  await panel.getByText(binding.event_id, { exact: true }).waitFor({ timeout: 30_000 });
  await panel.getByText('High', { exact: true }).first().waitFor();
  const body = await page.locator('body').innerText();
  if (body.includes('FAKE_SKYNET_EDR_ALPHA2_SECRET_DO_NOT_EXPOSE')) failures.push('redaction failure');
  if (failures.length) throw new Error('public journey browser validation failed');
  process.stdout.write('{"status":"PASS","same_event_rendered":true}\n');
} finally {
  await context.close();
  await browser.close();
}
