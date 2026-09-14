#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { installAuthenticatedOriginProxy } from './hermes-browser-origin-proxy.mjs';

let stage = 'inputs';
async function main() {
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
  stage = 'launch';
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ serviceWorkers: 'block' });
  const page = await context.newPage();
  const failures = [];
  try {
    await installAuthenticatedOriginProxy(context, url, token, failures);
    page.on('pageerror', () => failures.push('browser runtime error'));
    page.on('request', request => {
      if (new URL(request.url()).port === '8787') failures.push('direct daemon access');
    });
    stage = 'navigation';
    await page.goto(url, { waitUntil: 'networkidle', timeout: 60_000 });
    stage = 'health';
    await page.getByText('Engine Online', { exact: true }).waitFor({ timeout: 30_000 });
    await page.getByText('Telemetry healthy', { exact: false }).waitFor({ timeout: 30_000 });
    stage = 'risk-list';
    const list = page.getByRole('list', { name: 'Current page risk list' });
    const row = list.getByRole('button').filter({ hasText: 'Detection rule EDR-MALWARE-001' });
    await row.waitFor({ timeout: 30_000 });
    if (await row.count() !== 1) throw new Error('expected one rendered simulation incident');
    stage = 'risk-detail';
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
    stage = 'rendered-panel';
    const panel = page.getByRole('region', { name: 'Malware-like content supplied to AI runtime' });
    await panel.waitFor({ timeout: 30_000 });
    stage = 'rendered-event';
    await panel.getByText(' · event ' + binding.event_id, { exact: false }).waitFor({ timeout: 30_000 });
    stage = 'rendered-severity';
    await panel.getByText('high', { exact: true }).first().waitFor({ timeout: 30_000 });
    stage = 'browser-errors';
    const body = await page.locator('body').innerText();
    if (body.includes('FAKE_SKYNET_EDR_ALPHA2_SECRET_DO_NOT_EXPOSE')) failures.push('redaction failure');
    if (failures.length) throw new Error('public journey browser validation failed');
    process.stdout.write('{"status":"PASS","same_event_rendered":true}\n');
  } catch (error) {
    // Fixed counts help distinguish host rendering from API contract failures.
    process.stderr.write(JSON.stringify({
      browser_stage: stage,
      panel_count: await page.locator('#skynet-risk-detail-panel').count(),
      event_visible_in_body: (await page.locator('body').innerText()).includes(binding.event_id),
      invalid_detail_count: await page.getByText('The read-only backend did not return a valid risk detail.', { exact: true }).count(),
      runtime_error_count: failures.filter(value => value === 'browser runtime error').length,
      transport_error_count: failures.filter(value => value !== 'browser runtime error').length,
    }) + '\n');
    throw error;
  } finally {
    await context.close();
    await browser.close();
  }
}
await main().catch(() => {
  // Never publish browser exceptions, response bodies, or the session token.
  process.stderr.write(JSON.stringify({ status: 'FAIL', browser_stage: stage }) + '\n');
  process.exitCode = 1;
});
