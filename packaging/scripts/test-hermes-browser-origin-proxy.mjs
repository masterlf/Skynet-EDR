#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { installAuthenticatedOriginProxy } from './hermes-browser-origin-proxy.mjs';

const [browserRuntime] = process.argv.slice(2);
if (!browserRuntime) throw new Error('usage: test-hermes-browser-origin-proxy.mjs BROWSER_RUNTIME');
const requireFromRuntime = createRequire(join(resolve(browserRuntime), 'package.json'));
const { chromium } = requireFromRuntime('playwright');
const token = 'negative-test-token-0000000000000000000000000001';
const received = { origin: [], external: [] };

function listen(handler) {
  return new Promise((resolve, reject) => {
    const server = createServer(handler);
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}
function close(server) {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

const external = await listen((request, response) => {
  received.external.push(request.headers['x-hermes-session-token'] ?? null);
  response.writeHead(200, { 'content-type': 'text/html' });
  response.end('<!doctype html><title>external</title>');
});
const externalOrigin = `http://127.0.0.1:${external.address().port}`;
const origin = await listen((request, response) => {
  received.origin.push(request.headers['x-hermes-session-token'] ?? null);
  if (request.url === '/redirect') {
    response.writeHead(302, { location: `${externalOrigin}/redirect-target` });
    response.end();
    return;
  }
  if (request.url === '/popup') {
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end(`<!doctype html><script>window.open(${JSON.stringify(`${externalOrigin}/popup-target`)}, '_blank')</script>`);
    return;
  }
  response.writeHead(200, { 'content-type': 'text/html' });
  response.end('<!doctype html><title>same origin</title>');
});
const originUrl = `http://127.0.0.1:${origin.address().port}`;
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ serviceWorkers: 'block' });
const failures = [];
try {
  await installAuthenticatedOriginProxy(context, originUrl, token, failures);
  const direct = await context.newPage();
  await direct.goto(`${originUrl}/direct`, { waitUntil: 'load' });
  assert.equal(received.origin.at(-1), token);

  const redirected = await context.newPage();
  await assert.rejects(redirected.goto(`${originUrl}/redirect`, { waitUntil: 'load' }));
  assert.equal(received.external.length, 0);
  assert.ok(failures.some((failure) => failure.startsWith('blocked authenticated redirect: 302')));

  const popupPage = await context.newPage();
  const popup = popupPage.waitForEvent('popup');
  await popupPage.goto(`${originUrl}/popup`, { waitUntil: 'load' });
  await popup;
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(received.external.length, 0);
  assert.ok(failures.some((failure) => failure.startsWith('blocked cross-origin request:')));
  process.stdout.write(JSON.stringify({ lane: 'origin-proxy-negative', status: 'PASS' }) + '\n');
} finally {
  await context.close();
  await browser.close();
  await close(origin);
  await close(external);
}
