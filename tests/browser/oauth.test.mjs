import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createServer as createHttpsServer } from 'node:https';
import { once } from 'node:events';
import { chromium } from 'playwright';
import { startGarden } from '../helper.mjs';

// Real HTTPS pages and redirects exercise browser-generated Origin, cookies and
// CSP. The proxy forwards headers unchanged to the actual application server.
// All certificates, keys, cookies and authorization codes are disposable.
test('browser OAuth form preserves Origin and keeps callback referrer private', { timeout: 30000 }, async t => {
  const temporary = await mkdtemp(join(tmpdir(), 'garden-browser-tls-'));
  let browser, server;
  t.after(async () => {
    await browser?.close();
    if (server) {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
    await rm(temporary, { recursive: true, force: true });
  });
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-keyout', join(temporary, 'key.pem'), '-out', join(temporary, 'cert.pem')], { stdio: 'ignore' });
  const tls = { key: await readFile(join(temporary, 'key.pem')), cert: await readFile(join(temporary, 'cert.pem')) };
  let g, callbackRequest;
  const submissions = [], proxyErrors = [];
  server = createHttpsServer(tls, async (req, res) => {
    try {
      if (req.headers.host.startsWith('localhost:')) {
        callbackRequest = { url: new URL(req.url, 'https://' + req.headers.host), headers: req.headers };
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!doctype html><p>OAuth callback received</p>');
        return;
      }
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const response = await g.request(req.url, {
        method: req.method, headers: req.headers, body: Buffer.concat(chunks),
      });
      if (req.url === '/oauth/approve') submissions.push({
        origin: req.headers.origin, cookiePresent: (req.headers.cookie || '').includes('rh_oauth_csrf='), status: response.status,
      });
      const responseHeaders = Object.fromEntries(response.headers);
      delete responseHeaders['transfer-encoding'];
      delete responseHeaders['content-length'];
      res.writeHead(response.status, responseHeaders);
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      proxyErrors.push('test HTTPS proxy failed');
      res.writeHead(500); res.end('test proxy failure');
    }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const base = 'https://127.0.0.1:' + server.address().port;
  const callbackOrigin = 'https://localhost:' + server.address().port;
  const callback = callbackOrigin + '/callback';
  g = await startGarden(t, { publicBase: base });
  browser = await chromium.launch({ headless: true,
    ...(process.env.PLAYWRIGHT_EXECUTABLE_PATH ? { executablePath: process.env.PLAYWRIGHT_EXECUTABLE_PATH } : {}) });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  const policyErrors = [];
  page.on('console', message => {
    if (message.text().includes('form-action')) policyErrors.push('form-action violation');
  });
  const registered = await g.json('/register', { client_name: 'Browser regression test', redirect_uris: [callback],
    token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] });
  assert.equal(registered.status, 201);
  const client = await registered.json();
  const verifier = randomBytes(32).toString('base64url');
  const params = new URLSearchParams({ client_id: client.client_id, redirect_uri: callback, response_type: 'code',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
    scope: 'garden:play', state: 'browser-test', resource: base + '/mcp' });

  for (const decision of ['approve', 'approve', 'deny']) {
    callbackRequest = null;
    await page.goto(base + '/authorize?' + params);
    if (decision === 'approve') await page.locator('#key').fill(g.keys.user);
    const posted = page.waitForResponse(r => r.url() === base + '/oauth/approve' && r.request().method() === 'POST');
    await page.locator('button[value="' + decision + '"]').click();
    assert.equal((await posted).status(), 303, 'real browser form submission must pass the server origin check');
    await page.waitForURL(url => url.origin === callbackOrigin);
    assert.deepEqual(submissions.at(-1), { origin: base, cookiePresent: true, status: 303 });
    assert.deepEqual(proxyErrors, []);
    assert.deepEqual(policyErrors, [], 'validated callback must not be blocked by form-action');
    assert.equal(callbackRequest.headers.referer, undefined, 'callback must not receive the authorization page URL');
    assert.equal(callbackRequest.headers.cookie, undefined, 'garden CSRF cookie must not leave its origin');
    assert.equal(callbackRequest.url.searchParams.get('state'), 'browser-test');
    if (decision === 'deny') {
      assert.equal(callbackRequest.url.searchParams.get('error'), 'access_denied');
      assert.equal(callbackRequest.url.searchParams.has('code'), false);
      continue;
    }
    const code = callbackRequest.url.searchParams.get('code');
    assert.ok(code);
    const exchanged = await g.request('/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', client_id: client.client_id, code,
        redirect_uri: callback, code_verifier: verifier, resource: base + '/mcp' }).toString() });
    assert.equal(exchanged.status, 200);
    const tokens = await exchanged.json();
    const tools = await g.json('/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list' }, tokens.access_token,
      { Accept: 'application/json, text/event-stream' });
    assert.equal(tools.status, 200);
  }
});
