// HTTP-level tests: login/sessions, sliding TTL, admin auth, resolve, validation, CORS.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { createSecretManagerServer } from '../server.js';

const TOKEN = 'test-resolver-token-1234567890';
const ADMIN_TOKEN = 'test-admin-token-0987654321';
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

async function startServer(opts = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'sm-srv-'));
  const srv = createSecretManagerServer({
    token: TOKEN,
    adminToken: ADMIN_TOKEN,
    dataFile: join(dir, 'data.json'),
    ...opts,
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${srv.address().port}`;
  return {
    url,
    stop: async () => {
      await new Promise((r) => srv.close(r));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function headers(bearer) {
  const h = { 'content-type': 'application/json' };
  if (bearer) h.authorization = `Bearer ${bearer}`;
  return h;
}

async function login(url, token = ADMIN_TOKEN, sessionId = randomUUID()) {
  const res = await fetch(url + '/login', {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ token, sessionId }),
  });
  return { res, sessionId };
}

// Shared server with a long TTL so sessions survive the fast functional tests.
let server;
before(async () => {
  server = await startServer({ sessionTtlMs: 60_000 });
});
after(async () => {
  await server.stop();
});

test('login: admin token + v4 uuid → session; resolver/wrong token → 401; bad uuid → 400', async () => {
  const ok = await login(server.url);
  assert.equal(ok.res.status, 200);
  assert.equal((await ok.res.json()).ok, true);

  const resolverCredential = await login(server.url, TOKEN);
  assert.equal(resolverCredential.res.status, 401);
  assert.equal((await resolverCredential.res.json()).code, 'unauthorized');

  const wrong = await login(server.url, 'wrong-token');
  assert.equal(wrong.res.status, 401);
  assert.equal((await wrong.res.json()).code, 'unauthorized');

  const bad = await login(server.url, TOKEN, 'not-a-uuid');
  assert.equal(bad.res.status, 400);
  assert.equal((await bad.res.json()).code, 'bad_request');
});

test('admin auth: /keys requires a valid session uuid (not the raw token)', async () => {
  let res = await fetch(server.url + '/keys'); // no header
  assert.equal(res.status, 401);
  assert.equal((await res.json()).code, 'unauthorized');

  res = await fetch(server.url + '/keys', { headers: headers(randomUUID()) }); // unknown uuid
  assert.equal(res.status, 401);

  res = await fetch(server.url + '/keys', { headers: headers(TOKEN) }); // raw token is not a session
  assert.equal(res.status, 401);
});

test('keys: a session can append versions and list them masked', async () => {
  const { sessionId } = await login(server.url);

  const create = await fetch(server.url + '/keys', {
    method: 'POST',
    headers: headers(sessionId),
    body: JSON.stringify({ name: 'FOO', value: 'foo-v1' }),
  });
  assert.equal(create.status, 201);
  assert.deepEqual(await create.json(), { name: 'FOO', version: 1 });

  await fetch(server.url + '/keys', {
    method: 'POST',
    headers: headers(sessionId),
    body: JSON.stringify({ name: 'FOO', value: 'foo-v2' }),
  });

  const list = await fetch(server.url + '/keys', { headers: headers(sessionId) });
  const text = JSON.stringify(await list.json());
  assert.ok(!text.includes('foo-v1'));
  assert.ok(!text.includes('foo-v2'));
  assert.ok(text.includes('••••••'));
});

test('resolve: uses only the resolver token, maps BAR_V2, omits unknown pointers', async () => {
  // Seed via a session.
  const { sessionId } = await login(server.url);
  for (const value of ['bar-v1', 'bar-v2']) {
    await fetch(server.url + '/keys', {
      method: 'POST',
      headers: headers(sessionId),
      body: JSON.stringify({ name: 'BAR', value }),
    });
  }

  // Resolve with the raw token (client apps), NOT a session.
  const res = await fetch(server.url + '/resolve', {
    method: 'POST',
    headers: headers(TOKEN),
    body: JSON.stringify({ keys: ['BAR_V2', 'NOPE_V9'] }),
  });
  assert.equal(res.status, 200);
  const { values } = await res.json();
  assert.equal(values.BAR_V2, 'bar-v2');
  assert.ok(!('NOPE_V9' in values));

  // Neither an administrator credential nor a session UUID is accepted on /resolve.
  const adminCredential = await fetch(server.url + '/resolve', {
    method: 'POST',
    headers: headers(ADMIN_TOKEN),
    body: JSON.stringify({ keys: [] }),
  });
  assert.equal(adminCredential.status, 401);

  const wrong = await fetch(server.url + '/resolve', {
    method: 'POST',
    headers: headers(sessionId),
    body: JSON.stringify({ keys: [] }),
  });
  assert.equal(wrong.status, 401);
});

test('validation: POST /keys rejects a _V<n> name and an empty value with 400', async () => {
  const { sessionId } = await login(server.url);

  const reserved = await fetch(server.url + '/keys', {
    method: 'POST',
    headers: headers(sessionId),
    body: JSON.stringify({ name: 'FOO_V2', value: 'x' }),
  });
  assert.equal(reserved.status, 400);
  assert.equal((await reserved.json()).code, 'bad_request');

  const empty = await fetch(server.url + '/keys', {
    method: 'POST',
    headers: headers(sessionId),
    body: JSON.stringify({ name: 'BAZ', value: '' }),
  });
  assert.equal(empty.status, 400);
});

test('reveal: a session returns the real value; unknown → 404; no session → 401', async () => {
  const { sessionId } = await login(server.url);
  await fetch(server.url + '/keys', {
    method: 'POST',
    headers: headers(sessionId),
    body: JSON.stringify({ name: 'REVEAL_ME', value: 'top-secret' }),
  });

  const ok = await fetch(server.url + '/reveal', {
    method: 'POST',
    headers: headers(sessionId),
    body: JSON.stringify({ name: 'REVEAL_ME', version: 1 }),
  });
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).value, 'top-secret');

  const missing = await fetch(server.url + '/reveal', {
    method: 'POST',
    headers: headers(sessionId),
    body: JSON.stringify({ name: 'REVEAL_ME', version: 99 }),
  });
  assert.equal(missing.status, 404);
  assert.equal((await missing.json()).code, 'unknown_key');

  const noSession = await fetch(server.url + '/reveal', {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ name: 'REVEAL_ME', version: 1 }),
  });
  assert.equal(noSession.status, 401);
});

test('logout: ends the session', async () => {
  const { sessionId } = await login(server.url);
  assert.equal((await fetch(server.url + '/keys', { headers: headers(sessionId) })).status, 200);

  await fetch(server.url + '/logout', { method: 'POST', headers: headers(sessionId) });
  assert.equal((await fetch(server.url + '/keys', { headers: headers(sessionId) })).status, 401);
});

test('CORS: preflight is answered 204 without auth, and exposes the right headers', async () => {
  const pre = await fetch(server.url + '/keys', { method: 'OPTIONS' });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get('access-control-allow-origin'), '*');
  assert.match(pre.headers.get('access-control-allow-headers'), /authorization/i);
});

test('admin pages execute no remote scripts and support a same-origin proxy prefix', async () => {
  for (const path of ['/', '/editor']) {
    const response = await fetch(server.url + path);
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.doesNotMatch(html, /<script[^>]+src=["']https?:/i);
    assert.doesNotMatch(html, /cdn\.tailwindcss\.com/i);
    assert.match(html, /default-src 'none'/);
    assert.match(html, /<link rel="stylesheet" href="\.\/styles\.css"/);
    assert.match(html, /const BASE_PATH = pagePath\.replace/);
    assert.match(html, /const BACKEND_URL = window\.location\.origin \+ BASE_PATH/);

    const inlineScript = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
    assert.ok(inlineScript);
    const browserNormalizedScript = inlineScript.replace(/\r\n?/g, '\n');
    const scriptHash = createHash('sha256').update(browserNormalizedScript).digest('base64');
    assert.ok(html.includes(`script-src 'sha256-${scriptHash}'`));
  }

  assert.equal(new URL('./styles.css', 'https://example.test/').pathname, '/styles.css');
  assert.equal(
    new URL('./styles.css', 'https://example.test/secrets/').pathname,
    '/secrets/styles.css',
  );

  const stylesheet = await fetch(server.url + '/styles.css');
  assert.equal(stylesheet.status, 200);
  assert.match(stylesheet.headers.get('content-type'), /^text\/css/);
  assert.match(await stylesheet.text(), /\.bg-slate-100/);
});

test('session TTL: activity slides the window; idle past the TTL expires it', async () => {
  const s = await startServer({ sessionTtlMs: 400 });
  try {
    const { sessionId } = await login(s.url);
    const hit = () => fetch(s.url + '/keys', { headers: headers(sessionId) });

    assert.equal((await hit()).status, 200); // active
    await delay(250);
    assert.equal((await hit()).status, 200); // reset at 250ms → still valid
    await delay(250);
    // 500ms since login but only 250ms since last hit — sliding keeps it alive.
    assert.equal((await hit()).status, 200);
    await delay(650); // idle well past the 400ms TTL
    assert.equal((await hit()).status, 401); // expired
  } finally {
    await s.stop();
  }
});
