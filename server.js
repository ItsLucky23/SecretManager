// server.js — HTTP server: routing, sessions, /login, /resolve, /keys, admin pages.
// Node built-ins only (http, crypto, fs). No framework.

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash, timingSafeEqual } from 'node:crypto';
import { Store, isValidBaseName } from './store.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, 'public');
const BODY_LIMIT = 1024 * 1024; // 1 MB — payloads are tiny.
const DEFAULT_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Thrown by readJsonBody for malformed / oversized bodies → 400 bad_request. */
class BodyError extends Error {}

function sendJson(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}

function sendError(res, status, code, message) {
  sendJson(res, status, { error: message, code });
}

function setCors(res) {
  // The admin pages may be served from a different origin than the API. This API
  // is token/session-gated and cookie-less, so the bearer credential — not the
  // origin — is the real gate; permissive CORS is safe.
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Max-Age', '600');
}

/** Constant-time string compare that doesn't leak length. */
function safeEqual(a, b) {
  const ha = createHash('sha256').update(String(a)).digest();
  const hb = createHash('sha256').update(String(b)).digest();
  return timingSafeEqual(ha, hb);
}

/** Extract the `Bearer <value>` credential from the Authorization header, or null. */
function bearer(req) {
  const header = req.headers['authorization'];
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return null;
  return header.slice('Bearer '.length);
}

async function readJsonBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > BODY_LIMIT) throw new BodyError('Request body too large');
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new BodyError('Invalid JSON body');
  }
}

async function serveFile(res, filePath, contentType) {
  const data = await readFile(filePath);
  res.writeHead(200, { 'content-type': contentType });
  res.end(data);
}

/**
 * Build the HTTP server.
 * - `token`         — the shared secret. Client apps use it directly on /resolve;
 *                     admins exchange it at /login for a session.
 * - `dataFile`      — JSON store path.
 * - `sessionTtlMs`  — admin session lifetime; the TTL slides on each /keys request.
 */
export function createSecretManagerServer({ token, dataFile, sessionTtlMs = DEFAULT_SESSION_TTL_MS }) {
  if (!token) throw new Error('token is required');
  const store = new Store(dataFile);

  // In-memory admin sessions: sessionId (client-generated UUID v4) -> { timer }.
  // The timer reference, linked from the session id, lets us reset (slide) the TTL
  // on each authorized request. unref() so pending timers never block process exit.
  const sessions = new Map();
  function touchSession(sessionId) {
    const existing = sessions.get(sessionId);
    if (existing) clearTimeout(existing.timer);
    const timer = setTimeout(() => sessions.delete(sessionId), sessionTtlMs);
    if (typeof timer.unref === 'function') timer.unref();
    sessions.set(sessionId, { timer });
  }
  function dropSession(sessionId) {
    const existing = sessions.get(sessionId);
    if (existing) clearTimeout(existing.timer);
    sessions.delete(sessionId);
  }
  // Validate the bearer session and, if valid, slide its TTL. Returns the id or null.
  function sessionOf(req) {
    const sessionId = bearer(req);
    if (!sessionId || !sessions.has(sessionId)) return null;
    touchSession(sessionId);
    return sessionId;
  }

  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
      const { pathname } = url;
      const method = req.method;

      setCors(res);
      // CORS preflight carries no Authorization header — answer before any auth.
      if (method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      // --- Public static pages (no secrets; the editor self-gates client-side) ---
      if (method === 'GET' && (pathname === '/' || pathname === '/index.html' || pathname === '/login')) {
        return await serveFile(res, join(PUBLIC_DIR, 'login.html'), 'text/html; charset=utf-8');
      }
      if (method === 'GET' && (pathname === '/editor' || pathname === '/editor.html')) {
        return await serveFile(res, join(PUBLIC_DIR, 'editor.html'), 'text/html; charset=utf-8');
      }

      // --- POST /login — exchange the shared token for a session UUID ---
      if (method === 'POST' && pathname === '/login') {
        const body = await readJsonBody(req);
        if (typeof body.sessionId !== 'string' || !UUID_V4.test(body.sessionId)) {
          return sendError(res, 400, 'bad_request', 'sessionId must be a v4 UUID');
        }
        if (typeof body.token !== 'string' || !safeEqual(body.token, token)) {
          return sendError(res, 401, 'unauthorized', 'Invalid token');
        }
        touchSession(body.sessionId);
        return sendJson(res, 200, { ok: true, ttlMs: sessionTtlMs });
      }

      // --- POST /logout — end a session ---
      if (method === 'POST' && pathname === '/logout') {
        const sessionId = bearer(req);
        if (sessionId) dropSession(sessionId);
        return sendJson(res, 200, { ok: true });
      }

      // --- POST /resolve — client apps, raw shared token (no session) ---
      if (method === 'POST' && pathname === '/resolve') {
        const presented = bearer(req);
        if (presented === null || !safeEqual(presented, token)) {
          return sendError(res, 401, 'unauthorized', 'Missing or invalid bearer token');
        }
        const body = await readJsonBody(req);
        if (!Array.isArray(body.keys)) {
          return sendError(res, 400, 'bad_request', '"keys" must be an array of pointer strings');
        }
        const pointers = body.keys.filter((k) => typeof k === 'string');
        return sendJson(res, 200, { values: store.resolve(pointers) });
      }

      // --- Admin /keys — session (UUID) auth; each hit slides the TTL ---
      if (pathname === '/keys' && (method === 'GET' || method === 'POST')) {
        if (!sessionOf(req)) {
          return sendError(res, 401, 'unauthorized', 'No valid session — log in again');
        }
        if (method === 'GET') {
          return sendJson(res, 200, { keys: store.listMasked() });
        }
        const body = await readJsonBody(req);
        if (!isValidBaseName(body.name)) {
          return sendError(
            res,
            400,
            'bad_request',
            'name must match ^[A-Z0-9_]+$ and must not end in _V<n>',
          );
        }
        if (typeof body.value !== 'string' || body.value.length === 0) {
          return sendError(res, 400, 'bad_request', 'value must be a non-empty string');
        }
        return sendJson(res, 201, store.addVersion(body.name, body.value));
      }

      // --- POST /reveal — return ONE real value on demand (session auth) ---
      if (method === 'POST' && pathname === '/reveal') {
        if (!sessionOf(req)) {
          return sendError(res, 401, 'unauthorized', 'No valid session — log in again');
        }
        const body = await readJsonBody(req);
        const { name, version } = body;
        if (typeof name !== 'string' || (typeof version !== 'number' && typeof version !== 'string')) {
          return sendError(res, 400, 'bad_request', 'name (string) and version are required');
        }
        const value = store.getValue(name, version);
        if (value === undefined) {
          return sendError(res, 404, 'unknown_key', 'No such key/version');
        }
        return sendJson(res, 200, { name, version: Number(version), value });
      }

      return sendError(res, 404, 'unknown_key', 'Not found');
    } catch (err) {
      if (err instanceof BodyError) {
        return sendError(res, 400, 'bad_request', err.message);
      }
      console.error(err);
      return sendError(res, 500, 'internal', 'Internal server error');
    }
  });
}

// Optionally load a .env that sits next to this file. Node does not read .env
// automatically — without this, `node server.js` only sees real env vars.
// Variables already set in the real environment take precedence.
const ENV_FILE = join(__dirname, '.env');
if (existsSync(ENV_FILE)) process.loadEnvFile(ENV_FILE);

const TOKEN = process.env.SECRET_MANAGER_TOKEN;
if (!TOKEN) {
  console.error('FATAL: SECRET_MANAGER_TOKEN is not set. Refusing to start.');
  process.exit(1);
}
const PORT = Number(process.env.PORT) || 4000;
const HOST = process.env.HOST || '127.0.0.1';
const DATA_FILE = process.env.DATA_FILE || join(__dirname, 'data.json');
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS) || DEFAULT_SESSION_TTL_MS;

const server = createSecretManagerServer({
  token: TOKEN,
  dataFile: DATA_FILE,
  sessionTtlMs: SESSION_TTL_MS,
});
server.listen(PORT, HOST, () => {
  console.log(`Secret manager listening on http://${HOST}:${PORT}`);
  console.log(`Store: ${DATA_FILE}`);
  console.log(`Session TTL: ${SESSION_TTL_MS} ms`);
});
