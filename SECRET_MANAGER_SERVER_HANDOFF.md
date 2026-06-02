# Secret Manager Server — Build Handoff (external repo)

> Self-contained spec. Hand this whole file to the AI that builds the **separate** repo
> `luckystack-secret-manager`. It does NOT depend on the LuckyStack codebase — build it standalone.

---

## 1. What you're building

A tiny **secret manager**: a Node.js HTTP server + a single static admin webpage. It stores secret
values as **append-only versioned entries** and serves them to client apps that authenticate with one
shared bearer token.

### The pointer model (the reason this exists)

Client apps keep their `.env` committed to git. Instead of real secrets, `.env` holds **pointers**:

```
OPENAI_KEY=OPENAI_AUTHORIZATION_KEY_V5
STRIPE_KEY=STRIPE_SECRET_KEY_V2
```

A pointer has the shape `<BASE_NAME>_V<number>`. At boot the client app sends the list of pointers it
references to this server's `/resolve` endpoint and gets back the real values. Rotating a secret means
**publishing a new version** (`..._V6`) — never editing an old one — so old git branches that still
point at `..._V5` keep working.

**Your server owns:** storage, versioning (append-only), the resolve endpoint, the admin endpoints, and
the admin webpage. Nothing about LuckyStack leaks into this repo; any framework can be a client.

---

## 2. Stack & constraints

- **Runtime:** Node.js `>=20` (uses built-in `http` + `fetch`; no Express).
- **Dependencies:** zero or near-zero. Storage is a plain JSON file. No DB.
- **Frontend:** one static `index.html` served by the same server. Tailwind via CDN `<script>` — **no
  build step**, no bundler, no framework. Plain HTML + vanilla JS.
- **Keep it simple** — this is intentionally a small tool.

---

## 3. Data model — append-only JSON

Single file `data.json` on disk:

```json
{
  "OPENAI_AUTHORIZATION_KEY": { "1": "sk-old...", "5": "sk-current..." },
  "STRIPE_SECRET_KEY":        { "1": "rk-...",    "2": "rk-..." }
}
```

- Top-level keys = **base names**. Values = `{ "<version>": "<secret>" }`.
- **Append-only invariant (enforced server-side):** an existing `version` is immutable. Adding a value
  to a base name creates `max(existingVersions) + 1`. First value for a new base name → version `1`.
- **No edit, no delete** endpoints. (Retiring old versions is out of scope; add later if needed.)
- Write atomically (write to a temp file, then rename) so a crash mid-write can't corrupt `data.json`.

---

## 4. Auth

- Single shared token from env var `SECRET_MANAGER_TOKEN`.
- **Every** endpoint (resolve + admin) requires header `Authorization: Bearer <SECRET_MANAGER_TOKEN>`.
- Missing/wrong token → `401` with body `{ "error": "...", "code": "unauthorized" }`.
- Use a constant-time comparison for the token check.

---

## 5. HTTP endpoints

All requests/responses are JSON. Error body shape everywhere: `{ "error": string, "code": string }`.
Codes: `unauthorized` (401), `bad_request` (400), `unknown_key` (404), `internal` (500).

### 5.1 `POST /resolve` — the ONLY endpoint client apps call

Resolve a batch of pointers in one request. Called by the app at boot, and again on dev file-change /
poll.

**Request**
```json
{ "keys": ["OPENAI_AUTHORIZATION_KEY_V5", "STRIPE_SECRET_KEY_V2"] }
```

**Response 200**
```json
{ "values": { "OPENAI_AUTHORIZATION_KEY_V5": "sk-current...", "STRIPE_SECRET_KEY_V2": "rk-..." } }
```

- For each requested pointer: split the trailing `_V<n>` → `base` + `version`, look up
  `data[base][version]`.
- Pointers that don't resolve are **omitted** from `values` (the client decides whether a missing
  pointer is fatal). Do not 404 the whole batch.
- Returns **real** values — this endpoint is the only place secrets leave the server.

### 5.2 `GET /keys` — admin list (masked)

Powers the admin table. **Never returns real values.**

**Response 200**
```json
{
  "keys": [
    { "name": "OPENAI_AUTHORIZATION_KEY", "versions": [ { "version": 1, "masked": "••••••" }, { "version": 5, "masked": "••••••" } ] },
    { "name": "STRIPE_SECRET_KEY",        "versions": [ { "version": 1, "masked": "••••••" }, { "version": 2, "masked": "••••••" } ] }
  ]
}
```

- `masked` is a fixed placeholder (e.g. `"••••••"`). Do not derive it from the real value (no length
  leak, no last-4 chars).

### 5.3 `POST /keys` — admin create / append version

Create a new base name (version 1) OR append the next version to an existing one.

**Request**
```json
{ "name": "OPENAI_AUTHORIZATION_KEY", "value": "sk-new..." }
```

**Response 201**
```json
{ "name": "OPENAI_AUTHORIZATION_KEY", "version": 6 }
```

- Server computes the next version automatically. Caller never picks the version number.
- Validate `name` matches `^[A-Z0-9_]+$` and does **not** itself end in `_V<n>` (the version suffix is
  reserved). Reject with `400 bad_request` otherwise.
- `value` must be a non-empty string.

---

## 6. Admin frontend (`index.html`, served at `GET /`)

Single page, plain HTML + vanilla JS, Tailwind via `<script src="https://cdn.tailwindcss.com"></script>`.

Must have:
1. **Token field** — input where the operator pastes the shared token; persist in `sessionStorage`.
   Sent as `Authorization: Bearer <token>` on every fetch.
2. **Add-secret form** — `name` input + `value` input + submit → `POST /keys`. After success, refresh
   the table. One form handles both "new key" and "new version of existing key" (server decides).
3. **Keys table** — `GET /keys` → one group per base name, a row per version showing `version` and a
   **masked** value (`••••••`, rendered password-style). No reveal button — real values never reach the
   browser.
4. Basic feedback on 401 (prompt to re-enter token) and on validation errors.

Keep styling minimal but clean (a centered card, a table). No SPA framework.

---

## 7. Suggested repo layout

```
luckystack-secret-manager/
  server.js          # http server: routing, auth, /resolve, /keys
  store.js           # load/save data.json, append-only nextVersion logic, masking
  public/index.html  # admin UI (Tailwind CDN)
  data.json          # created on first write (gitignored)
  .gitignore         # data.json, .env
  .env.example       # SECRET_MANAGER_TOKEN=, PORT=4000
  package.json       # type:module, start script
  README.md          # quickstart
  test/store.test.js # minimal tests (see §9)
```

---

## 8. Run

```
SECRET_MANAGER_TOKEN=<long-random> PORT=4000 node server.js
```

- `PORT` defaults to `4000` if unset. Bind to `127.0.0.1` by default; document how to expose it.
- README must cover: setting the token, adding a secret via the UI, and a `curl` example of `/resolve`.

---

## 9. Minimal tests (must pass)

1. **Append-only:** adding a value to an existing key creates `max+1`; the previous version's value is
   unchanged; no endpoint can overwrite an existing version.
2. **Auth:** any endpoint without/with a wrong Bearer token → `401 unauthorized`.
3. **Resolve mapping:** `POST /resolve` with `["FOO_V2"]` returns `data["FOO"]["2"]`; an unknown pointer
   is omitted from `values`.
4. **Masking:** `GET /keys` never includes a real value; `masked` is the fixed placeholder.
5. **Validation:** `POST /keys` rejects a `name` ending in `_V<n>` and an empty `value` with `400`.

---

## 10. Acceptance checklist

- [ ] `POST /resolve` batch-resolves pointers; only place real values are returned.
- [ ] `GET /keys` lists base names + versions, masked.
- [ ] `POST /keys` appends the next version; never overwrites; auto-increments.
- [ ] All endpoints enforce the shared bearer token.
- [ ] `data.json` writes are atomic and append-only.
- [ ] Admin page works with Tailwind CDN, no build step; values shown masked.
- [ ] README quickstart + `.env.example` + the 5 tests present and passing.

---

## Appendix — client side (for your awareness; built in the LuckyStack repo, not here)

The client (`@luckystack/secret-manager`) at app boot: scans `process.env` for values matching
`^(.+)_V(\d+)$`, sends those pointer strings to `POST /resolve`, then overwrites each `process.env`
entry with the resolved value (so `OPENAI_KEY` ends up holding the real secret, not the pointer). You
do **not** build this — just keep the `/resolve` contract in §5.1 stable.
