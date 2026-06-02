# luckystack-secret-manager

A tiny secret manager: a zero-dependency Node.js HTTP server plus a static admin UI (a login page and
an editor page). Secrets are stored as **append-only, versioned** entries. Client apps authenticate to
`POST /resolve` with one shared bearer token; admins log in with that token and get a short-lived
**session** that protects the editor.

## The pointer model

Client apps commit their `.env` to git — but instead of real secrets, `.env` holds **pointers**:

```
OPENAI_KEY=OPENAI_AUTHORIZATION_KEY_V5
STRIPE_KEY=STRIPE_SECRET_KEY_V2
```

A pointer has the shape `<BASE_NAME>_V<number>`. At boot, a client sends the pointers it references to
`POST /resolve` and gets back the real values. **Rotating a secret means publishing a new version**
(`..._V6`) — never editing an old one — so old git branches that still point at `..._V5` keep working.

## Quickstart

Requires Node.js `>=20.12` (for the built-in `.env` auto-load; earlier `20.x` works too if you pass
the vars as real environment variables instead of relying on `.env`).

1. **Set a token** (any long random string):

   ```bash
   cp .env.example .env
   # generate one:
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

2. **Start the server:**

   ```bash
   node server.js          # or: npm start
   ```

   On startup the server reads the `.env` next to `server.js` (via Node's built-in
   `process.loadEnvFile` — no dotenv dependency), so the values from step 1 are picked up
   automatically. Real environment variables, if set, take precedence over the `.env` file:

   ```bash
   # bash — inline env vars override .env
   SECRET_MANAGER_TOKEN=<long-random> PORT=4000 node server.js
   ```

   ```powershell
   # Windows PowerShell — inline `VAR=value node ...` does NOT work; set vars first, or just
   # rely on .env and run `node server.js`.
   $env:SECRET_MANAGER_TOKEN="<long-random>"; $env:PORT="4000"; node server.js
   ```

   `SECRET_MANAGER_TOKEN` is required — the server refuses to start without it (whether from `.env`
   or the environment). It binds to `127.0.0.1` by default. To expose it beyond localhost, set
   `HOST=0.0.0.0` (and put it behind TLS / a reverse proxy — the token is the only thing protecting
   your secrets).

3. **Log in and add a secret:** open <http://127.0.0.1:4000>. You land on the **login page** — paste
   the auth token and click **Log in**. The browser generates a session UUID, sends it with the token,
   and on success forwards you to the **editor** at `/editor`. There, use the **Add secret / new
   version** form: a brand-new `BASE_NAME` creates version 1, an existing one appends the next version
   (the server picks the number). The keys table shows masked values (`••••••`) by default; click the
   **eye** next to a version to fetch and reveal that single value on demand (via `POST /reveal`), and
   click again to hide it. **Log out** ends the session immediately.

   > **Backend URL is fixed in code.** The pages send requests to a `BACKEND_URL` constant at the top
   > of the `<script>` in `public/login.html` and `public/editor.html` (it defaults to the origin that
   > served the page). If you host the pages somewhere other than the backend, hardcode the real
   > backend there, e.g. `const BACKEND_URL = 'http://127.0.0.1:4000'`. Error messages always show the
   > URL currently in use. A `405 Method Not Allowed` in the UI almost always means `BACKEND_URL`
   > points at the wrong server (a static host that rejects `POST`). The server enables permissive CORS
   > so a cross-origin admin page can reach it; this is safe because every endpoint is gated by the
   > token/session and there are no cookies.

## Resolving secrets (client side)

`POST /resolve` is the only endpoint client apps call, and the only place real values leave the server:

```bash
curl -s http://127.0.0.1:4000/resolve \
  -H "Authorization: Bearer $SECRET_MANAGER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"keys":["OPENAI_AUTHORIZATION_KEY_V5","STRIPE_SECRET_KEY_V2"]}'
```

```json
{ "values": { "OPENAI_AUTHORIZATION_KEY_V5": "sk-current...", "STRIPE_SECRET_KEY_V2": "rk-..." } }
```

Pointers that don't resolve are **omitted** from `values` (the client decides whether a missing pointer
is fatal) — the batch is never failed wholesale.

## Admin auth & sessions

The editor is not protected by the raw token — it uses a **session**:

1. The browser generates a **UUID v4** and `POST`s it to `/login` together with the token.
2. If the token matches, the server stores that UUID **in memory** with a TTL timer (`SESSION_TTL_MS`,
   default 7 days) and returns `{ ok: true, ttlMs }`. The browser keeps the UUID in `localStorage`.
3. Every admin request (`GET`/`POST` on `/keys`) authenticates with `Authorization: Bearer <uuid>` and
   **slides the TTL** — the timer is reset to the full lifetime on each request, so an active session
   never expires while in use. An idle session is dropped after the TTL; `POST /logout` drops it at once.

Sessions live only in memory, so a server restart invalidates them (the browser is bounced back to the
login page on the next `401`). `POST /resolve` is unaffected by all of this — client apps keep using the
shared token directly.

## API

All bodies are JSON. Errors have the shape `{ "error": string, "code": string }` with codes
`unauthorized` (401), `bad_request` (400), `unknown_key` (404), `internal` (500).

| Method & path   | Auth          | Purpose                                                              |
| --------------- | ------------- | ------------------------------------------------------------------- |
| `GET /`         | none          | Login page.                                                         |
| `GET /editor`   | none*         | Editor page (\*self-gates client-side; redirects to login if no session). |
| `POST /login`   | token in body | `{token, sessionId}` → creates a session. Wrong token → 401.        |
| `POST /logout`  | session       | Ends the session named by the bearer UUID.                          |
| `POST /resolve` | shared token  | Batch-resolve pointers → real values. The only endpoint clients call. |
| `GET /keys`     | session       | Admin listing of base names + versions, **masked**. Slides the TTL. |
| `POST /keys`    | session       | Create a base name (v1) or append the next version. Slides the TTL. Body `{name,value}`. |
| `POST /reveal`  | session       | Return ONE real value on demand (the editor's eye toggle). Body `{name,version}`; missing → 404. |

`POST /keys` validates that `name` matches `^[A-Z0-9_]+$` and does not end in the reserved `_V<n>`
suffix, and that `value` is a non-empty string.

## Storage

A single `data.json` on disk (gitignored, created on first write):

```json
{
  "OPENAI_AUTHORIZATION_KEY": { "1": "sk-old...", "5": "sk-current..." },
  "STRIPE_SECRET_KEY":        { "1": "rk-...",    "2": "rk-..." }
}
```

Existing versions are **immutable** — there is no edit or delete endpoint, and the next version is
always `max(existing) + 1`. Writes are atomic (temp file + rename) so a crash mid-write can't corrupt
the file.

## Tests

```bash
npm test
# or directly:
node --test "test/**/*.test.js"
```

Covers: the append-only invariant, login/sessions, sliding-TTL expiry, admin auth enforcement, resolve
mapping (including omitted unknown pointers), masking, on-demand reveal, request validation, logout,
and CORS.
