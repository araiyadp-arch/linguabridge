# LinguaBridge Auth API (Cloudflare Worker)

Real backend authentication for the founder account, replacing the old
client-side-only login gate. Source of truth lives here in the repo;
deployed by hand into the Cloudflare dashboard (see steps below) since
no CLI/deploy tool was available when this was built.

## What it does

- `POST /api/login` — checks username/password against the `linguabridge`
  D1 database (passwords are PBKDF2-hashed, never stored in plaintext),
  and sets an `httpOnly` session cookie on success.
- `GET /api/me` — tells the frontend whether the current visitor has a
  valid session.
- `POST /api/logout` — ends the session.
- `POST /api/ask-bridge` — "Ask Bridge": a student types a question, Bridge
  answers it using Cloudflare Workers AI. Scoped to kid-safe English-learning
  topics by a strict system prompt, rate-limited per visitor, and every
  exchange is logged to D1 so the founder can review what's being asked.
  Not behind the founder login (the lesson pages aren't login-gated yet
  either — see Scope below), so its safety comes from the prompt + rate
  limit, not from an account wall.

Runs on `api.lingua-bridge.us` (its own subdomain) so the main site's
existing GitHub Pages DNS records are never touched.

## Scope

Founder login only, on purpose. Real student accounts are a separate,
not-yet-decided piece of work (credential type — email, username, or
school+student code — hasn't been chosen yet). Because of that, the lesson
pages themselves (lesson/quiz/video/badge/see-you-tomorrow) are currently
reachable without logging in — only the dashboard checks `/api/me`. Ask
Bridge inherits that same "no real gate yet" reality, which is why its
safety has to live in the system prompt and the rate limit rather than in
"only logged-in students can use it."

## Deploying / updating this Worker

1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Create Worker**.
   Name it `linguabridge-api`. (Skip this step if the Worker already exists —
   just go straight to editing its code.)
2. Open the Worker → **Edit code** → replace the code with the contents of
   `src/index.js` in this folder → **Deploy**.
3. Worker → **Settings** → **Bindings** → **Add binding**, three of them:
   - **D1 Database** — variable name `DB`, database `linguabridge`
   - **Workers AI** — variable name `AI` (no extra setup; it's built into
     every Cloudflare account, nothing to create first)
   - **KV Namespace** — variable name `RATE_LIMIT`, namespace
     `linguabridge-ask-bridge-ratelimit`
4. Domain routing (`api.lingua-bridge.us` → this Worker): the dashboard's
   **Domains & Routes → Add → Custom Domain** flow didn't work for this zone
   (it errored with "No zones match" even though the zone is active). What
   actually worked: **Cloudflare dashboard → your domain → Workers Routes →
   Add route** → route `api.lingua-bridge.us/*` → service `linguabridge-api`.
   That also needs a DNS A record for `api` pointing at `192.0.2.1` with
   **Proxied** (orange cloud) turned on — Workers Routes only intercept
   traffic that's already proxied through Cloudflare; the IP itself is never
   actually used; Cloudflare intercepts the request before it gets there.

To update the API later: edit `src/index.js` in this repo, then paste the
updated code into the same Worker's **Edit code** screen and **Deploy**
again.

## Database

D1 database name: `linguabridge`
Tables:
- `users` (id, username, password_hash, password_salt, iterations, role, created_at)
- `sessions` (token, user_id, created_at, expires_at)
- `bridge_questions` (id, client_id, question, answer, level, lesson_topic,
  flagged, created_at) — a log of every Ask Bridge exchange, for the founder
  to review. `flagged` isn't set automatically by anything yet; it's there
  for manual review use (e.g. mark a row 1 while going through the log).
