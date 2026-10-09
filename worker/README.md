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

Runs on `api.lingua-bridge.us` (its own subdomain) so the main site's
existing GitHub Pages DNS records are never touched.

## Scope

Founder login only, on purpose. Real student accounts are a separate,
not-yet-decided piece of work (credential type — email, username, or
school+student code — hasn't been chosen yet).

## Deploying / updating this Worker

1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Create Worker**.
   Name it `linguabridge-api`.
2. Open the Worker → **Edit code** → replace the default code with the
   contents of `src/index.js` in this folder → **Deploy**.
3. Worker → **Settings** → **Bindings** → **Add binding** → **D1 Database**:
   - Variable name: `DB`
   - Database: `linguabridge`
4. Worker → **Settings** → **Domains & Routes** → **Add** → **Custom Domain**:
   `api.lingua-bridge.us` (Cloudflare creates the DNS record and certificate
   automatically).

To update the API later: edit `src/index.js` in this repo, then paste the
updated code into the same Worker's **Edit code** screen and **Deploy**
again.

## Database

D1 database name: `linguabridge`
Tables: `users` (id, username, password_hash, password_salt, iterations,
role, created_at), `sessions` (token, user_id, created_at, expires_at).
