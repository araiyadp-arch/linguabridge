/**
 * LinguaBridge Auth API (Cloudflare Worker)
 * ------------------------------------------------------------------
 * Real backend authentication, replacing the old client-side placeholder
 * lock. As of 2026-10-30: public signup is open. A parent creates an
 * account with a real email+password; a parent can then create one or
 * more child logins (username + PIN, no email) under their account. Both
 * parent and child accounts are just rows in the `users` table
 * (role='parent'/'student', `parent_id` set on children, `email` set on
 * parents only) so the existing login/me/logout code below needed no
 * changes to support either kind of account.
 *
 * Runs on its own subdomain (api.lingua-bridge.us) so the main site's
 * existing GitHub Pages DNS is never touched. Cross-origin calls from
 * lingua-bridge.us use CORS + credentials:"include".
 *
 * Endpoints:
 *   POST /api/login       { username, password } -> sets httpOnly session cookie
 *   GET  /api/me                                  -> { authenticated, username, role }
 *   POST /api/logout                              -> clears session cookie
 *   POST /api/signup      { email, password } -> creates a PARENT account,
 *        sets session cookie. Parents sign up with a real email+password;
 *        kids never do (see /api/children below) — this keeps the site's
 *        direct collection of personal info from children to a minimum
 *        (COPPA consideration, 2026-10-30).
 *   GET  /api/children                          -> list of the signed-in
 *        parent's children ({id, username, created_at} only — no hash/salt)
 *   POST /api/children    { username, pin } -> creates a CHILD login under
 *        the signed-in parent (no email collected from the child at all).
 *        Both require a valid parent session cookie.
 *   GET/POST /api/progress -> per-user lesson progress saved to D1 (see
 *        "Progress saving" section below), added 2026-11-05.
 *   POST /api/ask-bridge  { question, level?, lessonTopic? } -> { answer }
 *        "Ask Bridge" — lets a student type a question to Bridge and get a
 *        real answer, using Cloudflare Workers AI (no external API key
 *        needed). Scoped to kid-safe topics by the system prompt below;
 *        unlimited (no rate limit — the founder wants the kid<->Bridge
 *        chat to never be interrupted); every exchange is logged to D1
 *        (bridge_questions) so the founder can review what kids are
 *        actually asking/getting. NOT behind the founder login — the
 *        lesson pages themselves aren't login-gated yet either (no real
 *        student accounts exist), so this endpoint's safety has to come
 *        from the system prompt alone, not from "only logged-in users can
 *        reach it."
 *
 * Account safety (2026-11-05, founder request): signup needs an INVITE CODE the
 * founder creates, and every new parent account starts as 'pending' until the
 * founder approves it (admin endpoints /api/admin/*, founder only). Logins are
 * rate-limited and locked out after repeated wrong tries (table auth_limits).
 * Passwords need 10+ characters. Child logins only work while their parent is
 * approved. Ask Bridge now requires a signed-in account. Tables/columns used:
 * users.status ('approved'|'pending'|'disabled'), users.invite_code,
 * invite_codes, auth_limits (already created in D1).
 *
 * Bindings required (set in the Cloudflare dashboard when creating the Worker):
 *   DB -> the "linguabridge" D1 database
 *   AI -> Workers AI (Settings -> Bindings -> Add -> Workers AI; no extra
 *         setup/account needed, it's built into Cloudflare)
 *
 * Deployed by pasting this file into the Cloudflare dashboard's Worker
 * editor (no CLI/deploy tool was available when this was built), binding
 * the D1 database, and adding api.lingua-bridge.us as a custom domain
 * for the Worker.
 * ------------------------------------------------------------------ */

const SESSION_COOKIE = "lb_session";
const SESSION_DAYS = 7;

// Only these origins are allowed to call this API with credentials.
const ALLOWED_ORIGINS = [
  "https://lingua-bridge.us",
  "https://www.lingua-bridge.us",
];

function corsHeaders(request) {
  const origin = request.headers.get("Origin");
  const headers = {};
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Credentials"] = "true";
    headers["Vary"] = "Origin";
  }
  return headers;
}

function jsonResponse(data, status, request, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      ...corsHeaders(request),
      ...extraHeaders,
    },
  });
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : null;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Must match the PBKDF2 parameters used when the founder account was seeded:
// SHA-256, dklen=32 bytes.
async function verifyPassword(password, saltHex, iterations, expectedHashHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: hexToBytes(saltHex),
      iterations: iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    32 * 8
  );
  const derivedHex = bytesToHex(new Uint8Array(derivedBits));

  if (derivedHex.length !== expectedHashHex.length) return false;
  let diff = 0;
  for (let i = 0; i < derivedHex.length; i++) {
    diff |= derivedHex.charCodeAt(i) ^ expectedHashHex.charCodeAt(i);
  }
  return diff === 0;
}

// Same PBKDF2 parameters as verifyPassword above (SHA-256, dklen=32 bytes,
// 100000 iterations — matches the founder account already in D1), used for
// both parent passwords and child PINs: a PIN is just stored and checked
// exactly like a password, reusing the existing login code path unchanged.
const HASH_ITERATIONS = 100000;

async function hashPassword(password) {
  const enc = new TextEncoder();
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: HASH_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    32 * 8
  );
  return {
    hash: bytesToHex(new Uint8Array(derivedBits)),
    salt: bytesToHex(saltBytes),
    iterations: HASH_ITERATIONS,
  };
}

function setSessionCookieHeaders(token) {
  return {
    "Set-Cookie": [
      `${SESSION_COOKIE}=${token}`,
      "Path=/",
      "HttpOnly",
      "Secure",
      "SameSite=None",
      `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`,
    ].join("; "),
  };
}

async function createSession(env, userId) {
  const token = crypto.randomUUID() + crypto.randomUUID();
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  await env.DB.prepare(
    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
  )
    .bind(token, userId, expiresAt.toISOString())
    .run();
  return token;
}

// Looks up the signed-in user for this request (via the session cookie),
// or null if there isn't a valid one. Shared by the /api/children endpoints
// so they can require a real parent session before touching child accounts.
async function getSessionUser(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT users.id as id, users.username as username, users.role as role, sessions.expires_at as expires_at
     FROM sessions JOIN users ON users.id = sessions.user_id
     LEFT JOIN users p ON p.id = users.parent_id
     WHERE sessions.token = ? AND users.status = 'approved' AND (p.id IS NULL OR p.status = 'approved')`
  )
    .bind(token)
    .first();
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return null;
  }
  return row;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// Kid-chosen usernames: letters/numbers only, 3-20 chars, so they're easy
// for a young child to type and never look like an email address.
const CHILD_USERNAME_RE = /^[a-zA-Z0-9]{3,20}$/;
// PIN, not a password: numeric only, 4-6 digits — quick for a young child
// to enter, stored/verified exactly like a password hash underneath.
const CHILD_PIN_RE = /^[0-9]{4,6}$/;

// ---------- Safety helpers (2026-11-05) ----------
const COMMON_PASSWORDS = new Set(["password","password1","password123","1234567890","123456789","12345678","qwertyuiop","qwerty123","iloveyou","letmein123","welcome123","admin12345","abc123456","linguabridge","lingua-bridge","password12","passw0rd12"]);

function passwordProblem(password, email) {
  if (password.length < 10) return "Password must be at least 10 characters.";
  if (password.length > 200) return "That password is too long.";
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) return "Password needs at least one letter and one number.";
  const lower = password.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) return "That password is too easy to guess. Please pick another.";
  const local = (email || "").split("@")[0].toLowerCase();
  if (local.length >= 4 && lower.includes(local)) return "Password should not contain your email name.";
  return null;
}

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

// Simple fixed-window failure counter + lockout, stored in D1 (auth_limits).
async function isLocked(env, key) {
  const row = await env.DB.prepare("SELECT locked_until FROM auth_limits WHERE k = ?").bind(key).first();
  return !!row && row.locked_until > Date.now();
}
async function recordFailure(env, key, max, windowMs, lockMs) {
  const now = Date.now();
  const row = await env.DB.prepare("SELECT n, first_at FROM auth_limits WHERE k = ?").bind(key).first();
  let n = 1, first = now;
  if (row && now - row.first_at <= windowMs) { n = row.n + 1; first = row.first_at; }
  const locked = n >= max ? now + lockMs : 0;
  await env.DB.prepare(
    "INSERT INTO auth_limits (k, n, first_at, locked_until) VALUES (?, ?, ?, ?) ON CONFLICT(k) DO UPDATE SET n = excluded.n, first_at = excluded.first_at, locked_until = excluded.locked_until"
  ).bind(key, n, first, locked).run();
}
async function clearFailures(env, key) {
  await env.DB.prepare("DELETE FROM auth_limits WHERE k = ?").bind(key).run();
}

function normalizeInvite(raw) {
  return (raw || "").toString().toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 20);
}
function formatInvite(code) {
  return "LB-" + code.slice(0, 4) + "-" + code.slice(4, 8);
}

async function handleSignup(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "Invalid request body." }, 400, request);
  }

  const ip = clientIp(request);
  const ipKey = "signup:ip:" + ip;
  if (await isLocked(env, ipKey)) {
    return jsonResponse({ error: "Too many tries. Please wait an hour and try again." }, 429, request);
  }

  const email = (body.email || "").toString().trim().toLowerCase();
  const password = (body.password || "").toString();
  // Stored without the "LB-" prefix and dashes: "LB-ABCD-EFGH" -> "ABCDEFGH"
  let invite = normalizeInvite(body.invite);
  if (invite.startsWith("LB") && invite.length === 10) invite = invite.slice(2);

  if (!email || !EMAIL_RE.test(email) || email.length > 200) {
    return jsonResponse({ error: "Please enter a valid email address." }, 400, request);
  }
  const pwProblem = passwordProblem(password, email);
  if (pwProblem) {
    return jsonResponse({ error: pwProblem }, 400, request);
  }

  const now = Date.now();
  const codeRow = invite
    ? await env.DB.prepare(
        "SELECT code, label, max_uses, uses, expires_at, active FROM invite_codes WHERE code = ?"
      ).bind(invite).first()
    : null;
  const codeOk = !!codeRow && codeRow.active === 1 && codeRow.uses < codeRow.max_uses &&
    (codeRow.expires_at == null || codeRow.expires_at > now);
  if (!codeOk) {
    await recordFailure(env, ipKey, 8, 60 * 60 * 1000, 60 * 60 * 1000);
    return jsonResponse(
      { error: "That invite code isn't valid or has expired. Please check it or ask the LinguaBridge founder for a new one." },
      403,
      request
    );
  }

  const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
  if (existing) {
    await recordFailure(env, ipKey, 8, 60 * 60 * 1000, 60 * 60 * 1000);
    return jsonResponse(
      { error: "An account with that email already exists. Try logging in instead." },
      409,
      request
    );
  }

  // Use up one invite slot atomically (so two people can't both use a single-use code).
  const used = await env.DB.prepare(
    "UPDATE invite_codes SET uses = uses + 1 WHERE code = ? AND active = 1 AND uses < max_uses AND (expires_at IS NULL OR expires_at > ?)"
  ).bind(invite, now).run();
  if (!used.meta || used.meta.changes !== 1) {
    return jsonResponse({ error: "That invite code isn't valid or has expired." }, 403, request);
  }

  const { hash, salt, iterations } = await hashPassword(password);
  const id = "usr_" + crypto.randomUUID();

  try {
    await env.DB.prepare(
      `INSERT INTO users (id, username, password_hash, password_salt, iterations, role, email, parent_id, status, invite_code)
       VALUES (?, ?, ?, ?, ?, 'parent', ?, NULL, 'pending', ?)`
    )
      .bind(id, email, hash, salt, iterations, email, invite)
      .run();
  } catch (e) {
    await env.DB.prepare("UPDATE invite_codes SET uses = MAX(uses - 1, 0) WHERE code = ?").bind(invite).run();
    return jsonResponse(
      { error: "An account with that email already exists. Try logging in instead." },
      409,
      request
    );
  }

  // No session is created: the account can't be used until the founder approves it.
  return jsonResponse({ pending: true }, 200, request);
}

async function handleListChildren(request, env) {
  const sessionUser = await getSessionUser(request, env);
  if (!sessionUser || sessionUser.role !== "parent") {
    return jsonResponse({ error: "You must be logged in as a parent." }, 401, request);
  }

  const result = await env.DB.prepare(
    "SELECT id, username, created_at FROM users WHERE parent_id = ? ORDER BY created_at ASC"
  )
    .bind(sessionUser.id)
    .all();

  return jsonResponse({ children: result.results || [] }, 200, request);
}

async function handleCreateChild(request, env) {
  const sessionUser = await getSessionUser(request, env);
  if (!sessionUser || sessionUser.role !== "parent") {
    return jsonResponse({ error: "You must be logged in as a parent." }, 401, request);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "Invalid request body." }, 400, request);
  }

  const username = (body.username || "").toString().trim();
  const pin = (body.pin || "").toString();

  if (!username || !CHILD_USERNAME_RE.test(username)) {
    return jsonResponse(
      { error: "Username must be 3-20 letters or numbers, no spaces or symbols." },
      400,
      request
    );
  }
  if (!pin || !CHILD_PIN_RE.test(pin)) {
    return jsonResponse(
      { error: "PIN must be 4 to 6 numbers." },
      400,
      request
    );
  }

  const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?")
    .bind(username)
    .first();
  if (existing) {
    return jsonResponse(
      { error: "That username is already taken. Try another one." },
      409,
      request
    );
  }

  const { hash, salt, iterations } = await hashPassword(pin);
  const id = "usr_" + crypto.randomUUID();

  try {
    await env.DB.prepare(
      `INSERT INTO users (id, username, password_hash, password_salt, iterations, role, email, parent_id)
       VALUES (?, ?, ?, ?, ?, 'student', NULL, ?)`
    )
      .bind(id, username, hash, salt, iterations, sessionUser.id)
      .run();
  } catch (e) {
    return jsonResponse(
      { error: "That username is already taken. Try another one." },
      409,
      request
    );
  }

  return jsonResponse({ id, username, created_at: new Date().toISOString() }, 200, request);
}

async function handleLogin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "Invalid request body." }, 400, request);
  }

  const username = (body.username || "").toString().trim().slice(0, 200);
  const password = (body.password || "").toString().slice(0, 200);

  if (!username || !password) {
    return jsonResponse(
      { error: "Username and password are required." },
      400,
      request
    );
  }

  // Lockouts: per person+device, per account (any device), and per device overall.
  const ip = clientIp(request);
  const uname = username.toLowerCase();
  const keyPair = "login:p:" + ip + ":" + uname;
  const keyUser = "login:u:" + uname;
  const keyIp = "login:i:" + ip;
  if ((await isLocked(env, keyPair)) || (await isLocked(env, keyUser)) || (await isLocked(env, keyIp))) {
    return jsonResponse(
      { error: "Too many tries. Please wait 15 minutes and try again.", locked: true },
      429,
      request
    );
  }
  const fail = async () => {
    await recordFailure(env, keyPair, 5, 15 * 60 * 1000, 15 * 60 * 1000);
    await recordFailure(env, keyUser, 20, 60 * 60 * 1000, 60 * 60 * 1000);
    await recordFailure(env, keyIp, 40, 15 * 60 * 1000, 15 * 60 * 1000);
  };

  const user = await env.DB.prepare(
    `SELECT u.id as id, u.username as username, u.password_hash as password_hash, u.password_salt as password_salt,
            u.iterations as iterations, u.role as role, u.status as status, p.status as parent_status
     FROM users u LEFT JOIN users p ON p.id = u.parent_id WHERE u.username = ?`
  )
    .bind(username)
    .first();

  // Same error for "no such user" and "wrong password" — don't leak which.
  if (!user) {
    await hashPassword(password); // keep timing similar to a real check
    await fail();
    return jsonResponse({ error: "Incorrect username or password." }, 401, request);
  }

  const ok = await verifyPassword(
    password,
    user.password_salt,
    user.iterations,
    user.password_hash
  );

  if (!ok) {
    await fail();
    return jsonResponse({ error: "Incorrect username or password." }, 401, request);
  }

  // Correct password, but the account may not be switched on yet.
  const parentWaiting = user.parent_status && user.parent_status !== "approved";
  if (user.status === "pending" || parentWaiting) {
    return jsonResponse(
      { error: "Your account is waiting for approval from the LinguaBridge founder. Please check back soon.", pending: true },
      403,
      request
    );
  }
  if (user.status !== "approved") {
    return jsonResponse({ error: "This account is not active. Please contact LinguaBridge." }, 403, request);
  }

  await clearFailures(env, keyPair);
  await clearFailures(env, keyUser);

  const token = await createSession(env, user.id);
  // Tidy up old expired sessions now and then (cheap, keeps the table small).
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(new Date().toISOString()).run();

  return jsonResponse(
    { authenticated: true, username: user.username, role: user.role },
    200,
    request,
    setSessionCookieHeaders(token)
  );
}

// ---------- Founder admin (approve accounts, make invite codes) ----------
async function requireFounder(request, env) {
  const u = await getSessionUser(request, env);
  return u && u.role === "founder" ? u : null;
}

async function readJson(request) {
  try { return await request.json(); } catch (e) { return null; }
}

async function handleAdminOverview(request, env) {
  if (!(await requireFounder(request, env))) return jsonResponse({ error: "Not allowed." }, 403, request);
  const pending = await env.DB.prepare(
    `SELECT u.id, u.email, u.created_at, i.label as invite_label
     FROM users u LEFT JOIN invite_codes i ON i.code = u.invite_code
     WHERE u.role = 'parent' AND u.status = 'pending' ORDER BY u.created_at ASC LIMIT 200`
  ).all();
  const approved = await env.DB.prepare(
    `SELECT u.id, u.email, u.status, u.created_at,
            (SELECT COUNT(*) FROM users c WHERE c.parent_id = u.id) as children
     FROM users u WHERE u.role = 'parent' AND u.status != 'pending' ORDER BY u.created_at DESC LIMIT 200`
  ).all();
  const invites = await env.DB.prepare(
    "SELECT code, label, max_uses, uses, expires_at, active FROM invite_codes ORDER BY created_at DESC LIMIT 100"
  ).all();
  return jsonResponse(
    {
      pending: pending.results || [],
      parents: approved.results || [],
      invites: (invites.results || []).map((r) => ({ ...r, code: formatInvite(r.code) })),
    },
    200,
    request
  );
}

async function handleAdminAction(request, env, action) {
  if (!(await requireFounder(request, env))) return jsonResponse({ error: "Not allowed." }, 403, request);
  const body = await readJson(request);
  if (!body) return jsonResponse({ error: "Invalid request body." }, 400, request);
  const id = (body.id || "").toString();

  if (action === "approve") {
    const r = await env.DB.prepare("UPDATE users SET status = 'approved' WHERE id = ? AND role = 'parent' AND status = 'pending'").bind(id).run();
    return jsonResponse({ ok: !!(r.meta && r.meta.changes) }, 200, request);
  }
  if (action === "reject") {
    // Only never-approved accounts can be rejected (deleted).
    await env.DB.prepare("DELETE FROM users WHERE id = ? AND role = 'parent' AND status = 'pending'").bind(id).run();
    return jsonResponse({ ok: true }, 200, request);
  }
  if (action === "disable" || action === "enable") {
    const status = action === "disable" ? "disabled" : "approved";
    await env.DB.prepare("UPDATE users SET status = ? WHERE id = ? AND role = 'parent'").bind(status, id).run();
    if (action === "disable") {
      await env.DB.prepare(
        "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE id = ? OR parent_id = ?)"
      ).bind(id, id).run();
    }
    return jsonResponse({ ok: true }, 200, request);
  }
  if (action === "invite") {
    const label = (body.label || "").toString().trim().slice(0, 80);
    const maxUses = Math.min(Math.max(parseInt(body.max_uses, 10) || 1, 1), 100);
    const days = Math.min(Math.max(parseInt(body.days, 10) || 14, 1), 90);
    const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    let code = "";
    for (const b of bytes) code += alphabet[b % alphabet.length];
    await env.DB.prepare(
      "INSERT INTO invite_codes (code, label, max_uses, uses, expires_at, active, created_at) VALUES (?, ?, ?, 0, ?, 1, ?)"
    ).bind(code, label, maxUses, Date.now() + days * 86400000, Date.now()).run();
    return jsonResponse({ code: formatInvite(code), max_uses: maxUses, days }, 200, request);
  }
  if (action === "revoke") {
    await env.DB.prepare("UPDATE invite_codes SET active = 0 WHERE code = ?").bind(normalizeInvite(body.code).replace(/^LB/, "")).run();
    return jsonResponse({ ok: true }, 200, request);
  }
  return jsonResponse({ error: "Not found." }, 404, request);
}

async function handleMe(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return jsonResponse({ authenticated: false }, 200, request);

  const row = await env.DB.prepare(
    `SELECT sessions.expires_at as expires_at, users.username as username, users.role as role
     FROM sessions JOIN users ON users.id = sessions.user_id
     LEFT JOIN users p ON p.id = users.parent_id
     WHERE sessions.token = ? AND users.status = 'approved' AND (p.id IS NULL OR p.status = 'approved')`
  )
    .bind(token)
    .first();

  if (!row) return jsonResponse({ authenticated: false }, 200, request);

  if (new Date(row.expires_at).getTime() < Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return jsonResponse({ authenticated: false }, 200, request);
  }

  return jsonResponse(
    { authenticated: true, username: row.username, role: row.role },
    200,
    request
  );
}

async function handleLogout(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
  }
  const cookie = [
    `${SESSION_COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
    "Max-Age=0",
  ].join("; ");
  return jsonResponse({ ok: true }, 200, request, { "Set-Cookie": cookie });
}

// ------------------------------------------------------------------
// Ask Bridge — a kid-safe Q&A chat, answered by Cloudflare Workers AI.
// ------------------------------------------------------------------

// NOTE: @cf/meta/llama-3.1-8b-instruct was deprecated by Cloudflare on
// 2026-05-30. Two reasoning models (glm-4.7-flash, then kimi-k2.6 with
// reasoning_effort) were tried next and both caused problems — reasoning
// models are the wrong shape for a simple kid-chat that needs a fast,
// direct answer. Settled on a plain (non-reasoning) fast instruct model,
// which also uses the simpler { response } output format.
const ASK_BRIDGE_MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const ASK_BRIDGE_MAX_QUESTION_LEN = 300;

// This system prompt is the actual safety boundary for this feature (see
// the big comment above). The founder asked for Bridge to answer general
// kid-appropriate questions, not just English-learning ones (2026-10-10) —
// so the topic restriction was widened. The hard child-safety rules below
// were NOT loosened: this is an unsupervised chat for kids as young as 5,
// with no adult reviewing messages before they're sent, so those stay
// strict regardless of what's asked. Don't remove them to make answers
// "more helpful" — a wrong refusal is a much smaller problem than a bad
// answer to a 5-year-old.
const ASK_BRIDGE_SYSTEM_PROMPT = `You are Bridge, a friendly robot mascot inside LinguaBridge, a private learning app for kids and teens ages 5 to 17.

You ONLY help with learning English: words and their meanings, grammar, pronunciation, spelling, reading, writing, speaking practice, conversation practice, and questions about the student's current LinguaBridge lesson. Answer in short, warm, age-appropriate sentences (2-5 sentences max). Use simple words for the age group. Be encouraging, like a kind teacher.

If a student asks about anything that is not about learning English (math or other school subjects, general knowledge, how things work, games, celebrities, news, or chit-chat), do not answer it. Kindly say that you are Bridge, an English helper, and that a teacher or parent can help with that, then offer an English activity instead, such as teaching a related English word or practicing a sentence about their topic. A friendly greeting or a short thank-you is fine to answer, then bring the conversation back to English. You may use a student's topic of interest as the example for an English lesson (for example, teach the words "ball" and "kick" if they mention soccer), but teach the English, not the subject.

Calibrate every answer to a 13-year-old or younger, even though some LinguaBridge users are older teens — you can't tell which one you're talking to, so keep things wholesome, gentle, and simple by default rather than assuming an older, more mature audience. Nothing mature, intense, or edgy, even if it would be fine for a 16-year-old elsewhere.

If a student writes in a language other than English, you can understand it — don't ignore or refuse a message just because it isn't in English. Respond warmly (a short reply in their language is fine), and also give the English version of your answer so they pick up more English from every exchange. Gently invite them to try their next message in English when it feels natural.

You do not have access to a live clock, calendar, or current-events feed, so never guess or make up the current time, date, or something happening live right now — say plainly that you can't know that instead of inventing an answer.

Hard rules, no exceptions:
- Never discuss or generate anything violent, sexual, scary, hateful, or otherwise inappropriate for a child.
- Never ask the student for personal information (full name, address, phone number, school name, photos, passwords, etc.), and if they share any, don't repeat it back or store it in your answer — just gently redirect to the question or lesson.
- If a question is about something an adult should handle instead (personal/family advice, medical or legal questions, serious current events, or anything else beyond general knowledge for a child), kindly say that's something to ask a teacher or parent, rather than answering it yourself.
- If a question suggests the student might be upset, in danger, or need help from an adult (bullying, being hurt, feeling unsafe, etc.), gently and clearly tell them to talk to a trusted adult, parent, or teacher right away. Do not try to solve that problem yourself.
- If a student says anything about wanting to die or hurt themselves, or says someone is hurting them (at home or anywhere), or that they are being abused: respond with warmth first and keep it short. Say you are really glad they told you, that it is not their fault, and that they deserve to be safe. Tell them to tell a trusted grown-up RIGHT NOW, such as a teacher or school counselor or another adult they trust (do not assume that a parent or someone at home is safe to tell). Tell them that in the United States they can call or text 988 any time, that the Childhelp hotline is 1-800-422-4453, and that if they are in danger right now they should call 911. Do not ask for details, do not probe, do not try to counsel them yourself, and do not change the subject back to lessons in that reply.
- Do not name real people such as singers, actors, athletes, or YouTubers in your answers; talk about the topic in general (for example, "music" instead of a singer's name).
- Never pretend to be human, never claim feelings you don't have in a way that could confuse a young child about what you are, and never break character in a way that's scary or confusing.
- If you are at all unsure whether something is appropriate to answer, politely decline and suggest asking a teacher or parent instead.`;

function clientKey(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

// The frontend keeps a short rolling log of the conversation so Bridge can
// handle follow-ups like "rewrite that" or "say it simpler" instead of
// treating every question as a fresh one with no context. Never trust it
// blindly though — validate shape/role/length before it goes anywhere near
// the model, same as any other user-supplied input.
const ASK_BRIDGE_MAX_HISTORY_TURNS = 10;
const ASK_BRIDGE_MAX_HISTORY_CHARS = 500;

function sanitizeHistory(raw) {
  if (!Array.isArray(raw)) return [];
  const cleaned = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const role = item.role === "user" || item.role === "assistant" ? item.role : null;
    if (!role) continue;
    const content = (item.content || "").toString().trim().slice(0, ASK_BRIDGE_MAX_HISTORY_CHARS);
    if (!content) continue;
    cleaned.push({ role, content });
  }
  // Keep only the most recent turns so the prompt doesn't grow unbounded.
  return cleaned.slice(-ASK_BRIDGE_MAX_HISTORY_TURNS);
}

// ------------------------------------------------------------------
// World clock — answers "what time is it in X" directly and accurately
// instead of asking the AI model to guess. Models have no access to a
// real clock, so letting one answer "what time is it" questions just
// produces a confident-sounding wrong answer. This covers every
// continent (by example cities, since a continent spans many zones),
// all 50 US states + DC, a broad list of countries, and many major
// world cities by name; anything else falls back to searching the
// IANA time zone database itself, which is keyed by city name for
// most entries (e.g. "America/Denver", "Asia/Tokyo").
// ------------------------------------------------------------------

const TIMEZONE_ALIASES = {
  // US states + DC (a representative zone — see SPANS_MULTIPLE_ZONES)
  "alabama": "America/Chicago", "alaska": "America/Anchorage", "arizona": "America/Phoenix",
  "arkansas": "America/Chicago", "california": "America/Los_Angeles", "colorado": "America/Denver",
  "connecticut": "America/New_York", "delaware": "America/New_York", "florida": "America/New_York",
  "georgia": "America/New_York", "hawaii": "Pacific/Honolulu", "idaho": "America/Denver",
  "illinois": "America/Chicago", "indiana": "America/Indiana/Indianapolis", "iowa": "America/Chicago",
  "kansas": "America/Chicago", "kentucky": "America/New_York", "louisiana": "America/Chicago",
  "maine": "America/New_York", "maryland": "America/New_York", "massachusetts": "America/New_York",
  "michigan": "America/Detroit", "minnesota": "America/Chicago", "mississippi": "America/Chicago",
  "missouri": "America/Chicago", "montana": "America/Denver", "nebraska": "America/Chicago",
  "nevada": "America/Los_Angeles", "new hampshire": "America/New_York", "new jersey": "America/New_York",
  "new mexico": "America/Denver", "new york": "America/New_York", "north carolina": "America/New_York",
  "north dakota": "America/Chicago", "ohio": "America/New_York", "oklahoma": "America/Chicago",
  "oregon": "America/Los_Angeles", "pennsylvania": "America/New_York", "rhode island": "America/New_York",
  "south carolina": "America/New_York", "south dakota": "America/Chicago", "tennessee": "America/Chicago",
  "texas": "America/Chicago", "utah": "America/Denver", "vermont": "America/New_York",
  "virginia": "America/New_York", "washington": "America/Los_Angeles", "washington dc": "America/New_York",
  "washington d c": "America/New_York", "west virginia": "America/New_York", "wisconsin": "America/Chicago",
  "wyoming": "America/Denver",

  // Countries (capital or majority-population zone)
  "united states": "America/New_York", "usa": "America/New_York", "u s a": "America/New_York",
  "canada": "America/Toronto", "mexico": "America/Mexico_City", "brazil": "America/Sao_Paulo",
  "argentina": "America/Argentina/Buenos_Aires", "chile": "America/Santiago", "colombia": "America/Bogota",
  "peru": "America/Lima", "venezuela": "America/Caracas", "ecuador": "America/Guayaquil",
  "united kingdom": "Europe/London", "uk": "Europe/London", "england": "Europe/London",
  "scotland": "Europe/London", "wales": "Europe/London", "ireland": "Europe/Dublin",
  "france": "Europe/Paris", "germany": "Europe/Berlin", "spain": "Europe/Madrid",
  "italy": "Europe/Rome", "portugal": "Europe/Lisbon", "netherlands": "Europe/Amsterdam",
  "belgium": "Europe/Brussels", "switzerland": "Europe/Zurich", "austria": "Europe/Vienna",
  "sweden": "Europe/Stockholm", "norway": "Europe/Oslo", "denmark": "Europe/Copenhagen",
  "finland": "Europe/Helsinki", "poland": "Europe/Warsaw", "greece": "Europe/Athens",
  "russia": "Europe/Moscow", "ukraine": "Europe/Kyiv", "turkey": "Europe/Istanbul",
  "egypt": "Africa/Cairo", "nigeria": "Africa/Lagos", "south africa": "Africa/Johannesburg",
  "kenya": "Africa/Nairobi", "morocco": "Africa/Casablanca", "ethiopia": "Africa/Addis_Ababa",
  "ghana": "Africa/Accra", "china": "Asia/Shanghai", "japan": "Asia/Tokyo",
  "south korea": "Asia/Seoul", "north korea": "Asia/Pyongyang", "india": "Asia/Kolkata",
  "pakistan": "Asia/Karachi", "bangladesh": "Asia/Dhaka", "indonesia": "Asia/Jakarta",
  "philippines": "Asia/Manila", "vietnam": "Asia/Ho_Chi_Minh", "thailand": "Asia/Bangkok",
  "malaysia": "Asia/Kuala_Lumpur", "singapore": "Asia/Singapore", "saudi arabia": "Asia/Riyadh",
  "united arab emirates": "Asia/Dubai", "uae": "Asia/Dubai", "israel": "Asia/Jerusalem",
  "iran": "Asia/Tehran", "iraq": "Asia/Baghdad", "afghanistan": "Asia/Kabul",
  "australia": "Australia/Sydney", "new zealand": "Pacific/Auckland",
  "haiti": "America/Port-au-Prince", "jamaica": "America/Jamaica", "cuba": "America/Havana",
  "dominican republic": "America/Santo_Domingo", "puerto rico": "America/Puerto_Rico",
  "guatemala": "America/Guatemala", "honduras": "America/Tegucigalpa", "el salvador": "America/El_Salvador",
  "nicaragua": "America/Managua", "costa rica": "America/Costa_Rica", "panama": "America/Panama",

  // Major cities not already covered above
  "new york city": "America/New_York", "nyc": "America/New_York", "los angeles": "America/Los_Angeles",
  "chicago": "America/Chicago", "houston": "America/Chicago", "phoenix": "America/Phoenix",
  "philadelphia": "America/New_York", "san antonio": "America/Chicago", "san diego": "America/Los_Angeles",
  "dallas": "America/Chicago", "san francisco": "America/Los_Angeles", "seattle": "America/Los_Angeles",
  "denver": "America/Denver", "boston": "America/New_York", "atlanta": "America/New_York",
  "miami": "America/New_York", "las vegas": "America/Los_Angeles", "london": "Europe/London",
  "paris": "Europe/Paris", "berlin": "Europe/Berlin", "madrid": "Europe/Madrid",
  "rome": "Europe/Rome", "moscow": "Europe/Moscow", "dubai": "Asia/Dubai",
  "beijing": "Asia/Shanghai", "shanghai": "Asia/Shanghai", "hong kong": "Asia/Hong_Kong",
  "tokyo": "Asia/Tokyo", "seoul": "Asia/Seoul", "mumbai": "Asia/Kolkata",
  "delhi": "Asia/Kolkata", "new delhi": "Asia/Kolkata", "bangkok": "Asia/Bangkok",
  "jakarta": "Asia/Jakarta", "manila": "Asia/Manila", "singapore city": "Asia/Singapore",
  "sydney": "Australia/Sydney", "melbourne": "Australia/Melbourne", "auckland": "Pacific/Auckland",
  "cairo": "Africa/Cairo", "lagos": "Africa/Lagos", "nairobi": "Africa/Nairobi",
  "johannesburg": "Africa/Johannesburg", "cape town": "Africa/Johannesburg",
  "toronto": "America/Toronto", "vancouver": "America/Vancouver", "montreal": "America/Toronto",
  "mexico city": "America/Mexico_City", "sao paulo": "America/Sao_Paulo", "rio de janeiro": "America/Sao_Paulo",
  "buenos aires": "America/Argentina/Buenos_Aires", "bogota": "America/Bogota", "lima": "America/Lima",
};

// Places that genuinely span more than one time zone — add a short honest
// caveat instead of implying the whole place shares a single clock.
const SPANS_MULTIPLE_ZONES = new Set([
  "texas", "tennessee", "idaho", "oregon", "nevada", "kansas", "nebraska",
  "north dakota", "south dakota", "florida", "kentucky", "michigan", "indiana",
  "arizona", "united states", "usa", "u s a", "canada", "russia", "brazil",
  "australia", "mexico", "indonesia",
]);

// A continent doesn't keep one clock, so answer with real example cities
// instead of a single (wrong) number.
const CONTINENT_EXAMPLES = {
  "africa": [["Cairo, Egypt", "Africa/Cairo"], ["Lagos, Nigeria", "Africa/Lagos"], ["Johannesburg, South Africa", "Africa/Johannesburg"]],
  "asia": [["Tokyo, Japan", "Asia/Tokyo"], ["Dubai, UAE", "Asia/Dubai"], ["New Delhi, India", "Asia/Kolkata"]],
  "europe": [["London, UK", "Europe/London"], ["Berlin, Germany", "Europe/Berlin"], ["Moscow, Russia", "Europe/Moscow"]],
  "north america": [["New York, USA", "America/New_York"], ["Los Angeles, USA", "America/Los_Angeles"], ["Mexico City, Mexico", "America/Mexico_City"]],
  "south america": [["Sao Paulo, Brazil", "America/Sao_Paulo"], ["Buenos Aires, Argentina", "America/Argentina/Buenos_Aires"], ["Bogota, Colombia", "America/Bogota"]],
  "australia": [["Sydney, Australia", "Australia/Sydney"], ["Perth, Australia", "Australia/Perth"]],
  "oceania": [["Sydney, Australia", "Australia/Sydney"], ["Auckland, New Zealand", "Pacific/Auckland"]],
  "antarctica": [["McMurdo Station", "Antarctica/McMurdo"]],
};

function formatTimeInZone(tz) {
  return new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    weekday: "long",
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  }).format(new Date());
}

function normalizePlace(raw) {
  return raw
    .toLowerCase()
    .replace(/[.?!,]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

// Last-resort lookup: the IANA zone database itself is largely keyed by
// city name (e.g. "America/Denver", "Asia/Tokyo"), so search it for a
// segment that matches what the student typed before giving up.
function searchIanaZones(place) {
  let zones;
  try {
    zones = Intl.supportedValuesOf("timeZone");
  } catch (e) {
    return null;
  }
  for (const zone of zones) {
    const segments = zone.toLowerCase().split("/");
    const last = segments[segments.length - 1].replace(/_/g, " ");
    if (last === place) return zone;
  }
  return null;
}

function resolveTimeZone(placeRaw) {
  const place = normalizePlace(placeRaw);
  if (!place) return null;
  if (TIMEZONE_ALIASES[place]) {
    return { tz: TIMEZONE_ALIASES[place], spans: SPANS_MULTIPLE_ZONES.has(place) };
  }
  const viaIana = searchIanaZones(place);
  if (viaIana) return { tz: viaIana, spans: false };
  return null;
}

function isTimeQuestion(q) {
  return /\b(what\s+time|current\s+time|time\s+is\s+it|time\s+zone|what's\s+the\s+time)\b/i.test(q);
}

// Pulls the place out of phrasing like "what time is it in Tokyo right
// now?" -> "Tokyo". Best-effort; returns "" if no "in <place>" is found.
function extractTimePlace(q) {
  const match = q.match(/\bin\s+([a-zA-Z .'-]+?)(?:\s+(?:right now|currently|today|now)\b)?[?!.]*\s*$/i);
  return match ? match[1].trim() : "";
}

function continentAnswer(name) {
  const examples = CONTINENT_EXAMPLES[name];
  const label = name.replace(/\b\w/g, (c) => c.toUpperCase());
  const parts = examples.map(([city, tz]) => `${formatTimeInZone(tz)} in ${city}`);
  return `${label} is so big it has several time zones! For example, right now it's ${parts.join(", and ")}.`;
}

function answerTimeQuestion(question) {
  const placePhrase = extractTimePlace(question);

  if (placePhrase) {
    const normalizedPhrase = normalizePlace(placePhrase);
    if (CONTINENT_EXAMPLES[normalizedPhrase]) {
      return continentAnswer(normalizedPhrase);
    }
    const resolved = resolveTimeZone(placePhrase);
    if (resolved) {
      const time = formatTimeInZone(resolved.tz);
      const label = placePhrase.replace(/\b\w/g, (c) => c.toUpperCase());
      const caveat = resolved.spans
        ? " (Heads up: this place is big enough to have more than one time zone — this is the time in its most common one!)"
        : "";
      return `Right now it's ${time} in ${label}!${caveat}`;
    }
    return `Hmm, I don't recognize "${placePhrase}" as a place I can check the time for. Can you try naming a country or a bigger nearby city?`;
  }

  const continentMatch = Object.keys(CONTINENT_EXAMPLES).find((name) =>
    normalizePlace(question).includes(name)
  );
  if (continentMatch) return continentAnswer(continentMatch);

  // No place named at all — Bridge has no idea where the student actually is.
  return 'I don\'t automatically know where you are! Tell me your city, state, or country (like "what time is it in Texas?") and I\'ll check it for you.';
}

async function handleAskBridge(request, env) {
  // Only signed-in, approved accounts can talk to Bridge (added 2026-11-05).
  if (!(await getSessionUser(request, env))) {
    return jsonResponse({ error: "Please log in to talk to Bridge." }, 401, request);
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "Invalid request body." }, 400, request);
  }

  const question = (body.question || "").toString().trim();
  const level = (body.level || "").toString().slice(0, 40);
  const lessonTopic = (body.lessonTopic || "").toString().slice(0, 80);
  const history = sanitizeHistory(body.history);

  if (!question) {
    return jsonResponse({ error: "Please type a question first." }, 400, request);
  }
  if (question.length > ASK_BRIDGE_MAX_QUESTION_LEN) {
    return jsonResponse(
      { error: "That question is a bit long — can you make it shorter?" },
      400,
      request
    );
  }

  let answer;
  if (isTimeQuestion(question)) {
    // Answered deterministically (see the world-clock section above) —
    // the AI model has no real clock, so letting it guess would just
    // produce a confident, wrong answer.
    answer = answerTimeQuestion(question);
  } else {
    try {
      const userPrompt = lessonTopic
        ? `(Student is on the "${lessonTopic}" lesson, level: ${level || "unknown"}.) Student's question: ${question}`
        : question;

      const aiResult = await env.AI.run(ASK_BRIDGE_MODEL, {
        messages: [
          { role: "system", content: ASK_BRIDGE_SYSTEM_PROMPT },
          ...history,
          { role: "user", content: userPrompt },
        ],
        max_tokens: 300,
      });

      // Different Workers AI models shape their output differently: older
      // models (like the retired llama-3.1-8b-instruct) return { response },
      // while newer OpenAI-compatible chat models (like glm-4.7-flash) return
      // { choices: [{ message: { content } }] }. Check both so this keeps
      // working across model swaps.
      const rawAnswer =
        (aiResult && aiResult.response) ||
        (aiResult && aiResult.choices && aiResult.choices[0] && aiResult.choices[0].message && aiResult.choices[0].message.content) ||
        "";
      answer = rawAnswer.trim();
      if (!answer) {
        answer =
          "Hmm, I'm not sure how to answer that one. Can you try asking a different way, or ask your teacher?";
      }
    } catch (e) {
      // Log the real error so it shows up in the Cloudflare dashboard's
      // Observability/Logs view (Message column) instead of being invisible —
      // the response to the student stays generic/kid-safe either way.
      console.error("Ask Bridge AI call failed:", e && e.message ? e.message : e);
      return jsonResponse(
        { error: "Bridge couldn't think of an answer right now. Please try again in a moment." },
        502,
        request
      );
    }
  }

  // Best-effort: don't fail the response if logging hiccups.
  try {
    await env.DB.prepare(
      "INSERT INTO bridge_questions (client_id, question, answer, level, lesson_topic) VALUES (?, ?, ?, ?, ?)"
    )
      .bind(clientKey(request), question, answer, level, lessonTopic)
      .run();
  } catch (e) {}

  return jsonResponse({ answer }, 200, request);
}

// ---------------------------------------------------------------------
// Progress saving (added 2026-11-05)
// Each signed-in user (student child login, parent, or founder) gets one
// row in `progress` holding their lesson progress as a JSON blob, so it
// follows their login across devices and survives cleared browser data.
//   GET  /api/progress            -> { data: <object|null>, updated_at }
//   POST /api/progress { data }   -> { ok: true, updated_at }
// Table (run once in D1):
//   CREATE TABLE IF NOT EXISTS progress (
//     user_id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL);
// ---------------------------------------------------------------------
const PROGRESS_MAX_BYTES = 60000;

async function handleGetProgress(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return jsonResponse({ error: "Not signed in." }, 401, request);
  const row = await env.DB.prepare("SELECT data, updated_at FROM progress WHERE user_id = ?")
    .bind(user.id)
    .first();
  if (!row) return jsonResponse({ data: null, updated_at: 0 }, 200, request);
  let data = null;
  try { data = JSON.parse(row.data); } catch (e) {}
  return jsonResponse({ data, updated_at: row.updated_at }, 200, request);
}

async function handleSaveProgress(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return jsonResponse({ error: "Not signed in." }, 401, request);
  let body;
  try { body = await request.json(); } catch (e) {
    return jsonResponse({ error: "Bad request." }, 400, request);
  }
  const data = body && body.data;
  if (!data || typeof data !== "object" || Array.isArray(data) || !Array.isArray(data.completed)) {
    return jsonResponse({ error: "Bad progress data." }, 400, request);
  }
  // Keep only the fields progress actually uses, so nothing else can be stored.
  const clean = {
    level: typeof data.level === "string" ? data.level.slice(0, 20) : "explorer",
    completed: data.completed.slice(0, 1000).map((c) => ({
      level: String(c && c.level || "").slice(0, 20),
      n: Number(c && c.n) || 0,
      date: String(c && c.date || "").slice(0, 10),
      score: c && typeof c.score === "number" ? c.score : undefined,
      total: c && typeof c.total === "number" ? c.total : undefined,
    })),
    voice: typeof data.voice === "string" ? data.voice.slice(0, 20) : undefined,
    quizHistory: Array.isArray(data.quizHistory) ? data.quizHistory.slice(-30).map((q) => ({
      level: String(q && q.level || "").slice(0, 20),
      n: Number(q && q.n) || 0,
      score: Number(q && q.score) || 0,
      total: Number(q && q.total) || 0,
    })) : undefined,
  };
  const json = JSON.stringify(clean);
  if (json.length > PROGRESS_MAX_BYTES) {
    return jsonResponse({ error: "Progress too large." }, 413, request);
  }
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO progress (user_id, data, updated_at) VALUES (?, ?, ?) " +
    "ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at"
  ).bind(user.id, json, now).run();
  return jsonResponse({ ok: true, updated_at: now }, 200, request);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          ...corsHeaders(request),
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    // Block cross-site POSTs from pages that are not ours (cookie-based sessions need this).
    if (request.method === "POST") {
      const origin = request.headers.get("Origin");
      if (origin && !ALLOWED_ORIGINS.includes(origin)) {
        return jsonResponse({ error: "Not allowed." }, 403, request);
      }
    }

    if (url.pathname === "/api/admin/overview" && request.method === "GET") {
      return handleAdminOverview(request, env);
    }
    if (url.pathname.startsWith("/api/admin/") && request.method === "POST") {
      return handleAdminAction(request, env, url.pathname.slice("/api/admin/".length));
    }
    if (url.pathname === "/api/login" && request.method === "POST") {
      return handleLogin(request, env);
    }
    if (url.pathname === "/api/me" && request.method === "GET") {
      return handleMe(request, env);
    }
    if (url.pathname === "/api/logout" && request.method === "POST") {
      return handleLogout(request, env);
    }
    if (url.pathname === "/api/signup" && request.method === "POST") {
      return handleSignup(request, env);
    }
    if (url.pathname === "/api/children" && request.method === "GET") {
      return handleListChildren(request, env);
    }
    if (url.pathname === "/api/children" && request.method === "POST") {
      return handleCreateChild(request, env);
    }
    if (url.pathname === "/api/progress" && request.method === "GET") {
      return handleGetProgress(request, env);
    }
    if (url.pathname === "/api/progress" && request.method === "POST") {
      return handleSaveProgress(request, env);
    }
    if (url.pathname === "/api/ask-bridge" && request.method === "POST") {
      return handleAskBridge(request, env);
    }

    return jsonResponse({ error: "Not found." }, 404, request);
  },
};
