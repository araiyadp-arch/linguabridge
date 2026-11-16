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
  if (password.length < 8) return "Password must be at least 8 characters.";
  if (password.length > 200) return "That password is too long.";
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) return "Password needs a letter, a number, and a special character like ! or #.";
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

// ---- Signup rules (2026-11-15, founder request) ----
// One simple account type: first + last name, unique username, strong password, and an email OR a
// phone number with country code. No invite code and no approval. Names and usernames must be clean:
// no swearing, hate, sexism, discrimination or sexual words (checked here on the server).
const NAME_RE = /^[A-Za-z][A-Za-z '\-]{0,39}$/;
const PHONE_RE = /^\+[1-9][0-9]{6,14}$/;
const BAD_SUBSTR_RE = /(fuck|fuk|fck|shit|bitch|bastard|asshole|cunt|nigg|faggot|slut|whore|porn|rapist|nazi|hitler|penis|vagina|pussy|retard|kike|chink|wetback|tranny|kkk|terrorist|jihad|suicid|molest|pedo)/;
function leetNormalize(str) {
  return str.toLowerCase().replace(/0/g, "o").replace(/1/g, "i").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/8/g, "b").replace(/[@]/g, "a").replace(/[$]/g, "s");
}
// ---- Cuss words in many languages (2026-11-15, founder request) ----
// Written the way people type them with English letters (names and usernames only allow A-Z, so other
// alphabets cannot be entered at all). LONG words are blocked even inside a longer name; SHORT words only
// when they stand alone, so real names are not blocked by accident. No list can cover every word in every
// language, so this is a strong first filter, not a guarantee. Add words here any time.
const INTL_LONG = ["mierda","joder","cabron","pendejo","culero","chinga","maricon","gilipollas","hijodeputa","merde","putain","salope","connard","connasse","encule","batard","scheisse","arschloch","fotze","hurensohn","wichser","schwuchtel","ficken","schlampe","cazzo","vaffanculo","stronzo","puttana","minchia","caralho","buceta","filhodaputa","klootzak","kanker","blyad","blyat","pizda","khuy","mudak","pidor","pidar","gandon","orospu","siktir","madarchod","behenchod","bhenchod","chutiya","bhosdi","bhosdike","harami","caonima","shabi","tamade","wangbadan","diunei","shibal","ssibal","gaesaekki","jotgat","kurwa","pierdol","skurwysyn","gamoto","poutana","putangina","tarantado","kantot","kontol","memek","ngentot","bajingan","goblok","sharmouta","sharmuta","kosomak","chikushou","bakayaro","kisama","chinko","anjing","bangsat","fuckyou","motherfuck","dumbass","jackass","dipshit","bullshit","arsehole","wanker","twat","bollocks","prick"];
const INTL_WORD = ["cono","zorra","chingar","hdp","pute","bordel","fick","kacke","merda","foda","foder","porra","viado","cuzao","kut","tering","suka","ebat","ebal","amk","ibne","yarak","ahbal","gandu","gaand","kuso","chuj","dupa","gago","tangina","puki","pakyu","dmm","vcl","tolol","ass","arse","damn","crap","piss","puta","puto","verga","troia","nique","sibal","malaka","manko"];
const INTL_LONG_RE = new RegExp("(" + INTL_LONG.join("|") + ")");
function intlDirty(str, asWholeWord) {
  const lower = leetNormalize(String(str)).replace(/ñ/g, "n");
  const letters = lower.replace(/[^a-z]/g, "");
  if (INTL_LONG_RE.test(letters)) return true;
  const tokens = lower.split(/[^a-zñ]+/).filter(Boolean);
  const set = new Set(INTL_WORD);
  if (tokens.some((t) => set.has(t))) return true;
  if (asWholeWord && set.has(letters)) return true;
  // word list entries also match as the start or end of a username like "suka2012" or "2012suka"
  return false;
}
function dirtyText(str) {
  const n = leetNormalize(str).replace(/[^a-z]/g, "");
  return BAD_SUBSTR_RE.test(n) || BAD_WORDS_RE.test(str) || HATE_RE.test(str) || intlDirty(str, true);
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
    return jsonResponse({ error: "Too many new accounts from this device today. Please try again tomorrow." }, 429, request);
  }

  const username = (body.username || "").toString().trim();
  const password = (body.password || "").toString();
  const contact = (body.contact || "").toString().trim();

  if (!CHILD_USERNAME_RE.test(username)) {
    return jsonResponse({ error: "Username must be 3-20 letters or numbers, no spaces or symbols." }, 400, request);
  }
  if (dirtyText(username)) {
    return jsonResponse({ error: "Please use kind, clean words only. Usernames cannot have bad words, hate, or anything unfair to any group of people. Please try again." }, 400, request);
  }
  const pwProblem = passwordProblem(password, username);
  if (pwProblem) {
    return jsonResponse({ error: pwProblem }, 400, request);
  }
  let email = null, phone = null;
  if (contact.includes("@")) {
    email = contact.toLowerCase();
    if (!EMAIL_RE.test(email) || email.length > 200) {
      return jsonResponse({ error: "Please enter a valid email address, or a phone number with country code like +1 555 123 4567." }, 400, request);
    }
  } else {
    phone = contact.replace(/[\s().-]/g, "");
    if (!PHONE_RE.test(phone)) {
      return jsonResponse({ error: "Please enter a valid email address, or a phone number with country code like +1 555 123 4567." }, 400, request);
    }
  }

  const existing = await env.DB.prepare("SELECT id FROM users WHERE lower(username) = lower(?)").bind(username).first();
  if (existing) {
    return jsonResponse({ error: "That username is already taken. Try another one." }, 409, request);
  }
  const dupe = email
    ? await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first()
    : await env.DB.prepare("SELECT id FROM users WHERE phone = ?").bind(phone).first();
  if (dupe) {
    return jsonResponse({ error: "An account with that email or phone number already exists. Try logging in instead." }, 409, request);
  }

  const { hash, salt, iterations } = await hashPassword(password);
  const id = "usr_" + crypto.randomUUID();

  try {
    await env.DB.prepare(
      `INSERT INTO users (id, username, password_hash, password_salt, iterations, role, email, parent_id, status, invite_code, first_name, last_name, phone)
       VALUES (?, ?, ?, ?, ?, 'student', ?, NULL, 'approved', NULL, ?, ?, ?)`
    )
      .bind(id, username, hash, salt, iterations, email, null, null, phone)
      .run();
  } catch (e) {
    return jsonResponse({ error: "That username, email or phone number is already used. Try another." }, 409, request);
  }

  // At most 6 new accounts per device per day.
  await recordFailure(env, ipKey, 6, 24 * 60 * 60 * 1000, 24 * 60 * 60 * 1000);

  const token = await createSession(env, id);
  return jsonResponse({ authenticated: true, username, role: "student" }, 200, request, setSessionCookieHeaders(token));
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
  const childPwProblem = passwordProblem(pin, "");
  if (childPwProblem) {
    return jsonResponse({ error: childPwProblem }, 400, request);
  }

  const existing = await env.DB.prepare("SELECT id FROM users WHERE lower(username) = lower(?)")
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
    `SELECT u.id, CASE WHEN u.first_name IS NOT NULL THEN u.first_name || ' ' || u.last_name || ' (' || u.username || ') - ' || COALESCE(u.email, u.phone) ELSE COALESCE(u.email, u.username) END as email, u.status, u.created_at,
            (SELECT COUNT(*) FROM users c WHERE c.parent_id = u.id) as children
     FROM users u WHERE (u.role = 'parent' OR (u.role = 'student' AND u.parent_id IS NULL)) AND u.status != 'pending' ORDER BY u.created_at DESC LIMIT 200`
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
    await env.DB.prepare("UPDATE users SET status = ? WHERE id = ? AND (role = 'parent' OR (role = 'student' AND parent_id IS NULL))").bind(status, id).run();
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
const BRIDGE_ADULT_MSG = "Sorry, please consult with an adult. I am a robot. I only teach the lessons that are on this website.";
const BRIDGE_REPHRASE_MSG = "Please ask this question differently. I can only help with learning conversational English.";
const BRIDGE_PRIVATE_MSG = "Please do not share personal information here. Ask me about English instead!";
const BRIDGE_HELP_MSG = "I am so sorry you feel this way. Please tell a trusted adult right now, like a parent or teacher. If you are in danger, call 911. You can call or text 988 any time. You are not alone.";
const BRIDGE_SAD_MSG = "I am sorry you feel sad. You matter. Please talk to a trusted adult, like a parent or teacher.";
const BRIDGE_ABUSE_MSG = "I am so sorry. This is not your fault. Please tell a trusted adult right now. If you are in danger, call 911. Childhelp: 1-800-422-4453.";

const ASK_BRIDGE_SYSTEM_PROMPT = `You are Bridge, a robot helper inside LinguaBridge, a free English-learning website for kids ages 5 to 17. You only teach conversational English: words and meanings, grammar, pronunciation, spelling, reading, writing, and speaking practice.

STYLE: Reply in 1 or 2 very short, simple sentences (under 30 words). Plain, clean, friendly English. No lists, no long explanations.

TRANSLATION HELP: Children from all over the world use this site. A child may ask how to say a word, greeting or phrase from ANY language in the world in English (for example "how to say namaste in English", "what is gracias in english", "bonjour in english"), or what an English word is in their own language. Always help. Answer in 1 or 2 short sentences, for example: "Namaste" is a greeting from India. In English we say "hello". Say what the word means in simple English and give the English word or phrase. Only help with clean, kind, child-friendly words. If the word or phrase, in ANY language, is a swear word, a rude or insulting word, sexual, hateful, racist, sexist, unfair to any group, violent, or about drugs, do not translate it and do not repeat it: reply exactly: "${BRIDGE_ADULT_MSG}". Never give a swear word or rude word in English or in any other language, even if asked "what is the bad word for".

SPELLING: Children make spelling mistakes. Always guess the closest word the child most likely meant and answer that, without correcting them or saying they made a mistake. Only if you truly cannot guess, reply exactly: "${BRIDGE_REPHRASE_MSG}"

RULES (no exceptions):
- If the question is not about learning English, or about words and phrases from any language and how to say them in English, reply exactly: "${BRIDGE_ADULT_MSG}"
- If the question is unclear and you cannot make a smart guess about what the child meant, reply exactly: "${BRIDGE_REPHRASE_MSG}"
- Never ask the student anything personal (name, age, school, address, family, photos, feelings, passwords). Never answer personal questions about anyone. If a student shares personal information, do not repeat it.
- Never use swearing or rude words. Never say anything racist, sexist, or unfair to any group of people. Never talk about sex, nudity, violence, drugs, or scary things.
- Never pass messages between students. Students cannot talk to each other through you.
- Never name real people. Never give the time, date, or news.
- Never pretend to be human. You are a robot.`;


// ---- Ask Bridge hard filters (2026-11-09) -------------------------------
// These run BEFORE the AI model and on its answer, so the safety rules do not
// depend on the model behaving. Founder rules: clean conversational English only,
// no swearing / hate / sexism / sex talk, no personal info, no student-to-student chat.
const BAD_WORDS_RE = /\b(fuck\w*|shit\w*|bitch\w*|bastard|asshole|dick|cock|pussy|cunt|slut|whore|damn|crap|piss\w*|wtf|stfu|nigg\w*|fag\w*|retard\w*|chink|spic|kike|tranny|sex\w*|porn\w*|nude|naked|penis|vagina|boob\w*|horny|erotic|rape\w*|molest\w*|orgasm|masturbat\w*|blowjob|condom|nazi|terrorist|cocaine|heroin|weed|marijuana)\b/i;
const HATE_RE = /\b(girls|boys|women|men|blacks?|whites?|asians?|mexicans?|jews?|muslims?|christians?|hindus?|gays?|immigrants?)\s+(are|is)\s+(stupid|dumb|bad|worse|inferior|dirty|ugly|better than)/i;
const SELFHARM_RE = /(kill myself|killing myself|want to die|wanna die|don.?t want to (be alive|live)|end my life|suicid|hurt myself|hurting myself|cut myself|self.?harm|better off dead|wish i was dead)/i;
const ABUSE_RE = /(hurts? me|hits? me|beats? me|abus(e|es|ed|ing)|touch(es|ed)? me|molest|someone is hurting|scared of (my|him|her)|unsafe at home)/i;
const SAD_RE = /(i am|i.?m|im|feel|feeling)\s+(so\s+)?(sad|lonely|alone|scared|afraid|unhappy|depressed|worried|anxious|upset)|nobody likes me|no one likes me|i have no friends|i hate myself|bullied|bullying|being mean to me/i;
const PERSONAL_SHARE_RE = /(my (full )?name is|i am called|my (phone|number|address|email|password|school)\b|i live (at|in|on)|\b\d{3}[-. )]*\d{3}[-. ]*\d{4}\b|[\w.+-]+@[\w-]+\.[\w.]+|\b\d{1,5}\s+\w+\s+(street|st|road|rd|avenue|ave|lane|ln|drive|dr)\b|i go to .{2,30} school|my (mom|dad|mother|father|sister|brother|teacher) (is|named|name))/i;
const PERSONAL_ASK_RE = /(how old are you|your age|where do you live|what.?s your (real )?name|who made you|are you a (boy|girl)|do you have (a )?(family|mom|dad|friends?)|are you (single|married)|your (phone|address|school|birthday))/i;
const STUDENT_CHAT_RE = /(tell|message|text|send|say to|talk to|chat with|ask)\s+(\w+\s+)?(another|other|my)?\s*(student|friend|classmate|kid|him|her|them)\b|\bpass (this|a) message|send (a )?message to/i;

function intlDirtyTokens(str) {
  const tokens = leetNormalize(String(str)).replace(/ñ/g, "n").split(/[^a-z]+/).filter(Boolean);
  const longs = INTL_LONG, shorts = new Set(INTL_WORD);
  return tokens.some((t) => shorts.has(t) || longs.includes(t));
}
// Extra safety check for questions that contain letters from other alphabets (Arabic, Chinese, Cyrillic, Hindi...)
// or that ask for a translation: our word lists only know Latin letters, so a safety model checks these too.
// If the check fails or cannot run, the question is NOT answered (fail closed).
const GUARD_MODEL = "@cf/meta/llama-guard-3-8b";
function needsGuard(q) {
  return /[^\u0000-\u024F\u2000-\u206F]/.test(q);
}
async function guardBlocks(env, text) {
  try {
    const out = await env.AI.run(GUARD_MODEL, { messages: [{ role: "user", content: text }] });
    const raw = JSON.stringify(out || {}).toLowerCase();
    if (raw.includes('"safe":false') || raw.includes("unsafe")) return true;
    return false;
  } catch (e) {
    console.error("Guard check failed:", e && e.message ? e.message : e);
    // Fail closed only for other alphabets (our word lists cannot read those); plain Latin text already passed the word lists.
    return /[^\u0000-\u024F\u2000-\u206F]/.test(text);
  }
}

function bridgeFilter(question) {
  if (SELFHARM_RE.test(question)) return BRIDGE_HELP_MSG;
  if (ABUSE_RE.test(question)) return BRIDGE_ABUSE_MSG;
  if (SAD_RE.test(question)) return BRIDGE_SAD_MSG;
  if (BAD_WORDS_RE.test(question) || HATE_RE.test(question) || intlDirtyTokens(question)) return BRIDGE_ADULT_MSG;
  if (PERSONAL_SHARE_RE.test(question)) return BRIDGE_PRIVATE_MSG;
  if (PERSONAL_ASK_RE.test(question)) return BRIDGE_REPHRASE_MSG;
  if (STUDENT_CHAT_RE.test(question)) return BRIDGE_ADULT_MSG;
  return null;
}
// Keep answers short: at most two sentences, and never anything that trips the word filters.
function bridgeClean(answer) {
  let a = (answer || "").replace(/\s+/g, " ").trim();
  if (!a) return BRIDGE_REPHRASE_MSG;
  // Fixed founder-approved messages are never cut short.
  if (a.startsWith("Sorry, please consult with an adult") || a.startsWith("Please ask this question differently")) return a.startsWith("Sorry") ? BRIDGE_ADULT_MSG : BRIDGE_REPHRASE_MSG;
  if (BAD_WORDS_RE.test(a) || HATE_RE.test(a)) return BRIDGE_ADULT_MSG;
  const sentences = a.match(/[^.!?]+[.!?]+(\s|$)|[^.!?]+$/g) || [a];
  a = sentences.slice(0, 2).join("").trim();
  if (a.length > 220) a = a.slice(0, 220).replace(/\s+\S*$/, "") + ".";
  return a;
}

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
  let blocked = bridgeFilter(question);
  if (!blocked && needsGuard(question) && (await guardBlocks(env, question))) blocked = BRIDGE_ADULT_MSG;
  if (blocked) {
    // Answered with a fixed, short message. Nothing is sent to the AI and nothing is stored.
    return jsonResponse({ answer: blocked }, 200, request);
  }
  // Greetings and thanks are answered without the AI, so they always work (even if the daily AI limit is used up).
  const gq = question.toLowerCase().replace(/[^a-z ]/g, "").replace(/(.)\1{2,}/g, "$1$1").trim();
  const gw = gq.split(/\s+/).filter(Boolean);
  // "hi", "hello", "hey bridge", and misspellings like "hi beidge": short and starting with a greeting word
  if (gw.length >= 1 && gw.length <= 3 && /^(h+i+|h+e+l+o+|hel+o|hey+|hiya|hallo|hola|yo|howdy|good)$/.test(gw[0]) && (gw.length === 1 || gw[0] === "good" ? true : gw.slice(1).every((x) => x.length <= 9))) {
    if (gw[0] !== "good" || /^good (morning|afternoon|evening)/.test(gq)) {
      return jsonResponse({ answer: "Hi! I am Bridge. Ask me about an English word, or how to say a word from your language in English!" }, 200, request);
    }
  }
  if (/^(thanks?|thank you|thx|ty)( bridge+e*)?( so much)?$/.test(gq)) {
    return jsonResponse({ answer: "You are welcome! Keep learning, you are doing great!" }, 200, request);
  }
  if (isTimeQuestion(question)) {
    // Answered deterministically (see the world-clock section above) —
    // the AI model has no real clock, so letting it guess would just
    // produce a confident, wrong answer.
    answer = answerTimeQuestion(question);
  } else {
    if (!(await aiAllowed(env, "chat"))) {
      return jsonResponse({ error: "Bridge is resting for today. Please try again tomorrow!" }, 503, request);
    }
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
        max_tokens: 110,
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
      answer = bridgeClean(rawAnswer);
      aiSpend(env, NEURONS_PER_CHAT);
    } catch (e) {
      // Log the real error so it shows up in the Cloudflare dashboard's
      // Observability/Logs view (Message column) instead of being invisible —
      // the response to the student stays generic/kid-safe either way.
      console.error("Ask Bridge AI call failed:", e && e.message ? e.message : e);
      const su = await getSessionUser(request, env);
      const detail = su && su.role === "founder" ? " [founder only: " + String(e && e.message ? e.message : e).slice(0, 200) + "]" : "";
      return jsonResponse(
        { error: "Bridge couldn't think of an answer right now. Please try again in a moment." + detail },
        502,
        request
      );
    }
  }

  // Privacy: questions and answers are NOT saved anywhere (founder rule, 2026-11-09).
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


// ---- AI budget guard (2026-11-15) ----
// Cloudflare gives 10,000 "neurons" a day for ALL AI together, free. The founder is on Workers Paid (from 2026-11-15), so AI can
// go past that and is billed at $0.011 per 1,000 neurons. Three limits keep the bill small:
//  1. Free part: new voice lines stop at 6,000 and chat at 9,500 so voices can never use the whole free day and kill Ask Bridge.
//  2. Daily paid part: with Paid, new voice lines stop at AI_VOICE_CAP and chat at AI_CHAT_CAP (about $0.44 and $0.55 a day at most).
//  3. 30-day paid part: all neurons above the free 10,000 per day, summed over the last 30 days, can never pass AI_PAID_30D_CAP
//     (150,000 = about $1.65). After that the site goes back to the free-only limits until the 30-day window moves on.
// The counts are estimates (NEURONS_PER_CHAT, 2.9 per voice character), so the real bill is kept under $2 on purpose.
const AI_FREE_VOICE_CAP = 6000;
const AI_FREE_CHAT_CAP = 9500;
const AI_VOICE_CAP = 50000;
const AI_CHAT_CAP = 60000;
const AI_PAID_30D_CAP = 150000;
const NEURONS_PER_CHAT = 30;
const ANON_NEW_LINES_PER_DAY = 60; // fresh (never-saved) voice lines one logged-out visitor can cause per day
function budgetDay() { return new Date().toISOString().slice(0, 10); }
async function aiUsedToday(env) {
  try { const r = await env.DB.prepare("SELECT n FROM ai_budget WHERE day = ?").bind(budgetDay()).first(); return r ? r.n : 0; } catch (e) { return 0; }
}
async function aiPaid30d(env) {
  try {
    const r = await env.DB.prepare("SELECT SUM(CASE WHEN n > 10000 THEN n - 10000 ELSE 0 END) AS p FROM ai_budget WHERE day >= date('now', '-30 days')").first();
    return r && r.p ? r.p : 0;
  } catch (e) { return 0; }
}
// kind: "chat" or "voice". True when one more AI call is allowed right now.
async function aiAllowed(env, kind) {
  const used = await aiUsedToday(env);
  const freeCap = kind === "chat" ? AI_FREE_CHAT_CAP : AI_FREE_VOICE_CAP;
  if (used < freeCap) return true;
  const dayCap = kind === "chat" ? AI_CHAT_CAP : AI_VOICE_CAP;
  if (used >= dayCap) return false;
  return (await aiPaid30d(env)) < AI_PAID_30D_CAP;
}
async function aiSpend(env, n) {
  try { await env.DB.prepare("INSERT INTO ai_budget (day, n) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET n = n + excluded.n").bind(budgetDay(), Math.ceil(n)).run(); } catch (e) {}
}

// ---- Text-to-speech (added 2026-11-10) ----
// Friendly voices from Workers AI (Deepgram Aura). Signed-in users only. Audio is cached at
// Cloudflare's edge so each line is only generated once. The site falls back to the device voice on any error.
const TTS_VOICES = { boy: "arcas", girl: "asteria" };
const TTS_SAMPLE_SPEAKERS = ["angus","asteria","arcas","orion","orpheus","athena","luna","zeus","perseus","helios","hera","stella"];
// Aura-2 voices (voice lab only, 2026-11-15): a newer, more natural family.
const TTS2_SPEAKERS = ["thalia","andromeda","helena","apollo","arcas","aries","amalthea","asteria","athena","atlas","aurora","callista","cora","cordelia","delia","draco","electra","harmonia","hera","hermes","hyperion","iris","janus","juno","jupiter","luna","mars","minerva","neptune","odysseus","ophelia","orion","orpheus","pandora","phoebe","pluto","saturn","selene","theia","vesta","zeus"];
async function handleTts(request, env, url, ctx) {
  // 2026-11-16: visitors who are not logged in (Try a Lesson, the home page, people who just got the link) must hear
  // Apollo and Callista too. Saved lines are free for everyone. A line that has to be made fresh by the AI is allowed
  // for visitors up to ANON_NEW_LINES_PER_DAY per person (IP address) per day, on top of the daily AI budget guard.
  const signedIn = !!(await getSessionUser(request, env));
  const text = (url.searchParams.get("text") || "").trim().slice(0, 220);
  if (!text) return jsonResponse({ error: "No text." }, 400, request);
  let speaker = TTS_VOICES[url.searchParams.get("voice")] || TTS_VOICES.boy;
  const sp = url.searchParams.get("speaker");
  if (sp && TTS_SAMPLE_SPEAKERS.includes(sp)) speaker = sp;
  const engine = url.searchParams.get("engine") || "aura1";
  if (engine === "aura2" && TTS2_SPEAKERS.includes(sp || "")) speaker = sp;
  const cacheKey = new Request("https://tts.cache.lingua-bridge.us/" + engine + "/" + speaker + "/" + encodeURIComponent(text));
  const cache = caches.default;
  let audio = await cache.match(cacheKey);
  // Permanent copy in D1 (2026-11-15): every line is made by the AI only ONCE ever, then reused for every child.
  // This protects Cloudflare's free daily AI limit, which Ask Bridge shares with the voices.
  const dbKey = engine + "/" + speaker + "/" + text;
  if (!audio) {
    try {
      const row = await env.DB.prepare("SELECT a FROM tts_cache WHERE k = ?").bind(dbKey).first();
      if (row && row.a) {
        const bin = atob(row.a);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        audio = new Response(bytes, { headers: { "Content-Type": "audio/mpeg", "Cache-Control": "public, max-age=2592000" } });
        ctx.waitUntil(cache.put(cacheKey, audio.clone()));
      }
    } catch (e) {}
  }
  if (!audio && !signedIn) {
    const anonKey = "tts:ip:" + clientIp(request);
    if (await isLocked(env, anonKey)) return jsonResponse({ error: "Voice resting for today." }, 429, request);
    await recordFailure(env, anonKey, ANON_NEW_LINES_PER_DAY, 24 * 60 * 60 * 1000, 24 * 60 * 60 * 1000);
  }
  if (!audio && !(await aiAllowed(env, "voice"))) {
    return jsonResponse({ error: "Voice resting for today." }, 503, request);
  }
  if (!audio) {
    try {
      let buf;
      if (engine === "melo") {
        const out = await env.AI.run("@cf/myshell-ai/melotts", { prompt: text, lang: "en" });
        const b64 = typeof out === "string" ? out : out && out.audio;
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        buf = bytes.buffer;
      } else {
        const model = engine === "aura2" ? "@cf/deepgram/aura-2-en" : "@cf/deepgram/aura-1";
        const resp = await env.AI.run(model, { text, speaker, encoding: "mp3" }, { returnRawResponse: true });
        buf = await resp.arrayBuffer();
      }
      if (!buf.byteLength) throw new Error("empty");
      ctx.waitUntil(aiSpend(env, text.length * (engine === "aura2" ? 2.9 : 1.5)));
      audio = new Response(buf, { headers: { "Content-Type": "audio/mpeg", "Cache-Control": "public, max-age=2592000" } });
      ctx.waitUntil(cache.put(cacheKey, audio.clone()));
      if (buf.byteLength < 1500000) {
        let b64 = "";
        const u8 = new Uint8Array(buf);
        for (let i = 0; i < u8.length; i += 8192) b64 += String.fromCharCode.apply(null, u8.subarray(i, i + 8192));
        ctx.waitUntil(env.DB.prepare("INSERT OR REPLACE INTO tts_cache (k, a, created_at) VALUES (?, ?, ?)").bind(dbKey, btoa(b64), Date.now()).run().catch(() => {}));
      }
    } catch (e) {
      return jsonResponse({ error: "Voice unavailable." }, 503, request);
    }
  }
  return new Response(audio.body, {
    status: 200,
    headers: { "Content-Type": "audio/mpeg", "Cache-Control": "private, max-age=3600", "X-Content-Type-Options": "nosniff", ...corsHeaders(request) },
  });
}

// ---- AI photos for lessons/games/videos (added 2026-11-15) ----
// Makes a realistic, child-safe photo for a word or phrase with Workers AI (FLUX.1 schnell).
// Signed-in users only. The seed comes from the word, so a word always gets the same picture,
// and the result is cached at Cloudflare's edge. The site shows its normal icon if this fails.
const PHOTO_OK_RE = /^[A-Za-z0-9 ,.'!?\-\/&]+$/;
function photoSeed(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
  return (h >>> 0) % 1000000;
}
async function handlePhoto(request, env, url, ctx) {
  if (!(await getSessionUser(request, env))) {
    return jsonResponse({ error: "Please log in." }, 401, request);
  }
  const w = (url.searchParams.get("w") || "").trim().slice(0, 60);
  const h = (url.searchParams.get("h") || "").trim().slice(0, 140);
  if (!w || !PHOTO_OK_RE.test(w) || (h && !PHOTO_OK_RE.test(h))) {
    return jsonResponse({ error: "Bad request." }, 400, request);
  }
  if (BAD_WORDS_RE.test(w) || BAD_WORDS_RE.test(h)) {
    return jsonResponse({ error: "Not allowed." }, 400, request);
  }
  const key = (w + "|" + h).toLowerCase();
  const cacheKey = new Request("https://photo.cache.lingua-bridge.us/v1/" + encodeURIComponent(key));
  const cache = caches.default;
  let hit = await cache.match(cacheKey);
  if (!hit) {
    const prompt =
      'A bright, realistic, high quality photograph for a children\'s English lesson. It shows: "' + w + '"' +
      (h ? " (" + h + ")" : "") +
      ". One clear main subject in the center, simple clean background, natural colors, happy and friendly, safe for young children. No text, no letters, no words, no watermark, no logos.";
    try {
      const out = await env.AI.run("@cf/black-forest-labs/flux-1-schnell", { prompt, steps: 4, seed: photoSeed(key) });
      const b64 = out && out.image;
      if (!b64) throw new Error("no image");
      const bin = atob(b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      hit = new Response(bytes, { headers: { "Content-Type": "image/jpeg", "Cache-Control": "public, max-age=2592000" } });
      ctx.waitUntil(cache.put(cacheKey, hit.clone()));
    } catch (e) {
      return jsonResponse({ error: "Photo unavailable." }, 503, request);
    }
  }
  return new Response(hit.body, {
    status: 200,
    headers: { "Content-Type": "image/jpeg", "Cache-Control": "private, max-age=86400", "X-Content-Type-Options": "nosniff", ...corsHeaders(request) },
  });
}

export default {
  async fetch(request, env, ctx) {
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
    if (url.pathname === "/api/photo" && request.method === "GET") {
      return handlePhoto(request, env, url, ctx);
    }
    if (url.pathname === "/api/tts" && request.method === "GET") {
      return handleTts(request, env, url, ctx);
    }
    if (url.pathname === "/api/ai-check" && request.method === "GET") {
      // Founder-only: tests the AI right now and shows the real error text (for finding why Bridge fails).
      if (!(await requireFounder(request, env))) return jsonResponse({ error: "Not allowed." }, 403, request);
      const out = {};
      try {
        const r = await env.AI.run(ASK_BRIDGE_MODEL, { messages: [{ role: "user", content: "Say hi in three words." }], max_tokens: 20 });
        out.chat = { ok: true, reply: (r && (r.response || (r.choices && r.choices[0] && r.choices[0].message && r.choices[0].message.content))) || r };
      } catch (e) { out.chat = { ok: false, error: String(e && e.message ? e.message : e) }; }
      try {
        const r2 = await env.AI.run("@cf/deepgram/aura-2-en", { text: "Hello.", speaker: "apollo", encoding: "mp3" }, { returnRawResponse: true });
        out.voice = { ok: true, bytes: (await r2.arrayBuffer()).byteLength };
      } catch (e) { out.voice = { ok: false, error: String(e && e.message ? e.message : e) }; }
      try { const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM tts_cache").first(); out.saved_voice_lines = c && c.n; } catch (e) { out.saved_voice_lines = "no table"; }
      return jsonResponse(out, 200, request);
    }
    if (url.pathname === "/api/ask-bridge" && request.method === "POST") {
      return handleAskBridge(request, env);
    }

    return jsonResponse({ error: "Not found." }, 404, request);
  },
};
