/**
 * LinguaBridge Auth API (Cloudflare Worker)
 * ------------------------------------------------------------------
 * Real backend authentication, replacing the old client-side placeholder
 * lock. Currently scoped to the founder account only — public/student
 * accounts are intentionally NOT implemented yet (credential type for
 * students has not been decided: email, username, or school+student code).
 *
 * Runs on its own subdomain (api.lingua-bridge.us) so the main site's
 * existing GitHub Pages DNS is never touched. Cross-origin calls from
 * lingua-bridge.us use CORS + credentials:"include".
 *
 * Endpoints:
 *   POST /api/login   { username, password } -> sets httpOnly session cookie
 *   GET  /api/me                              -> { authenticated, username, role }
 *   POST /api/logout                          -> clears session cookie
 *
 * Bindings required (set in the Cloudflare dashboard when creating the Worker):
 *   DB -> the "linguabridge" D1 database
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

async function handleLogin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "Invalid request body." }, 400, request);
  }

  const username = (body.username || "").trim();
  const password = body.password || "";

  if (!username || !password) {
    return jsonResponse(
      { error: "Username and password are required." },
      400,
      request
    );
  }

  const user = await env.DB.prepare(
    "SELECT id, username, password_hash, password_salt, iterations, role FROM users WHERE username = ?"
  )
    .bind(username)
    .first();

  // Same error for "no such user" and "wrong password" — don't leak which.
  if (!user) {
    return jsonResponse(
      { error: "Incorrect username or password." },
      401,
      request
    );
  }

  const ok = await verifyPassword(
    password,
    user.password_salt,
    user.iterations,
    user.password_hash
  );

  if (!ok) {
    return jsonResponse(
      { error: "Incorrect username or password." },
      401,
      request
    );
  }

  const token = crypto.randomUUID() + crypto.randomUUID();
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);

  await env.DB.prepare(
    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
  )
    .bind(token, user.id, expiresAt.toISOString())
    .run();

  const cookie = [
    `${SESSION_COOKIE}=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None", // cross-subdomain (lingua-bridge.us -> api.lingua-bridge.us)
    `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`,
  ].join("; ");

  return jsonResponse(
    { authenticated: true, username: user.username, role: user.role },
    200,
    request,
    { "Set-Cookie": cookie }
  );
}

async function handleMe(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return jsonResponse({ authenticated: false }, 200, request);

  const row = await env.DB.prepare(
    `SELECT sessions.expires_at as expires_at, users.username as username, users.role as role
     FROM sessions JOIN users ON users.id = sessions.user_id
     WHERE sessions.token = ?`
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

    if (url.pathname === "/api/login" && request.method === "POST") {
      return handleLogin(request, env);
    }
    if (url.pathname === "/api/me" && request.method === "GET") {
      return handleMe(request, env);
    }
    if (url.pathname === "/api/logout" && request.method === "POST") {
      return handleLogout(request, env);
    }

    return jsonResponse({ error: "Not found." }, 404, request);
  },
};
