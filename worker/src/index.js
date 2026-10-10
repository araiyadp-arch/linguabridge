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
 *   POST /api/login       { username, password } -> sets httpOnly session cookie
 *   GET  /api/me                                  -> { authenticated, username, role }
 *   POST /api/logout                              -> clears session cookie
 *   POST /api/ask-bridge  { question, level?, lessonTopic? } -> { answer }
 *        "Ask Bridge" — lets a student type a question to Bridge and get a
 *        real answer, using Cloudflare Workers AI (no external API key
 *        needed). Scoped hard to kid-safe, English-learning topics by the
 *        system prompt below; rate-limited per visitor via KV; every
 *        exchange is logged to D1 (bridge_questions) so the founder can
 *        review what kids are actually asking/getting. NOT behind the
 *        founder login — the lesson pages themselves aren't login-gated
 *        yet either (no real student accounts exist), so this endpoint's
 *        safety has to come from the system prompt + rate limit, not from
 *        "only logged-in users can reach it."
 *
 * Bindings required (set in the Cloudflare dashboard when creating the Worker):
 *   DB         -> the "linguabridge" D1 database
 *   AI         -> Workers AI (Settings -> Bindings -> Add -> Workers AI; no
 *                 extra setup/account needed, it's built into Cloudflare)
 *   RATE_LIMIT -> the "linguabridge-ask-bridge-ratelimit" KV namespace
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
const ASK_BRIDGE_DAILY_LIMIT = 40; // per visitor (by IP), resets daily

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

You can help with anything a kid might reasonably ask a helpful teacher: English learning (words, grammar, pronunciation, spelling), homework help in other school subjects, how things work, general knowledge, fun facts, and simple everyday questions. Answer in short, warm, age-appropriate sentences (2-5 sentences max). Use simple words for the age group. Be encouraging, like a kind teacher.

If the conversation drifts away from English learning (games, random topics, chit-chat), that's fine — answer briefly and kindly, then gently steer things back toward an English word, a bit of reading, or practice, instead of refusing to engage. Ease back toward English over a turn or two rather than snapping back to it abruptly.

If a student writes in a language other than English, you can understand it — don't ignore or refuse a message just because it isn't in English. Respond warmly (a short reply in their language is fine), and also give the English version of your answer so they pick up more English from every exchange. Gently invite them to try their next message in English when it feels natural.

You do not have access to a live clock, calendar, or current-events feed, so never guess or make up the current time, date, or something happening live right now — say plainly that you can't know that instead of inventing an answer.

Hard rules, no exceptions:
- Never discuss or generate anything violent, sexual, scary, hateful, or otherwise inappropriate for a child.
- Never ask the student for personal information (full name, address, phone number, school name, photos, passwords, etc.), and if they share any, don't repeat it back or store it in your answer — just gently redirect to the question or lesson.
- If a question is about something an adult should handle instead (personal/family advice, medical or legal questions, serious current events, or anything else beyond general knowledge for a child), kindly say that's something to ask a teacher or parent, rather than answering it yourself.
- If a question suggests the student might be upset, in danger, or need help from an adult (bullying, being hurt, feeling unsafe, etc.), gently and clearly tell them to talk to a trusted adult, parent, or teacher right away. Do not try to solve that problem yourself.
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

  // Rate limit: N questions per visitor (by IP) per UTC day.
  const today = new Date().toISOString().slice(0, 10);
  const rlKey = `askbridge:${clientKey(request)}:${today}`;
  const countRaw = await env.RATE_LIMIT.get(rlKey);
  const count = countRaw ? parseInt(countRaw, 10) : 0;
  if (count >= ASK_BRIDGE_DAILY_LIMIT) {
    return jsonResponse(
      {
        error:
          "Bridge has answered a lot of questions today! Please try again tomorrow.",
      },
      429,
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

  // Best-effort: don't fail the response if logging or rate-limit bookkeeping hiccups.
  try {
    await env.RATE_LIMIT.put(rlKey, String(count + 1), { expirationTtl: 60 * 60 * 26 });
  } catch (e) {}
  try {
    await env.DB.prepare(
      "INSERT INTO bridge_questions (client_id, question, answer, level, lesson_topic) VALUES (?, ?, ?, ?, ?)"
    )
      .bind(clientKey(request), question, answer, level, lessonTopic)
      .run();
  } catch (e) {}

  return jsonResponse({ answer }, 200, request);
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
    if (url.pathname === "/api/ask-bridge" && request.method === "POST") {
      return handleAskBridge(request, env);
    }

    return jsonResponse({ error: "Not found." }, 404, request);
  },
};
