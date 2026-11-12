// Serves the app from /public (ASSETS binding) and provides the API:
//   POST /api/signup, /api/login, /api/logout, GET /api/me, PUT /api/state  (accounts, need the D1 binding "DB")
//   POST /api/plan                                                           (AI plan maker, needs ANTHROPIC_API_KEY)
const MODEL = "claude-haiku-5-5";
const enc = new TextEncoder();
const SESSION_DAYS = 30;
const COOKIE = "anchor_session";

function json(body, status, headers) {
  const h = new Headers({ "content-type": "application/json", "cache-control": "no-store" });
  if (headers) for (const k in headers) h.append(k, headers[k]);
  return new Response(JSON.stringify(body), { status: status || 200, headers: h });
}

/* ---------- crypto helpers ---------- */
function toHex(buf) {
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
async function hashPassword(password, saltBytes) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: 100000 }, key, 256);
  return toHex(bits);
}
async function sha256Hex(text) {
  return toHex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}
function sameString(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

/* ---------- database ---------- */
let schemaReady = null;
function ensureSchema(env) {
  if (!schemaReady) {
    schemaReady = env.DB.batch([
      env.DB.prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, created INTEGER NOT NULL)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS states (user_id INTEGER PRIMARY KEY, json TEXT NOT NULL, updated INTEGER NOT NULL)"),
    ]).catch((e) => { schemaReady = null; throw e; });
  }
  return schemaReady;
}

function getCookie(request, name) {
  const raw = request.headers.get("cookie") || "";
  const parts = raw.split(/;\s*/);
  for (const p of parts) {
    const i = p.indexOf("=");
    if (i > 0 && p.slice(0, i) === name) return p.slice(i + 1);
  }
  return null;
}
function cookieHeader(token, maxAge) {
  return COOKIE + "=" + token + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=" + maxAge;
}

async function currentUser(request, env) {
  const token = getCookie(request, COOKIE);
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return null;
  const th = await sha256Hex(token);
  const row = await env.DB.prepare(
    "SELECT users.id AS id, users.username AS username FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ? AND sessions.expires > ?"
  ).bind(th, Date.now()).first();
  return row || null;
}

async function createSession(env, userId) {
  const token = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const th = await sha256Hex(token);
  const expires = Date.now() + SESSION_DAYS * 86400000;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE expires < ?").bind(Date.now()),
    env.DB.prepare("INSERT INTO sessions (token_hash, user_id, expires) VALUES (?, ?, ?)").bind(th, userId, expires),
  ]);
  return token;
}

/* ---------- account routes ---------- */
function cleanUsername(v) { return String(v || "").trim().toLowerCase(); }

async function signup(request, env) {
  let b; try { b = await request.json(); } catch (e) { return json({ error: "bad_request", message: "Something went wrong. Try again." }, 400); }
  const username = cleanUsername(b.username), password = String(b.password || "");
  if (!/^[a-z0-9_]{3,20}$/.test(username)) return json({ error: "username", message: "Usernames are 3 to 20 letters, numbers or underscores." }, 400);
  if (password.length < 8 || password.length > 100) return json({ error: "password", message: "Passwords need at least 8 characters." }, 400);
  const exists = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
  if (exists) return json({ error: "taken", message: "That username is taken." }, 409);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(password, salt);
  let res;
  try {
    res = await env.DB.prepare("INSERT INTO users (username, salt, hash, created) VALUES (?, ?, ?, ?)").bind(username, toHex(salt), hash, Date.now()).run();
  } catch (e) { return json({ error: "taken", message: "That username is taken." }, 409); }
  const userId = res.meta.last_row_id;
  const token = await createSession(env, userId);
  return json({ username }, 200, { "set-cookie": cookieHeader(token, SESSION_DAYS * 86400) });
}

async function login(request, env) {
  let b; try { b = await request.json(); } catch (e) { return json({ error: "bad_request", message: "Something went wrong. Try again." }, 400); }
  const username = cleanUsername(b.username), password = String(b.password || "");
  const bad = json({ error: "credentials", message: "Wrong username or password." }, 401);
  if (!username || !password || password.length > 100) return bad;
  const u = await env.DB.prepare("SELECT id, salt, hash FROM users WHERE username = ?").bind(username).first();
  if (!u) { await hashPassword(password, crypto.getRandomValues(new Uint8Array(16))); return bad; }
  const hash = await hashPassword(password, fromHex(u.salt));
  if (!sameString(hash, u.hash)) return bad;
  const token = await createSession(env, u.id);
  return json({ username }, 200, { "set-cookie": cookieHeader(token, SESSION_DAYS * 86400) });
}

async function logout(request, env) {
  const token = getCookie(request, COOKIE);
  if (token && /^[0-9a-f]{64}$/.test(token)) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256Hex(token)).run();
  }
  return json({ ok: true }, 200, { "set-cookie": cookieHeader("", 0) });
}

async function me(request, env) {
  const u = await currentUser(request, env);
  if (!u) return json({ error: "unauthorized" }, 401);
  const row = await env.DB.prepare("SELECT json FROM states WHERE user_id = ?").bind(u.id).first();
  let state = null;
  if (row) { try { state = JSON.parse(row.json); } catch (e) { state = null; } }
  return json({ username: u.username, state });
}

async function putState(request, env) {
  const u = await currentUser(request, env);
  if (!u) return json({ error: "unauthorized" }, 401);
  const text = await request.text();
  if (text.length > 400000) return json({ error: "too_big" }, 413);
  let s; try { s = JSON.parse(text); } catch (e) { return json({ error: "bad_request" }, 400); }
  if (!s || !Array.isArray(s.goals)) return json({ error: "bad_request" }, 400);
  await env.DB.prepare(
    "INSERT INTO states (user_id, json, updated) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET json = excluded.json, updated = excluded.updated"
  ).bind(u.id, text, Date.now()).run();
  return json({ ok: true });
}

/* ---------- AI plan maker ---------- */
async function makePlan(request, env) {
  if (!env.ANTHROPIC_API_KEY) return json({ error: "not_configured" }, 501);
  // When accounts are set up, only signed-in people can spend API credit.
  if (env.DB) {
    await ensureSchema(env);
    if (!(await currentUser(request, env))) return json({ error: "unauthorized" }, 401);
  }

  let body;
  try { body = await request.json(); } catch (e) { return json({ error: "bad_request" }, 400); }
  const goal = String(body.goal || "").trim().slice(0, 120);
  const days = Number(body.days);
  if (!goal || !Number.isInteger(days) || days < 3 || days > 30) return json({ error: "bad_request" }, 400);

  const prompt =
    "You are a practical coach. The person's goal: \"" + goal + "\".\n" +
    "Break it into exactly " + days + " daily steps, one per day, in order. Each step is a small, concrete action " +
    "that takes about 20 to 30 minutes, builds on the day before, and is written as an instruction (for example " +
    "\"Read 20 pages of your book\"). Keep each step under 60 characters. Make the last day a short review or wrap-up.\n" +
    "Reply with JSON only, no other text, in this shape: {\"steps\":[\"...\"]}";

  let res;
  try {
    res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: MODEL, max_tokens: 2000, messages: [{ role: "user", content: prompt }] }),
    });
  } catch (e) { return json({ error: "upstream" }, 502); }
  if (!res.ok) return json({ error: "upstream" }, 502);

  const data = await res.json();
  const text = (data.content || []).map((b) => b.text || "").join("");
  const match = text.match(/\{[\s\S]*\}/);
  if (!match) return json({ error: "parse" }, 502);
  let steps;
  try { steps = JSON.parse(match[0]).steps; } catch (e) { return json({ error: "parse" }, 502); }
  if (!Array.isArray(steps) || !steps.length) return json({ error: "parse" }, 502);
  steps = steps.slice(0, days).map((s) => String(s).trim().slice(0, 80));
  return json({ steps });
}

/* ---------- router ---------- */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);

    try {
      // Block cross-site writes.
      if (request.method !== "GET") {
        const origin = request.headers.get("origin");
        if (origin && origin !== url.origin) return json({ error: "forbidden" }, 403);
      }

      if (path === "/api/plan") {
        if (request.method !== "POST") return json({ error: "method" }, 405);
        return await makePlan(request, env);
      }

      const accountRoutes = { "/api/signup": "POST", "/api/login": "POST", "/api/logout": "POST", "/api/me": "GET", "/api/state": "PUT" };
      if (accountRoutes[path]) {
        if (!env.DB) return json({ error: "not_configured" }, 501);
        if (request.method !== accountRoutes[path]) return json({ error: "method" }, 405);
        await ensureSchema(env);
        if (path === "/api/signup") return await signup(request, env);
        if (path === "/api/login") return await login(request, env);
        if (path === "/api/logout") return await logout(request, env);
        if (path === "/api/me") return await me(request, env);
        return await putState(request, env);
      }
      return json({ error: "not_found" }, 404);
    } catch (e) {
      return json({ error: "server" }, 500);
    }
  },
};
