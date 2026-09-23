const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extra,
    },
  });

const corsHeaders = (request, env) => {
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);

  if (!origin || allowed.includes(origin)) {
    return {
      "access-control-allow-origin": origin || "*",
      "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
      "access-control-allow-headers": "content-type,authorization",
      "access-control-max-age": "86400",
      vary: "Origin",
    };
  }
  return {};
};

const utf8 = (value) => new TextEncoder().encode(value);

const base64url = (bytes) => {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const fromBase64url = (value) => {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const raw = atob(padded);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
};

async function sha256Hex(value) {
  const hash = await crypto.subtle.digest("SHA-256", typeof value === "string" ? utf8(value) : value);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const PIN_ITERATIONS = 100000;

async function hashPin(pin, saltBytes = null) {
  const salt = saltBytes || crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", utf8(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PIN_ITERATIONS },
    keyMaterial,
    256
  );
  return `pbkdf2$${PIN_ITERATIONS}$${base64url(salt)}$${base64url(new Uint8Array(bits))}`;
}

async function verifyPin(pin, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 10000 || iterations > 1000000) return false;
  const salt = fromBase64url(parts[2]);
  const expected = fromBase64url(parts[3]);
  const keyMaterial = await crypto.subtle.importKey("raw", utf8(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations },
      keyMaterial,
      expected.length * 8
    )
  );
  if (bits.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < bits.length; i++) diff |= bits[i] ^ expected[i];
  return diff === 0;
}

let authSchemaReady = false;
async function ensureAuthSchema(env) {
  if (authSchemaReady) return;
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS auth_sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON auth_sessions(expires_at)"
  ).run();
  authSchemaReady = true;
}

function bearer(request) {
  const auth = request.headers.get("authorization") || "";
  return auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
}

async function createSession(env, userId) {
  await ensureAuthSchema(env);
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const token = base64url(raw);
  const tokenHash = await sha256Hex(raw);
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = 60 * 60 * 12;
  const expiresAt = now + expiresIn;

  await env.DB.prepare(
    "INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)"
  ).bind(tokenHash, userId, expiresAt).run();

  return { token, expiresIn, expiresAt };
}

async function requireSession(request, env) {
  const token = bearer(request);
  if (!token || !env.DB) return null;
  await ensureAuthSchema(env);
  const tokenHash = await sha256Hex(fromBase64url(token));
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    `SELECT s.user_id, s.expires_at, u.email, u.display_name
     FROM auth_sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND u.active = 1
     LIMIT 1`
  ).bind(tokenHash, now).first();

  return row || null;
}

async function login(request, env) {
  if (!env.DB) return json({ ok: false, error: "D1_NOT_BOUND" }, 503);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "INVALID_JSON" }, 400);
  }

  const pin = String(body?.pin || "").trim();
  if (!/^\d{4,20}$/.test(pin)) {
    return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);
  }

  const users = await env.DB.prepare(
    "SELECT id, email, display_name, pin_hash FROM users WHERE active = 1 ORDER BY display_name"
  ).all();

  let user = null;
  for (const candidate of users.results || []) {
    if (await verifyPin(pin, candidate.pin_hash)) {
      user = candidate;
      break;
    }
  }

  if (!user) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

  const sessionData = await createSession(env, user.id);

  await env.DB.prepare(
    "INSERT INTO app_log (event_type, user_id, details_json) VALUES ('login', ?1, ?2)"
  ).bind(user.id, JSON.stringify({ source: "cloudflare", auth: "d1-session" })).run();

  return json({
    ok: true,
    token: sessionData.token,
    expires_in: sessionData.expiresIn,
    user: { id: user.id, email: user.email, name: user.display_name },
  });
}

async function session(request, env) {
  const auth = await requireSession(request, env);
  if (!auth) return json({ ok: false, error: "UNAUTHORIZED" }, 401);
  return json({
    ok: true,
    user: { id: auth.user_id, email: auth.email, name: auth.display_name },
    expires_at: auth.expires_at,
  });
}

async function logout(request, env) {
  const token = bearer(request);
  if (!token || !env.DB) return json({ ok: true });
  try {
    await ensureAuthSchema(env);
    const tokenHash = await sha256Hex(fromBase64url(token));
    await env.DB.prepare("DELETE FROM auth_sessions WHERE token_hash = ?1").bind(tokenHash).run();
  } catch (_) {}
  return json({ ok: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = corsHeaders(request, env);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    let response;
    try {
      if (url.pathname === "/api/health" && request.method === "GET") {
        response = json({
          ok: true,
          service: "club-deportivo-api",
          d1: Boolean(env.DB),
          auth: "d1-sessions",
          time: new Date().toISOString(),
        });
      } else if (url.pathname === "/api/login" && request.method === "POST") {
        response = await login(request, env);
      } else if (url.pathname === "/api/session" && request.method === "GET") {
        response = await session(request, env);
      } else if (url.pathname === "/api/logout" && request.method === "POST") {
        response = await logout(request, env);
      } else {
        response = json({ ok: false, error: "NOT_FOUND" }, 404);
      }
    } catch (error) {
      console.error(error);
      response = json({ ok: false, error: "INTERNAL_ERROR" }, 500);
    }

    const headers = new Headers(response.headers);
    for (const [key, value] of Object.entries(cors)) headers.set(key, value);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  },
};
