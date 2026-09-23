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

const INITIAL_EMAILS = new Set([
  "cesarperozo@losroblesenlinea.com.ve",
  "davidbarcelo@losroblesenlinea.com.ve",
  "alexandropolanco@losroblesenlinea.com.ve",
  "inrifereira@losroblesenlinea.com.ve",
]);

async function bootstrapStatus(env) {
  if (!env.DB) return json({ ok: false, error: "D1_NOT_BOUND" }, 503);
  const row = await env.DB.prepare("SELECT COUNT(*) AS total FROM users").first();
  const total = Number(row?.total || 0);
  return json({ ok: true, initialized: total > 0, users: total });
}

async function bootstrapUsers(request, env) {
  if (!env.DB) return json({ ok: false, error: "D1_NOT_BOUND" }, 503);

  const existing = await env.DB.prepare("SELECT COUNT(*) AS total FROM users").first();
  if (Number(existing?.total || 0) > 0) {
    return json({ ok: false, error: "BOOTSTRAP_CLOSED" }, 409);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "INVALID_JSON" }, 400);
  }

  const users = Array.isArray(body?.users) ? body.users : [];
  if (users.length !== INITIAL_EMAILS.size) {
    return json({ ok: false, error: "INITIAL_USERS_REQUIRED" }, 400);
  }

  const seenEmails = new Set();
  const seenPins = new Set();
  const prepared = [];

  for (const item of users) {
    const id = crypto.randomUUID();
    const email = String(item?.email || "").trim().toLowerCase();
    const name = String(item?.name || "").trim();
    const pin = String(item?.pin || "").trim();

    if (!INITIAL_EMAILS.has(email) || seenEmails.has(email) || !name || !/^\d{4,20}$/.test(pin)) {
      return json({ ok: false, error: "INVALID_USER_DATA", email }, 400);
    }
    if (seenPins.has(pin)) {
      return json({ ok: false, error: "DUPLICATE_PIN" }, 400);
    }

    seenEmails.add(email);
    seenPins.add(pin);
    prepared.push({ id, email, name, pinHash: await hashPin(pin) });
  }

  if (seenEmails.size !== INITIAL_EMAILS.size) {
    return json({ ok: false, error: "INITIAL_USERS_REQUIRED" }, 400);
  }

  const statements = prepared.map((u) =>
    env.DB.prepare(
      "INSERT INTO users (id, email, display_name, pin_hash, active) VALUES (?1, ?2, ?3, ?4, 1)"
    ).bind(u.id, u.email, u.name, u.pinHash)
  );

  await env.DB.batch(statements);

  await env.DB.prepare(
    "INSERT INTO app_log (event_type, details_json) VALUES ('bootstrap_users', ?1)"
  ).bind(JSON.stringify({ count: prepared.length, auth: "pbkdf2+d1-session" })).run();

  return json({
    ok: true,
    users: prepared.map(({ id, email, name }) => ({ id, email, name })),
    bootstrap_closed: true,
  });
}

function bootstrapPage() {
  return new Response(`<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Inicializar usuarios</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f6f7fb;color:#111827;margin:0;padding:24px}
main{max-width:760px;margin:auto;background:#fff;border:1px solid #e5e7eb;border-radius:20px;padding:24px}
h1{margin-top:0}.grid{display:grid;gap:12px}.row{display:grid;grid-template-columns:1.1fr 1.4fr 1fr;gap:10px}
input{width:100%;box-sizing:border-box;padding:11px 12px;border:1px solid #d1d5db;border-radius:10px;font-size:16px}
button{padding:12px 16px;border:0;border-radius:10px;background:#111827;color:#fff;font-weight:800;cursor:pointer}
button:disabled{opacity:.55;cursor:not-allowed}small{color:#6b7280}.status{margin-top:14px;font-weight:700}.ok{color:#166534}.err{color:#b91c1c}
@media(max-width:700px){.row{grid-template-columns:1fr}}
</style>
</head>
<body>
<main>
<h1>Inicializar usuarios</h1>
<p>Esta pantalla solo funciona mientras la base de datos no tenga usuarios. Las claves se transforman con PBKDF2 y una sal individual dentro de Cloudflare; no se guardan en texto plano. Al crear los usuarios, esta función se cierra automáticamente.</p>
<div class="grid" id="form">
  <div class="row"><input class="name" value="César Perozo"><input class="email" type="email" value="cesarperozo@losroblesenlinea.com.ve"><input class="pin" type="password" inputmode="numeric" placeholder="Clave"></div>
  <div class="row"><input class="name" value="David Barceló"><input class="email" type="email" value="davidbarcelo@losroblesenlinea.com.ve"><input class="pin" type="password" inputmode="numeric" placeholder="Clave"></div>
  <div class="row"><input class="name" value="Alexandro Polanco"><input class="email" type="email" value="alexandropolanco@losroblesenlinea.com.ve"><input class="pin" type="password" inputmode="numeric" placeholder="Clave"></div>
  <div class="row"><input class="name" value="Inri Fereira"><input class="email" type="email" value="inrifereira@losroblesenlinea.com.ve"><input class="pin" type="password" inputmode="numeric" placeholder="Clave"></div>
  <button id="save">Crear usuarios y cerrar inicialización</button>
  <small>Después podrás probar cada clave desde /login-test.</small>
  <div id="status" class="status"></div>
</div>
<script>
const save=document.getElementById('save');
async function check(){
  const r=await fetch('/api/setup-status');
  const d=await r.json();
  if(d.initialized){
    save.disabled=true;
    document.getElementById('status').className='status ok';
    document.getElementById('status').textContent='La base ya está inicializada con '+d.users+' usuarios. Esta pantalla está cerrada.';
  }
}
save.addEventListener('click', async () => {
  const status=document.getElementById('status');
  status.className='status';status.textContent='Procesando…';save.disabled=true;
  const names=[...document.querySelectorAll('.name')];
  const emails=[...document.querySelectorAll('.email')];
  const pins=[...document.querySelectorAll('.pin')];
  const users=names.map((n,i)=>({name:n.value.trim(),email:emails[i].value.trim(),pin:pins[i].value.trim()}));
  try{
    const r=await fetch('/api/admin/bootstrap-users',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({users})});
    const data=await r.json();
    if(!r.ok) throw new Error(data.error||'Error');
    status.className='status ok';
    status.textContent='Usuarios creados correctamente. La inicialización quedó cerrada.';
    document.querySelectorAll('.pin').forEach(i=>i.value='');
  }catch(e){
    save.disabled=false;
    status.className='status err';
    status.textContent='No se pudo completar: '+e.message;
  }
});
check();
</script>
</main>
</body>
</html>`, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

function loginTestPage() {
  return new Response(`<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Prueba de inicio de sesión</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f6f7fb;color:#111827;margin:0;padding:24px}
main{max-width:520px;margin:auto;background:#fff;border:1px solid #e5e7eb;border-radius:20px;padding:24px}
input,button{width:100%;box-sizing:border-box;padding:12px 14px;border-radius:10px;font-size:16px}
input{border:1px solid #d1d5db;margin:12px 0}button{border:0;background:#111827;color:#fff;font-weight:800;cursor:pointer}
.status{margin-top:14px;font-weight:700}.ok{color:#166534}.err{color:#b91c1c}
</style></head><body><main>
<h1>Prueba de inicio de sesión</h1>
<p>Introduce una de las claves configuradas. La prueba también valida la sesión creada en D1.</p>
<input id="pin" type="password" inputmode="numeric" placeholder="Clave" autocomplete="off">
<button id="go">Probar acceso</button><div id="status" class="status"></div>
<script>
document.getElementById('go').addEventListener('click',async()=>{
 const status=document.getElementById('status');status.className='status';status.textContent='Verificando…';
 try{
  const r=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({pin:document.getElementById('pin').value.trim()})});
  const d=await r.json();if(!r.ok)throw new Error(d.error||'Error');
  const s=await fetch('/api/session',{headers:{authorization:'Bearer '+d.token}});
  const sd=await s.json();if(!s.ok)throw new Error(sd.error||'Sesión inválida');
  status.className='status ok';status.textContent='Acceso correcto: '+sd.user.name+' · '+sd.user.email;
  document.getElementById('pin').value='';
 }catch(e){status.className='status err';status.textContent='No se pudo iniciar sesión: '+e.message;}
});
</script></main></body></html>`, {
    headers: {"content-type":"text/html; charset=utf-8","cache-control":"no-store","x-robots-tag":"noindex, nofollow"},
  });
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
      if (url.pathname === "/api/env-check" && request.method === "GET") {
        response = json({
          ok: true,
          DB: Boolean(env.DB),
          ALLOWED_ORIGINS: Boolean(env.ALLOWED_ORIGINS),
          auth_mode: "pbkdf2+d1-sessions",
        });
      } else if (url.pathname === "/api/setup-status" && request.method === "GET") {
        response = await bootstrapStatus(env);
      } else if (url.pathname === "/bootstrap" && request.method === "GET") {
        response = bootstrapPage();
      } else if (url.pathname === "/login-test" && request.method === "GET") {
        response = loginTestPage();
      } else if (url.pathname === "/api/health" && request.method === "GET") {
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
      } else if (url.pathname === "/api/admin/bootstrap-users" && request.method === "POST") {
        response = await bootstrapUsers(request, env);
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
