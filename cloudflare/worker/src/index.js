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

const base64url = (bytes) => {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const utf8 = (value) => new TextEncoder().encode(value);

async function sha256Hex(value) {
  const hash = await crypto.subtle.digest("SHA-256", utf8(value));
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function signToken(payload, secret) {
  const header = base64url(utf8(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = base64url(utf8(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey(
    "raw",
    utf8(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, utf8(`${header}.${body}`));
  return `${header}.${body}.${base64url(new Uint8Array(signature))}`;
}

function decodeBase64url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const raw = atob(padded);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

async function verifyToken(token, secret) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  const [header, body, signature] = parts;
  const key = await crypto.subtle.importKey(
    "raw",
    utf8(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const ok = await crypto.subtle.verify(
    "HMAC",
    key,
    decodeBase64url(signature),
    utf8(`${header}.${body}`)
  );
  if (!ok) return null;
  const payload = JSON.parse(new TextDecoder().decode(decodeBase64url(body)));
  if (!payload.exp || Date.now() >= payload.exp * 1000) return null;
  return payload;
}

function bearer(request) {
  const auth = request.headers.get("authorization") || "";
  return auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
}

async function requireSession(request, env) {
  const token = bearer(request);
  if (!token || !env.SESSION_SECRET) return null;
  return verifyToken(token, env.SESSION_SECRET);
}

async function login(request, env) {
  if (!env.DB) return json({ ok: false, error: "D1_NOT_BOUND" }, 503);
  if (!env.PIN_PEPPER || !env.SESSION_SECRET) {
    return json({ ok: false, error: "AUTH_SECRETS_NOT_CONFIGURED" }, 503);
  }

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

  const pinHash = await sha256Hex(`${env.PIN_PEPPER}:${pin}`);
  const user = await env.DB.prepare(
    "SELECT id, email, display_name FROM users WHERE pin_hash = ?1 AND active = 1 LIMIT 1"
  )
    .bind(pinHash)
    .first();

  if (!user) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

  const now = Math.floor(Date.now() / 1000);
  const expiresIn = 60 * 60 * 12;
  const token = await signToken(
    { sub: user.id, email: user.email, name: user.display_name, iat: now, exp: now + expiresIn },
    env.SESSION_SECRET
  );

  await env.DB.prepare(
    "INSERT INTO app_log (event_type, user_id, details_json) VALUES ('login', ?1, ?2)"
  )
    .bind(user.id, JSON.stringify({ source: "cloudflare" }))
    .run();

  return json({
    ok: true,
    token,
    expires_in: expiresIn,
    user: { id: user.id, email: user.email, name: user.display_name },
  });
}

async function session(request, env) {
  const auth = await requireSession(request, env);
  if (!auth) return json({ ok: false, error: "UNAUTHORIZED" }, 401);
  return json({
    ok: true,
    user: { id: auth.sub, email: auth.email, name: auth.name },
    expires_at: auth.exp,
  });
}


// TEMPORARY_BOOTSTRAP_ROUTE
async function bootstrapUsers(request, env) {
  if (!env.DB) return json({ ok: false, error: "D1_NOT_BOUND" }, 503);
  if (!env.PIN_PEPPER || !env.BOOTSTRAP_SECRET) {
    return json({ ok: false, error: "BOOTSTRAP_NOT_CONFIGURED" }, 503);
  }

  const suppliedSecret = request.headers.get("x-bootstrap-secret") || "";
  if (!suppliedSecret || suppliedSecret !== env.BOOTSTRAP_SECRET) {
    return json({ ok: false, error: "UNAUTHORIZED" }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "INVALID_JSON" }, 400);
  }

  const users = Array.isArray(body?.users) ? body.users : [];
  if (!users.length || users.length > 20) {
    return json({ ok: false, error: "INVALID_USERS" }, 400);
  }

  const results = [];
  for (const item of users) {
    const id = String(item?.id || crypto.randomUUID()).trim();
    const email = String(item?.email || "").trim().toLowerCase();
    const name = String(item?.name || "").trim();
    const pin = String(item?.pin || "").trim();

    if (!email || !name || !/^\d{4,20}$/.test(pin)) {
      return json({ ok: false, error: "INVALID_USER_DATA", email }, 400);
    }

    const pinHash = await sha256Hex(`${env.PIN_PEPPER}:${pin}`);
    await env.DB.prepare(
      `INSERT INTO users (id, email, display_name, pin_hash, active)
       VALUES (?1, ?2, ?3, ?4, 1)
       ON CONFLICT(email) DO UPDATE SET
         display_name = excluded.display_name,
         pin_hash = excluded.pin_hash,
         active = 1,
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')`
    )
      .bind(id, email, name, pinHash)
      .run();

    results.push({ id, email, name });
  }

  return json({ ok: true, users: results });
}


// TEMPORARY_BOOTSTRAP_UI
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
h1{margin-top:0} .grid{display:grid;gap:12px}.row{display:grid;grid-template-columns:1.1fr 1.4fr 1fr;gap:10px}
input{width:100%;box-sizing:border-box;padding:11px 12px;border:1px solid #d1d5db;border-radius:10px;font-size:16px}
button{padding:12px 16px;border:0;border-radius:10px;background:#111827;color:#fff;font-weight:800;cursor:pointer}
small{color:#6b7280}.status{margin-top:14px;font-weight:700}.ok{color:#166534}.err{color:#b91c1c}
@media(max-width:700px){.row{grid-template-columns:1fr}}
</style>
</head>
<body>
<main>
<h1>Inicializar usuarios</h1>
<p>Esta pantalla es temporal. Introduce el secreto de bootstrap y los usuarios iniciales. Las claves se convierten a hash dentro de Cloudflare y no se guardan en texto plano.</p>
<div class="grid">
  <input id="secret" type="password" placeholder="BOOTSTRAP_SECRET" autocomplete="off">
  <div class="row"><input class="name" placeholder="Nombre"><input class="email" type="email" placeholder="Correo"><input class="pin" type="password" inputmode="numeric" placeholder="Clave"></div>
  <div class="row"><input class="name" placeholder="Nombre"><input class="email" type="email" placeholder="Correo"><input class="pin" type="password" inputmode="numeric" placeholder="Clave"></div>
  <div class="row"><input class="name" placeholder="Nombre"><input class="email" type="email" placeholder="Correo"><input class="pin" type="password" inputmode="numeric" placeholder="Clave"></div>
  <div class="row"><input class="name" placeholder="Nombre"><input class="email" type="email" placeholder="Correo"><input class="pin" type="password" inputmode="numeric" placeholder="Clave"></div>
  <button id="save">Crear / actualizar usuarios</button>
  <small>Después de confirmar que funciona el inicio de sesión, elimina esta pantalla temporal y el secreto BOOTSTRAP_SECRET.</small>
  <div id="status" class="status"></div>
</div>
<script>
document.getElementById('save').addEventListener('click', async () => {
  const status=document.getElementById('status');
  status.className='status'; status.textContent='Procesando…';
  const names=[...document.querySelectorAll('.name')];
  const emails=[...document.querySelectorAll('.email')];
  const pins=[...document.querySelectorAll('.pin')];
  const users=names.map((n,i)=>({name:n.value.trim(),email:emails[i].value.trim(),pin:pins[i].value.trim()}))
    .filter(u=>u.name||u.email||u.pin);
  try{
    const r=await fetch('/api/admin/bootstrap-users',{
      method:'POST',
      headers:{'content-type':'application/json','x-bootstrap-secret':document.getElementById('secret').value},
      body:JSON.stringify({users})
    });
    const data=await r.json();
    if(!r.ok) throw new Error(data.error||'Error');
    status.className='status ok';
    status.textContent='Usuarios creados correctamente: '+data.users.length;
    document.querySelectorAll('.pin').forEach(i=>i.value='');
    document.getElementById('secret').value='';
  }catch(e){
    status.className='status err';
    status.textContent='No se pudo completar: '+e.message;
  }
});
</script>
</main>
</body>
</html>`, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow"
    }
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
          PIN_PEPPER: Boolean(env.PIN_PEPPER),
          SESSION_SECRET: Boolean(env.SESSION_SECRET),
          BOOTSTRAP_SECRET: Boolean(env.BOOTSTRAP_SECRET),
          ALLOWED_ORIGINS: Boolean(env.ALLOWED_ORIGINS)
        });
      } else if (url.pathname === "/bootstrap" && request.method === "GET") {
        response = bootstrapPage();
      } else if (url.pathname === "/api/health" && request.method === "GET") {
        response = json({
          ok: true,
          service: "club-deportivo-api",
          d1: Boolean(env.DB),
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
