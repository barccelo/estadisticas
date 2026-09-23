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
      "access-control-allow-headers": "content-type,authorization,x-edit-token,x-admin-token",
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

const RECORD_DISCIPLINES = ["Ajedrez","Astronomía","Atletismo","Baloncesto","Béisbol","Fútbol campo","Fútbol sala","Música","Tenis de campo","Robótica"];
const LEGACY_SHEET_URL = "https://docs.google.com/spreadsheets/d/e/2PACX-1vQi7LJ9GkWvS8xSGabaKdLwMRzhaMXppm8Vt8Z5chsQr92cWEOYF2SKeNPI15SYc1oryFw3eJP1SQkg/pub?gid=590274017&single=true&output=csv";
const LEGACY_APPS_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbzHHgoVMHLbCWYYPnPgtWsG3Ipq3Q_5dkMRKBFbJYW5uG3mkhlHWkLwi1DyOuKCDAGh/exec";

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

async function login(request, env, ctx) {
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

  const migration = await maybeStartLegacyImport(env, ctx);
  return json({
    ok: true,
    token: sessionData.token,
    expires_in: sessionData.expiresIn,
    user: { id: user.id, email: user.email, name: user.display_name },
    migration,
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

async function getDraft(request, env) {
  if (!env.DB) return json({ ok: false, error: "D1_NOT_BOUND" }, 503);
  const auth = await requireSession(request, env);
  if (!auth) return json({ ok: false, error: "UNAUTHORIZED" }, 401);

  const url = new URL(request.url);
  const date = String(url.searchParams.get("date") || "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return json({ ok: false, error: "INVALID_DATE" }, 400);
  }

  const row = await env.DB.prepare(
    `SELECT d.record_date, d.payload_json, d.version, d.updated_at,
            u.email AS updated_by_email, u.display_name AS updated_by_name
     FROM drafts d
     LEFT JOIN users u ON u.id = d.updated_by_user_id
     WHERE d.record_date = ?1
     LIMIT 1`
  ).bind(date).first();

  if (!row) return json({ ok: true, draft: null });

  let record = {};
  try { record = JSON.parse(row.payload_json || "{}"); } catch (_) {}

  return json({
    ok: true,
    draft: {
      date: row.record_date,
      record,
      version: Number(row.version || 1),
      updatedAt: row.updated_at,
      updatedBy: row.updated_by_email || "",
      updatedByName: row.updated_by_name || "",
    },
  });
}

async function saveDraft(request, env) {
  if (!env.DB) return json({ ok: false, error: "D1_NOT_BOUND" }, 503);
  const auth = await requireSession(request, env);
  if (!auth) return json({ ok: false, error: "UNAUTHORIZED" }, 401);
  const editAllowed = await requireEditSession(request, env, auth.user_id);
  if (!editAllowed) return json({ ok: false, error: "EDIT_LOCKED" }, 403);

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: "INVALID_JSON" }, 400); }

  const date = String(body?.date || "").trim();
  const record = body?.record;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !record || typeof record !== "object" || Array.isArray(record)) {
    return json({ ok: false, error: "INVALID_DRAFT" }, 400);
  }

  const payload = JSON.stringify(record);
  if (payload.length > 100000) return json({ ok: false, error: "DRAFT_TOO_LARGE" }, 413);

  await env.DB.prepare(
    `INSERT INTO drafts (record_date, payload_json, updated_by_user_id, version, updated_at)
     VALUES (?1, ?2, ?3, 1, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
     ON CONFLICT(record_date) DO UPDATE SET
       payload_json = excluded.payload_json,
       updated_by_user_id = excluded.updated_by_user_id,
       version = drafts.version + 1,
       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')`
  ).bind(date, payload, auth.user_id).run();

  const saved = await env.DB.prepare(
    "SELECT version, updated_at FROM drafts WHERE record_date = ?1 LIMIT 1"
  ).bind(date).first();

  await env.DB.prepare(
    "INSERT INTO app_log (event_type, user_id, details_json) VALUES ('draft_saved', ?1, ?2)"
  ).bind(auth.user_id, JSON.stringify({ date, version: Number(saved?.version || 1) })).run();

  return json({
    ok: true,
    version: Number(saved?.version || 1),
    updatedAt: saved?.updated_at || new Date().toISOString(),
  });
}

async function deleteDraft(request, env) {
  if (!env.DB) return json({ ok: false, error: "D1_NOT_BOUND" }, 503);
  const auth = await requireSession(request, env);
  if (!auth) return json({ ok: false, error: "UNAUTHORIZED" }, 401);

  const url = new URL(request.url);
  const date = String(url.searchParams.get("date") || "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return json({ ok: false, error: "INVALID_DATE" }, 400);
  }

  await env.DB.prepare("DELETE FROM drafts WHERE record_date = ?1").bind(date).run();
  await env.DB.prepare(
    "INSERT INTO app_log (event_type, user_id, details_json) VALUES ('draft_deleted', ?1, ?2)"
  ).bind(auth.user_id, JSON.stringify({ date })).run();

  return json({ ok: true });
}

function csvParse(text) {
  const rows=[]; let row=[], value="", quoted=false;
  for (let i=0;i<text.length;i++) {
    const ch=text[i], next=text[i+1];
    if (ch === '"') {
      if (quoted && next === '"') { value+='"'; i++; }
      else quoted=!quoted;
    } else if (ch === ',' && !quoted) {
      row.push(value); value="";
    } else if ((ch === "\n" || ch === "\r") && !quoted) {
      if (ch === "\r" && next === "\n") i++;
      row.push(value); value="";
      if (row.some((cell)=>String(cell).trim()!=="")) rows.push(row);
      row=[];
    } else value+=ch;
  }
  row.push(value);
  if (row.some((cell)=>String(cell).trim()!=="")) rows.push(row);
  if (!rows.length) return [];
  const headers=rows[0].map((h)=>String(h).trim());
  return rows.slice(1).map((r)=>{
    const obj={}; headers.forEach((h,i)=>obj[h]=r[i] ?? ""); return obj;
  });
}

function normalizedKey(value) {
  return String(value || "").normalize("NFD").replace(/[\u0300-\u036f]/g,"").toLowerCase().replace(/[^a-z0-9]/g,"");
}

function rowGetter(row) {
  const map={};
  for (const key of Object.keys(row || {})) map[normalizedKey(key)] = key;
  return (...names)=>{
    for (const name of names) {
      const key=map[normalizedKey(name)];
      if (key !== undefined) return row[key];
    }
    return "";
  };
}

function parseLegacyNumber(value) {
  let s=String(value ?? "").trim().replace(/\s/g,"");
  if (!s) return 0;
  if (s.includes(",") && !s.includes(".")) s=s.replace(",",".");
  const n=Number(s.replace(/[^0-9.-]/g,""));
  return Number.isFinite(n) ? Math.max(0, Math.trunc(n)) : 0;
}

function parseLegacyDate(value) {
  let s=String(value || "").trim();
  if (!s) return "";
  s=s.split(/\s+/)[0];
  const parts=s.split(/[\/.-]/).map((v)=>parseInt(v,10));
  if (parts.length<3 || parts.some(Number.isNaN)) return "";
  let y,m,d;
  if (String(parts[0]).length===4) [y,m,d]=parts;
  else [d,m,y]=parts;
  if (y<100) y+=2000;
  if (!y || !m || !d) return "";
  return `${String(y).padStart(4,"0")}-${String(m).padStart(2,"0")}-${String(d).padStart(2,"0")}`;
}

async function ensureMigrationSchema(env) {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS migration_state (
      name TEXT PRIMARY KEY,
      status TEXT NOT NULL,
      imported_count INTEGER NOT NULL DEFAULT 0,
      skipped_count INTEGER NOT NULL DEFAULT 0,
      error_text TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    )`
  ).run();
}

async function migrationStatus(env) {
  await ensureMigrationSchema(env);
  const row=await env.DB.prepare(
    "SELECT status, imported_count, skipped_count, error_text, updated_at FROM migration_state WHERE name='legacy_sheet' LIMIT 1"
  ).first();
  return row ? {
    status: row.status,
    imported: Number(row.imported_count || 0),
    skipped: Number(row.skipped_count || 0),
    error: row.error_text || "",
    updatedAt: row.updated_at || "",
  } : { status: "pending", imported: 0, skipped: 0, error: "", updatedAt: "" };
}

async function importLegacySheet(env) {
  await ensureMigrationSchema(env);
  try {
    const response=await fetch(LEGACY_SHEET_URL, { cf: { cacheTtl: 0, cacheEverything: false } });
    if (!response.ok) throw new Error("LEGACY_SHEET_FETCH_FAILED_"+response.status);
    const rows=csvParse(await response.text());

    const users=await env.DB.prepare("SELECT id, email FROM users WHERE active=1").all();
    const byEmail=new Map((users.results || []).map((u)=>[String(u.email||"").trim().toLowerCase(),u.id]));

    let imported=0, skipped=0;
    for (const row of rows) {
      const get=rowGetter(row);
      const date=parseLegacyDate(get("Fecha:","Fecha"));
      const email=String(get("Email Address","Dirección de correo electrónico","Correo electrónico") || "").trim().toLowerCase();
      const userId=byEmail.get(email);
      if (!date || !userId) { skipped++; continue; }

      const observations=String(get("Observaciones:","Observaciones") || "").trim();
      const attendance={};
      for (const d of RECORD_DISCIPLINES) attendance[d]=parseLegacyNumber(get(d));

      const canonical=JSON.stringify([date,observations,RECORD_DISCIPLINES.map((d)=>[d,attendance[d]])]);
      const contentKey=await sha256Hex(canonical);
      const idempotencyKey=await sha256Hex(userId+":"+contentKey);

      const existing=await env.DB.prepare(
        "SELECT id FROM records WHERE idempotency_key=?1 LIMIT 1"
      ).bind(idempotencyKey).first();
      if (existing) { skipped++; continue; }

      const recordId=crypto.randomUUID();
      const statements=[
        env.DB.prepare(
          `INSERT INTO records (id, record_date, responsible_user_id, observations, source, idempotency_key)
           VALUES (?1, ?2, ?3, ?4, 'legacy-sheet', ?5)`
        ).bind(recordId,date,userId,observations,idempotencyKey),
        ...RECORD_DISCIPLINES.map((discipline)=>
          env.DB.prepare(
            "INSERT INTO attendance_entries (record_id, discipline, attendance) VALUES (?1, ?2, ?3)"
          ).bind(recordId,discipline,attendance[discipline])
        )
      ];
      await env.DB.batch(statements);
      imported++;
    }

    await env.DB.prepare(
      `INSERT INTO migration_state (name,status,imported_count,skipped_count,error_text,updated_at)
       VALUES ('legacy_sheet','done',?1,?2,'',strftime('%Y-%m-%dT%H:%M:%fZ','now'))
       ON CONFLICT(name) DO UPDATE SET
         status='done', imported_count=?1, skipped_count=?2, error_text='',
         updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')`
    ).bind(imported,skipped).run();

    await env.DB.prepare(
      "INSERT INTO app_log (event_type, details_json) VALUES ('legacy_sheet_import', ?1)"
    ).bind(JSON.stringify({imported,skipped})).run();
  } catch (error) {
    await env.DB.prepare(
      `INSERT INTO migration_state (name,status,imported_count,skipped_count,error_text,updated_at)
       VALUES ('legacy_sheet','failed',0,0,?1,strftime('%Y-%m-%dT%H:%M:%fZ','now'))
       ON CONFLICT(name) DO UPDATE SET
         status='failed', error_text=?1, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')`
    ).bind(String(error?.message || error || "IMPORT_FAILED").slice(0,500)).run();
  }
}

async function maybeStartLegacyImport(env, ctx) {
  const state=await migrationStatus(env);
  if (state.status === "done" || state.status === "running") return state;
  await env.DB.prepare(
    `INSERT INTO migration_state (name,status,imported_count,skipped_count,error_text,updated_at)
     VALUES ('legacy_sheet','running',0,0,'',strftime('%Y-%m-%dT%H:%M:%fZ','now'))
     ON CONFLICT(name) DO UPDATE SET
       status='running', error_text='', updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')`
  ).run();
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(importLegacySheet(env));
  else await importLegacySheet(env);
  return { ...state, status: "running" };
}

async function listRecords(request, env, ctx) {
  await maybeStartLegacyImport(env, ctx);
  if (!env.DB) return json({ ok: false, error: "D1_NOT_BOUND" }, 503);
  const url = new URL(request.url);
  const from = String(url.searchParams.get("from") || "").trim();
  const to = String(url.searchParams.get("to") || "").trim();

  if ((from && !/^\d{4}-\d{2}-\d{2}$/.test(from)) || (to && !/^\d{4}-\d{2}-\d{2}$/.test(to))) {
    return json({ ok: false, error: "INVALID_DATE_RANGE" }, 400);
  }

  let sql = `SELECT r.id, r.record_date, r.observations, r.created_at,
                    u.email, u.display_name,
                    a.discipline, a.attendance
             FROM records r
             JOIN users u ON u.id = r.responsible_user_id
             LEFT JOIN attendance_entries a ON a.record_id = r.id
             WHERE 1=1`;
  const binds = [];
  if (from) { binds.push(from); sql += ` AND r.record_date >= ?${binds.length}`; }
  if (to) { binds.push(to); sql += ` AND r.record_date <= ?${binds.length}`; }
  sql += " ORDER BY r.record_date ASC, r.created_at ASC, a.discipline ASC";

  const stmt = env.DB.prepare(sql);
  const result = binds.length ? await stmt.bind(...binds).all() : await stmt.all();
  const grouped = new Map();

  for (const row of result.results || []) {
    if (!grouped.has(row.id)) {
      const values = {};
      for (const d of RECORD_DISCIPLINES) values[d] = 0;
      grouped.set(row.id, {
        id: row.id,
        timestamp: row.created_at,
        fecha: row.record_date,
        email: row.email,
        responsable: row.display_name,
        observaciones: row.observations || "",
        valores: values,
        total: 0,
        source: "cloudflare",
      });
    }
    const record = grouped.get(row.id);
    if (row.discipline && Object.prototype.hasOwnProperty.call(record.valores, row.discipline)) {
      const n = Number(row.attendance || 0);
      record.valores[row.discipline] = n;
    }
  }

  for (const record of grouped.values()) {
    record.total = RECORD_DISCIPLINES.reduce((sum, d) => sum + Number(record.valores[d] || 0), 0);
  }

  const migration = await migrationStatus(env);
  return json({ ok: true, records: [...grouped.values()], migration });
}

async function ensureEditSchema(env) {
  try { await env.DB.prepare("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'registrador'").run(); } catch (_) {}
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value_text TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    )`
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS edit_sessions_global (
      token_hash TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    )`
  ).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_edit_sessions_global_expiry ON edit_sessions_global(expires_at)").run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS admin_sessions_global (
      token_hash TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    )`
  ).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_admin_sessions_global_expiry ON admin_sessions_global(expires_at)").run();
}

async function validateLegacyEditPassword(password) {
  try {
    const callback="cf";
    const url=new URL(LEGACY_APPS_SCRIPT_URL);
    url.searchParams.set("action","getRecordsByDate");
    url.searchParams.set("callback",callback);
    url.searchParams.set("password",password);
    url.searchParams.set("date","2000-01-01");
    const response=await fetch(url.toString(),{redirect:"follow"});
    if(!response.ok) return false;
    const text=await response.text();
    const match=text.match(/^\s*cf\((.*)\)\s*;?\s*$/s);
    if(!match) return false;
    const data=JSON.parse(match[1]);
    return Boolean(data && data.ok);
  } catch (_) {
    return false;
  }
}

async function unlockEditing(request, env) {
  await ensureEditSchema(env);

  let body;
  try { body=await request.json(); }
  catch { return json({ok:false,error:"INVALID_JSON"},400); }
  const password=String(body?.password||"").trim();
  if(!password) return json({ok:false,error:"INVALID_EDIT_KEY"},401);

  const setting=await env.DB.prepare("SELECT value_text FROM app_settings WHERE key='edit_key_hash' LIMIT 1").first();
  let valid=false;
  if(setting?.value_text){
    valid=await verifyPin(password,setting.value_text);
  }else{
    valid=await validateLegacyEditPassword(password);
    if(valid){
      const hashed=await hashPin(password);
      await env.DB.prepare(
        `INSERT INTO app_settings (key,value_text,updated_at)
         VALUES ('edit_key_hash',?1,strftime('%Y-%m-%dT%H:%M:%fZ','now'))
         ON CONFLICT(key) DO UPDATE SET value_text=?1,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')`
      ).bind(hashed).run();
    }
  }
  if(!valid) return json({ok:false,error:"INVALID_EDIT_KEY"},401);

  const raw=crypto.getRandomValues(new Uint8Array(32));
  const token=base64url(raw);
  const tokenHash=await sha256Hex(raw);
  const expiresIn=60*30;
  const expiresAt=Math.floor(Date.now()/1000)+expiresIn;
  await env.DB.prepare(
    "INSERT INTO edit_sessions_global (token_hash,expires_at) VALUES (?1,?2)"
  ).bind(tokenHash,expiresAt).run();

  await env.DB.prepare(
    "INSERT INTO app_log (event_type,details_json) VALUES ('edit_unlocked',?1)"
  ).bind(JSON.stringify({expires_in:expiresIn,authorization:"edit-key"})).run();

  return json({ok:true,edit_token:token,expires_in:expiresIn});
}

async function requireEditSession(request, env) {
  await ensureEditSchema(env);
  const token=String(request.headers.get("x-edit-token")||"").trim();
  if(!token) return false;
  let tokenHash;
  try { tokenHash=await sha256Hex(fromBase64url(token)); }
  catch { return false; }
  const now=Math.floor(Date.now()/1000);
  const row=await env.DB.prepare(
    "SELECT token_hash FROM edit_sessions_global WHERE token_hash=?1 AND expires_at>?2 LIMIT 1"
  ).bind(tokenHash,now).first();
  return Boolean(row);
}

async function unlockAdmin(request, env) {
  await ensureEditSchema(env);
  let body;
  try { body=await request.json(); }
  catch { return json({ok:false,error:"INVALID_JSON"},400); }
  const password=String(body?.password||"").trim();
  if(!password) return json({ok:false,error:"INVALID_ADMIN_KEY"},401);

  let setting=await env.DB.prepare("SELECT value_text FROM app_settings WHERE key='admin_key_hash' LIMIT 1").first();
  let valid=false;

  if(setting?.value_text){
    valid=await verifyPin(password,setting.value_text);
  }else{
    const editSetting=await env.DB.prepare("SELECT value_text FROM app_settings WHERE key='edit_key_hash' LIMIT 1").first();
    if(editSetting?.value_text) valid=await verifyPin(password,editSetting.value_text);
    else valid=await validateLegacyEditPassword(password);

    if(valid){
      const hashed=await hashPin(password);
      await env.DB.prepare(
        `INSERT INTO app_settings (key,value_text,updated_at)
         VALUES ('admin_key_hash',?1,strftime('%Y-%m-%dT%H:%M:%fZ','now'))
         ON CONFLICT(key) DO UPDATE SET value_text=?1,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')`
      ).bind(hashed).run();
    }
  }

  if(!valid) return json({ok:false,error:"INVALID_ADMIN_KEY"},401);

  const raw=crypto.getRandomValues(new Uint8Array(32));
  const token=base64url(raw);
  const tokenHash=await sha256Hex(raw);
  const expiresIn=60*30;
  const expiresAt=Math.floor(Date.now()/1000)+expiresIn;
  await env.DB.prepare(
    "INSERT INTO admin_sessions_global (token_hash,expires_at) VALUES (?1,?2)"
  ).bind(tokenHash,expiresAt).run();

  await env.DB.prepare(
    "INSERT INTO app_log (event_type,details_json) VALUES ('admin_unlocked',?1)"
  ).bind(JSON.stringify({expires_in:expiresIn,authorization:"admin-key"})).run();

  return json({ok:true,admin_token:token,expires_in:expiresIn});
}

async function requireAdminSession(request, env) {
  await ensureEditSchema(env);
  const token=String(request.headers.get("x-admin-token")||"").trim();
  if(!token) return false;
  let tokenHash;
  try { tokenHash=await sha256Hex(fromBase64url(token)); }
  catch { return false; }
  const now=Math.floor(Date.now()/1000);
  const row=await env.DB.prepare(
    "SELECT token_hash FROM admin_sessions_global WHERE token_hash=?1 AND expires_at>?2 LIMIT 1"
  ).bind(tokenHash,now).first();
  return Boolean(row);
}

async function changeAdminKey(request, env) {
  const allowed=await requireAdminSession(request,env);
  if(!allowed) return json({ok:false,error:"ADMIN_LOCKED"},403);
  let body; try{body=await request.json();}catch{return json({ok:false,error:"INVALID_JSON"},400);}
  const kind=String(body?.kind||"").trim();
  const password=String(body?.password||"").trim();
  if(!["admin","edit"].includes(kind) || !/^\d{4,20}$/.test(password)) return json({ok:false,error:"INVALID_NEW_KEY"},400);

  const hash=await hashPin(password);
  const key=kind==="admin" ? "admin_key_hash" : "edit_key_hash";
  await env.DB.prepare(
    `INSERT INTO app_settings (key,value_text,updated_at)
     VALUES (?1,?2,strftime('%Y-%m-%dT%H:%M:%fZ','now'))
     ON CONFLICT(key) DO UPDATE SET value_text=?2,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')`
  ).bind(key,hash).run();

  if(kind==="admin") await env.DB.prepare("DELETE FROM admin_sessions_global").run();
  else await env.DB.prepare("DELETE FROM edit_sessions_global").run();

  await env.DB.prepare(
    "INSERT INTO app_log (event_type,details_json) VALUES ('access_key_changed',?1)"
  ).bind(JSON.stringify({kind,authorization:"admin-key"})).run();

  return json({ok:true,kind,message:kind==="admin"?"Clave de administración actualizada.":"Clave de edición actualizada."});
}

async function ensureBackupSchema(env) {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS backup_jobs (
      id TEXT PRIMARY KEY,
      record_id TEXT,
      operation TEXT NOT NULL CHECK(operation IN ('create','update','delete')),
      responsible_email TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done')),
      attempts INTEGER NOT NULL DEFAULT 0,
      last_error TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      completed_at TEXT
    )`
  ).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_backup_jobs_pending ON backup_jobs(status,operation,created_at)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_backup_jobs_email ON backup_jobs(responsible_email,status)").run();
}

async function enqueueBackupJob(env, operation, recordId, responsibleEmail, payload) {
  try {
    await ensureBackupSchema(env);
    const id=crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO backup_jobs (id,record_id,operation,responsible_email,payload_json)
       VALUES (?1,?2,?3,?4,?5)`
    ).bind(id,recordId||null,operation,String(responsibleEmail||"").trim().toLowerCase(),JSON.stringify(payload||{})).run();
    return id;
  } catch (error) {
    console.error("backup enqueue failed",error);
    return null;
  }
}

async function listBackupJobs(request, env) {
  await ensureBackupSchema(env);
  const editAllowed=await requireEditSession(request,env);
  const auth=await requireSession(request,env);

  if(editAllowed){
    const rows=await env.DB.prepare(
      `SELECT id,record_id,operation,responsible_email,payload_json,attempts,last_error,created_at,updated_at
       FROM backup_jobs
       WHERE status='pending' AND operation IN ('update','delete')
       ORDER BY created_at ASC LIMIT 50`
    ).all();
    return json({ok:true,jobs:(rows.results||[]).map(row=>({...row,payload:JSON.parse(row.payload_json||"{}"),payload_json:undefined}))});
  }

  if(auth){
    const rows=await env.DB.prepare(
      `SELECT id,record_id,operation,responsible_email,payload_json,attempts,last_error,created_at,updated_at
       FROM backup_jobs
       WHERE status='pending' AND operation='create' AND lower(responsible_email)=lower(?1)
       ORDER BY created_at ASC LIMIT 50`
    ).bind(auth.email).all();
    return json({ok:true,jobs:(rows.results||[]).map(row=>({...row,payload:JSON.parse(row.payload_json||"{}"),payload_json:undefined}))});
  }

  return json({ok:false,error:"UNAUTHORIZED"},401);
}

async function reportBackupJob(request, env, jobId) {
  await ensureBackupSchema(env);
  let body; try{body=await request.json();}catch{return json({ok:false,error:"INVALID_JSON"},400);}
  const success=Boolean(body?.success);
  const error=String(body?.error||"").slice(0,500);
  const job=await env.DB.prepare(
    "SELECT id,operation,responsible_email,status FROM backup_jobs WHERE id=?1 LIMIT 1"
  ).bind(jobId).first();
  if(!job) return json({ok:false,error:"BACKUP_JOB_NOT_FOUND"},404);

  const editAllowed=await requireEditSession(request,env);
  const auth=await requireSession(request,env);
  const allowed = editAllowed || (auth && job.operation==="create" && String(auth.email||"").toLowerCase()===String(job.responsible_email||"").toLowerCase());
  if(!allowed) return json({ok:false,error:"UNAUTHORIZED"},401);

  if(success){
    await env.DB.prepare(
      `UPDATE backup_jobs SET status='done',attempts=attempts+1,last_error='',
       completed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
       updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?1`
    ).bind(jobId).run();
  }else{
    await env.DB.prepare(
      `UPDATE backup_jobs SET attempts=attempts+1,last_error=?2,
       updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?1`
    ).bind(jobId,error||"BACKUP_FAILED").run();
  }
  return json({ok:true,status:success?"done":"pending"});
}

async function adminBackupStatus(request, env) {
  const adminAllowed=await requireAdminSession(request,env);
  if(!adminAllowed) return json({ok:false,error:"ADMIN_LOCKED"},403);
  await ensureBackupSchema(env);
  const counts=await env.DB.prepare(
    `SELECT status,operation,COUNT(*) AS count FROM backup_jobs GROUP BY status,operation`
  ).all();
  const pending=await env.DB.prepare(
    `SELECT id,record_id,operation,responsible_email,attempts,last_error,created_at,updated_at
     FROM backup_jobs WHERE status='pending' ORDER BY created_at ASC LIMIT 100`
  ).all();
  return json({ok:true,counts:counts.results||[],pending:pending.results||[]});
}

async function createRecord(request, env) {
  if (!env.DB) return json({ ok: false, error: "D1_NOT_BOUND" }, 503);
  const auth = await requireSession(request, env);
  if (!auth) return json({ ok: false, error: "UNAUTHORIZED" }, 401);

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: "INVALID_JSON" }, 400); }

  const date = String(body?.date || "").trim();
  const observations = String(body?.observations || "").trim();
  const attendance = body?.attendance;

  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !attendance || typeof attendance !== "object" || Array.isArray(attendance)) {
    return json({ ok: false, error: "INVALID_RECORD" }, 400);
  }
  if (observations.length > 5000) return json({ ok: false, error: "OBSERVATIONS_TOO_LONG" }, 400);

  const clean = {};
  for (const discipline of RECORD_DISCIPLINES) {
    const raw = Number(attendance[discipline] ?? 0);
    if (!Number.isFinite(raw) || raw < 0 || !Number.isInteger(raw) || raw > 100000) {
      return json({ ok: false, error: "INVALID_ATTENDANCE", discipline }, 400);
    }
    clean[discipline] = raw;
  }

  const suppliedClientKey = String(body?.client_key || "").trim().toLowerCase();
  const canonical = JSON.stringify({
    date,
    observations,
    attendance: RECORD_DISCIPLINES.map((d) => [d, clean[d]]),
  });
  const contentKey = /^[a-f0-9]{64}$/.test(suppliedClientKey)
    ? suppliedClientKey
    : await sha256Hex(canonical);
  const idempotencyKey = await sha256Hex(auth.user_id + ":" + contentKey);

  const existing = await env.DB.prepare(
    "SELECT id, created_at FROM records WHERE idempotency_key = ?1 LIMIT 1"
  ).bind(idempotencyKey).first();

  if (existing) {
    return json({
      ok: true,
      duplicate: true,
      record: { id: existing.id, createdAt: existing.created_at },
      message: "Este mismo registro ya estaba guardado.",
    });
  }

  const recordId = crypto.randomUUID();
  const statements = [
    env.DB.prepare(
      `INSERT INTO records
       (id, record_date, responsible_user_id, observations, source, idempotency_key)
       VALUES (?1, ?2, ?3, ?4, 'web', ?5)`
    ).bind(recordId, date, auth.user_id, observations, idempotencyKey),
    ...RECORD_DISCIPLINES.map((discipline) =>
      env.DB.prepare(
        "INSERT INTO attendance_entries (record_id, discipline, attendance) VALUES (?1, ?2, ?3)"
      ).bind(recordId, discipline, clean[discipline])
    ),
    env.DB.prepare("DELETE FROM drafts WHERE record_date = ?1").bind(date),
  ];

  try {
    await env.DB.batch(statements);
  } catch (error) {
    const raced = await env.DB.prepare(
      "SELECT id, created_at FROM records WHERE idempotency_key = ?1 LIMIT 1"
    ).bind(idempotencyKey).first();
    if (raced) {
      return json({
        ok: true,
        duplicate: true,
        record: { id: raced.id, createdAt: raced.created_at },
        message: "Este mismo registro ya estaba guardado.",
      });
    }
    throw error;
  }

  const saved = await env.DB.prepare(
    "SELECT id, created_at FROM records WHERE id = ?1 LIMIT 1"
  ).bind(recordId).first();

  await env.DB.prepare(
    "INSERT INTO app_log (event_type, user_id, record_id, details_json) VALUES ('record_created', ?1, ?2, ?3)"
  ).bind(auth.user_id, recordId, JSON.stringify({ date, idempotency_key: idempotencyKey })).run();

  const backupJobId=await enqueueBackupJob(env,"create",recordId,auth.email,{
    date,
    email:auth.email,
    observations,
    attendance:clean
  });

  return json({
    ok: true,
    duplicate: false,
    backup: { queued: Boolean(backupJobId), jobId: backupJobId },
    record: { id: recordId, createdAt: saved?.created_at || new Date().toISOString() },
    message: "Registro guardado correctamente.",
  }, 201);
}

async function deleteRecord(request, env, recordId) {
  if (!env.DB) return json({ ok: false, error: "D1_NOT_BOUND" }, 503);
  const editAllowed = await requireEditSession(request, env);
  if (!editAllowed) return json({ ok: false, error: "EDIT_LOCKED" }, 403);
  const auth = await requireSession(request, env);

  const current = await env.DB.prepare(
    `SELECT r.id, r.record_date, r.observations, r.source, r.created_at,
            u.email, u.display_name
     FROM records r JOIN users u ON u.id=r.responsible_user_id
     WHERE r.id=?1 LIMIT 1`
  ).bind(recordId).first();
  if (!current) return json({ ok:false, error:"RECORD_NOT_FOUND" },404);

  const entries = await env.DB.prepare(
    "SELECT discipline, attendance FROM attendance_entries WHERE record_id=?1 ORDER BY discipline"
  ).bind(recordId).all();

  await env.DB.prepare(
    "INSERT INTO app_log (event_type,user_id,record_id,details_json) VALUES ('record_deleted',?1,NULL,?2)"
  ).bind(auth?.user_id || null, JSON.stringify({
    authorization:"edit-key",
    deleted_record_id:recordId,
    record: current,
    attendance: entries.results || []
  })).run();

  const deletedAttendance={};
  for(const d of RECORD_DISCIPLINES) deletedAttendance[d]=0;
  for(const row of entries.results||[]){
    if(row.discipline && Object.prototype.hasOwnProperty.call(deletedAttendance,row.discipline)){
      deletedAttendance[row.discipline]=Number(row.attendance||0);
    }
  }
  const backupJobId=await enqueueBackupJob(env,"delete",recordId,current.email,{
    record:{
      id:recordId,
      fecha:current.record_date,
      email:current.email,
      responsable:current.display_name,
      observaciones:current.observations||"",
      valores:deletedAttendance
    }
  });

  await env.DB.prepare("UPDATE app_log SET record_id=NULL WHERE record_id=?1").bind(recordId).run();
  await env.DB.prepare("DELETE FROM records WHERE id=?1").bind(recordId).run();
  return json({ok:true,backup:{queued:Boolean(backupJobId),jobId:backupJobId},message:"Registro eliminado correctamente."});
}

async function listAdminUsers(request, env) {
  const adminAllowed=await requireAdminSession(request,env);
  if(!adminAllowed) return json({ok:false,error:"ADMIN_LOCKED"},403);
  await ensureEditSchema(env);
  const rows=await env.DB.prepare(
    "SELECT id,email,display_name,active,role,created_at,updated_at FROM users ORDER BY display_name"
  ).all();
  return json({ok:true,users:rows.results||[]});
}

async function createAdminUser(request, env) {
  const adminAllowed=await requireAdminSession(request,env);
  if(!adminAllowed) return json({ok:false,error:"ADMIN_LOCKED"},403);
  await ensureEditSchema(env);
  let body; try{body=await request.json();}catch{return json({ok:false,error:"INVALID_JSON"},400);}
  const email=String(body?.email||"").trim().toLowerCase();
  const name=String(body?.name||"").trim();
  const pin=String(body?.pin||"").trim();
  const role=["admin","editor","registrador"].includes(String(body?.role||"")) ? String(body.role) : "registrador";
  if(!email || !name || !/^\d{4,20}$/.test(pin)) return json({ok:false,error:"INVALID_USER"},400);
  const pinHash=await hashPin(pin);
  const id=crypto.randomUUID();
  try{
    await env.DB.prepare(
      "INSERT INTO users (id,email,display_name,pin_hash,active,role) VALUES (?1,?2,?3,?4,1,?5)"
    ).bind(id,email,name,pinHash,role).run();
  }catch(e){
    return json({ok:false,error:"USER_EXISTS"},409);
  }
  await env.DB.prepare(
    "INSERT INTO app_log (event_type,details_json) VALUES ('user_created',?1)"
  ).bind(JSON.stringify({id,email,name,role,authorization:"edit-key"})).run();
  return json({ok:true,user:{id,email,display_name:name,active:1,role}});
}

async function updateAdminUser(request, env, userId) {
  const adminAllowed=await requireAdminSession(request,env);
  if(!adminAllowed) return json({ok:false,error:"ADMIN_LOCKED"},403);
  await ensureEditSchema(env);
  let body; try{body=await request.json();}catch{return json({ok:false,error:"INVALID_JSON"},400);}
  const existing=await env.DB.prepare("SELECT id,email,display_name,active,role FROM users WHERE id=?1 LIMIT 1").bind(userId).first();
  if(!existing) return json({ok:false,error:"USER_NOT_FOUND"},404);

  const email=String(body?.email ?? existing.email).trim().toLowerCase();
  const name=String(body?.name ?? existing.display_name).trim();
  const active=body?.active===undefined ? Number(existing.active) : (body.active ? 1 : 0);
  const role=["admin","editor","registrador"].includes(String(body?.role||"")) ? String(body.role) : String(existing.role||"registrador");
  const pin=String(body?.pin||"").trim();

  if(!email || !name || (pin && !/^\d{4,20}$/.test(pin))) return json({ok:false,error:"INVALID_USER"},400);

  try{
    if(pin){
      const pinHash=await hashPin(pin);
      await env.DB.prepare(
        `UPDATE users SET email=?1,display_name=?2,active=?3,role=?4,pin_hash=?5,
         updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?6`
      ).bind(email,name,active,role,pinHash,userId).run();
    }else{
      await env.DB.prepare(
        `UPDATE users SET email=?1,display_name=?2,active=?3,role=?4,
         updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?5`
      ).bind(email,name,active,role,userId).run();
    }
  }catch(e){
    return json({ok:false,error:"USER_UPDATE_CONFLICT"},409);
  }

  if(!active){
    await env.DB.prepare("DELETE FROM auth_sessions WHERE user_id=?1").bind(userId).run();
  }
  await env.DB.prepare(
    "INSERT INTO app_log (event_type,details_json) VALUES ('user_updated',?1)"
  ).bind(JSON.stringify({user_id:userId,before:existing,after:{email,name,active,role},pin_reset:Boolean(pin),authorization:"edit-key"})).run();
  return json({ok:true,user:{id:userId,email,display_name:name,active,role}});
}

async function listAuditLog(request, env) {
  const adminAllowed=await requireAdminSession(request,env);
  if(!adminAllowed) return json({ok:false,error:"ADMIN_LOCKED"},403);
  const rows=await env.DB.prepare(
    `SELECT l.id,l.event_type,l.record_id,l.details_json,l.created_at,
            u.display_name,u.email
     FROM app_log l LEFT JOIN users u ON u.id=l.user_id
     ORDER BY l.id DESC LIMIT 100`
  ).all();
  return json({ok:true,events:rows.results||[]});
}

async function updateRecord(request, env, recordId) {
  if (!env.DB) return json({ ok: false, error: "D1_NOT_BOUND" }, 503);
  const editAllowed = await requireEditSession(request, env);
  if (!editAllowed) return json({ ok: false, error: "EDIT_LOCKED" }, 403);
  const auth = await requireSession(request, env);

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: "INVALID_JSON" }, 400); }

  const date = String(body?.date || "").trim();
  const observations = String(body?.observations || "").trim();
  const attendance = body?.attendance;
  const responsibleEmail = String(body?.responsible_email || auth?.email || "").trim().toLowerCase();

  if (!recordId || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !attendance || typeof attendance !== "object" || Array.isArray(attendance)) {
    return json({ ok: false, error: "INVALID_RECORD" }, 400);
  }
  if (observations.length > 5000) return json({ ok: false, error: "OBSERVATIONS_TOO_LONG" }, 400);

  const currentRows = await env.DB.prepare(
    `SELECT r.id, r.record_date, r.responsible_user_id, r.observations, r.idempotency_key,
            u.email, u.display_name, a.discipline, a.attendance
     FROM records r
     JOIN users u ON u.id = r.responsible_user_id
     LEFT JOIN attendance_entries a ON a.record_id = r.id
     WHERE r.id = ?1`
  ).bind(recordId).all();

  if (!(currentRows.results || []).length) return json({ ok: false, error: "RECORD_NOT_FOUND" }, 404);

  const responsible = await env.DB.prepare(
    "SELECT id, email, display_name FROM users WHERE lower(email)=?1 AND active=1 LIMIT 1"
  ).bind(responsibleEmail).first();
  if (!responsible) return json({ ok: false, error: "RESPONSIBLE_NOT_FOUND" }, 400);

  const clean = {};
  for (const discipline of RECORD_DISCIPLINES) {
    const raw = Number(attendance[discipline] ?? 0);
    if (!Number.isFinite(raw) || raw < 0 || !Number.isInteger(raw) || raw > 100000) {
      return json({ ok: false, error: "INVALID_ATTENDANCE", discipline }, 400);
    }
    clean[discipline] = raw;
  }

  const canonical = JSON.stringify([date, observations, RECORD_DISCIPLINES.map((d) => [d, clean[d]])]);
  const contentKey = await sha256Hex(canonical);
  const idempotencyKey = await sha256Hex(responsible.id + ":" + contentKey);

  const duplicate = await env.DB.prepare(
    "SELECT id FROM records WHERE idempotency_key=?1 AND id<>?2 LIMIT 1"
  ).bind(idempotencyKey, recordId).first();
  if (duplicate) return json({ ok: false, error: "DUPLICATE_RECORD" }, 409);

  const first = currentRows.results[0];
  const oldAttendance = {};
  for (const d of RECORD_DISCIPLINES) oldAttendance[d] = 0;
  for (const row of currentRows.results) {
    if (row.discipline && Object.prototype.hasOwnProperty.call(oldAttendance, row.discipline)) {
      oldAttendance[row.discipline] = Number(row.attendance || 0);
    }
  }

  const before = {
    date: first.record_date,
    responsible_email: first.email,
    observations: first.observations || "",
    attendance: oldAttendance,
  };
  const after = {
    date,
    responsible_email: responsible.email,
    observations,
    attendance: clean,
  };

  const statements = [
    env.DB.prepare(
      `UPDATE records
       SET record_date=?1, responsible_user_id=?2, observations=?3, idempotency_key=?4,
           updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
       WHERE id=?5`
    ).bind(date, responsible.id, observations, idempotencyKey, recordId),
    ...RECORD_DISCIPLINES.map((discipline) =>
      env.DB.prepare(
        `INSERT INTO attendance_entries (record_id, discipline, attendance)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(record_id, discipline) DO UPDATE SET attendance=excluded.attendance`
      ).bind(recordId, discipline, clean[discipline])
    ),
  ];
  await env.DB.batch(statements);

  await env.DB.prepare(
    "INSERT INTO app_log (event_type, user_id, record_id, details_json) VALUES ('record_updated', ?1, ?2, ?3)"
  ).bind(auth?.user_id || null, recordId, JSON.stringify({ before, after, authorization: "edit-key" })).run();

  const backupJobId=await enqueueBackupJob(env,"update",recordId,responsible.email,{before,after});

  return json({
    ok: true,
    backup: { queued: Boolean(backupJobId), jobId: backupJobId },
    record: {
      id: recordId,
      fecha: date,
      email: responsible.email,
      responsable: responsible.display_name,
      observaciones: observations,
      valores: clean,
      total: RECORD_DISCIPLINES.reduce((sum,d)=>sum+clean[d],0),
      source: "cloudflare",
    },
    message: "Registro actualizado correctamente.",
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
  async fetch(request, env, ctx) {
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
        response = await login(request, env, ctx);
      } else if (url.pathname === "/api/session" && request.method === "GET") {
        response = await session(request, env);
      } else if (url.pathname === "/api/drafts" && request.method === "GET") {
        response = await getDraft(request, env);
      } else if (url.pathname === "/api/drafts" && request.method === "PUT") {
        response = await saveDraft(request, env);
      } else if (url.pathname === "/api/drafts" && request.method === "DELETE") {
        response = await deleteDraft(request, env);
      } else if (url.pathname === "/api/edit/unlock" && request.method === "POST") {
        response = await unlockEditing(request, env);
      } else if (url.pathname === "/api/admin/unlock" && request.method === "POST") {
        response = await unlockAdmin(request, env);
      } else if (url.pathname === "/api/admin/keys" && request.method === "PUT") {
        response = await changeAdminKey(request, env);
      } else if (url.pathname === "/api/records" && request.method === "GET") {
        response = await listRecords(request, env, ctx);
      } else if (url.pathname === "/api/records" && request.method === "POST") {
        response = await createRecord(request, env);
      } else if (url.pathname.startsWith("/api/records/") && request.method === "PUT") {
        response = await updateRecord(request, env, decodeURIComponent(url.pathname.slice("/api/records/".length)));
      } else if (url.pathname.startsWith("/api/records/") && request.method === "DELETE") {
        response = await deleteRecord(request, env, decodeURIComponent(url.pathname.slice("/api/records/".length)));
      } else if (url.pathname === "/api/admin/users" && request.method === "GET") {
        response = await listAdminUsers(request, env);
      } else if (url.pathname === "/api/admin/users" && request.method === "POST") {
        response = await createAdminUser(request, env);
      } else if (url.pathname.startsWith("/api/admin/users/") && request.method === "PUT") {
        response = await updateAdminUser(request, env, decodeURIComponent(url.pathname.slice("/api/admin/users/".length)));
      } else if (url.pathname === "/api/admin/audit" && request.method === "GET") {
        response = await listAuditLog(request, env);
      } else if (url.pathname === "/api/admin/backups" && request.method === "GET") {
        response = await adminBackupStatus(request, env);
      } else if (url.pathname === "/api/backup/jobs" && request.method === "GET") {
        response = await listBackupJobs(request, env);
      } else if (url.pathname.startsWith("/api/backup/jobs/") && request.method === "POST") {
        response = await reportBackupJob(request, env, decodeURIComponent(url.pathname.slice("/api/backup/jobs/".length)));
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
