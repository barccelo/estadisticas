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

const RECORD_DISCIPLINES = ["Ajedrez","Astronomía","Atletismo","Baloncesto","Béisbol","Fútbol campo","Fútbol sala","Música","Tenis de campo","Robótica"];
const LEGACY_SHEET_URL = "https://docs.google.com/spreadsheets/d/e/2PACX-1vQi7LJ9GkWvS8xSGabaKdLwMRzhaMXppm8Vt8Z5chsQr92cWEOYF2SKeNPI15SYc1oryFw3eJP1SQkg/pub?gid=590274017&single=true&output=csv";

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

  return json({
    ok: true,
    duplicate: false,
    record: { id: recordId, createdAt: saved?.created_at || new Date().toISOString() },
    message: "Registro guardado correctamente.",
  }, 201);
}

async function updateRecord(request, env, recordId) {
  if (!env.DB) return json({ ok: false, error: "D1_NOT_BOUND" }, 503);
  const auth = await requireSession(request, env);
  if (!auth) return json({ ok: false, error: "UNAUTHORIZED" }, 401);

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: "INVALID_JSON" }, 400); }

  const date = String(body?.date || "").trim();
  const observations = String(body?.observations || "").trim();
  const attendance = body?.attendance;
  const responsibleEmail = String(body?.responsible_email || auth.email || "").trim().toLowerCase();

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
  ).bind(auth.user_id, recordId, JSON.stringify({ before, after })).run();

  return json({
    ok: true,
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
      } else if (url.pathname === "/api/records" && request.method === "GET") {
        response = await listRecords(request, env, ctx);
      } else if (url.pathname === "/api/records" && request.method === "POST") {
        response = await createRecord(request, env);
      } else if (url.pathname.startsWith("/api/records/") && request.method === "PUT") {
        response = await updateRecord(request, env, decodeURIComponent(url.pathname.slice("/api/records/".length)));
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
