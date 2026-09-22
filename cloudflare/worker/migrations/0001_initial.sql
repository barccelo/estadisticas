PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  pin_hash TEXT NOT NULL UNIQUE,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS records (
  id TEXT PRIMARY KEY,
  record_date TEXT NOT NULL,
  responsible_user_id TEXT NOT NULL,
  observations TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'web',
  idempotency_key TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  FOREIGN KEY (responsible_user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_records_date ON records(record_date);
CREATE INDEX IF NOT EXISTS idx_records_user_date ON records(responsible_user_id, record_date);

CREATE TABLE IF NOT EXISTS attendance_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  record_id TEXT NOT NULL,
  discipline TEXT NOT NULL,
  attendance INTEGER NOT NULL DEFAULT 0 CHECK (attendance >= 0),
  FOREIGN KEY (record_id) REFERENCES records(id) ON DELETE CASCADE,
  UNIQUE(record_id, discipline)
);

CREATE INDEX IF NOT EXISTS idx_attendance_discipline ON attendance_entries(discipline);

CREATE TABLE IF NOT EXISTS drafts (
  record_date TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL,
  updated_by_user_id TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  FOREIGN KEY (updated_by_user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS app_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  user_id TEXT,
  record_id TEXT,
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (record_id) REFERENCES records(id)
);

CREATE INDEX IF NOT EXISTS idx_app_log_created ON app_log(created_at);
CREATE INDEX IF NOT EXISTS idx_app_log_user ON app_log(user_id);
