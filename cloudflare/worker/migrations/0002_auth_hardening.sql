PRAGMA foreign_keys = ON;

ALTER TABLE users ADD COLUMN pin_fingerprint TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_pin_fingerprint_unique
  ON users(pin_fingerprint)
  WHERE pin_fingerprint IS NOT NULL;

CREATE TABLE IF NOT EXISTS auth_login_attempts (
  attempt_key TEXT PRIMARY KEY,
  failed_count INTEGER NOT NULL DEFAULT 0,
  first_failed_at INTEGER NOT NULL DEFAULT 0,
  blocked_until INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_updated
  ON auth_login_attempts(updated_at);
