PRAGMA foreign_keys = ON;

-- El Worker crea de forma idempotente la columna users.pin_fingerprint
-- y su índice único al inicializar el esquema de autenticación.
-- Esta migración conserva únicamente las estructuras que sí son seguras
-- de aplicar aunque el Worker ya haya arrancado antes.

CREATE TABLE IF NOT EXISTS auth_login_attempts (
  attempt_key TEXT PRIMARY KEY,
  failed_count INTEGER NOT NULL DEFAULT 0,
  first_failed_at INTEGER NOT NULL DEFAULT 0,
  blocked_until INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_updated
  ON auth_login_attempts(updated_at);
