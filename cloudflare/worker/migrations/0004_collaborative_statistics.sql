PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS partial_statistics (
  record_date TEXT NOT NULL,
  discipline TEXT NOT NULL,
  attendance INTEGER NOT NULL DEFAULT 0 CHECK (attendance >= 0),
  updated_by_user_id TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (record_date, discipline),
  FOREIGN KEY (updated_by_user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_partial_statistics_date
  ON partial_statistics(record_date);
