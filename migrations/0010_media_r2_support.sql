ALTER TABLE school_media
  ADD COLUMN local_object_key TEXT;

ALTER TABLE school_media
  ADD COLUMN object_synced_at TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_school_media_local_object_key
  ON school_media (local_object_key)
  WHERE local_object_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS system_state (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
