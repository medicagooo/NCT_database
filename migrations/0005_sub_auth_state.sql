ALTER TABLE downstream_clients
  ADD COLUMN auth_failure_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE downstream_clients
  ADD COLUMN blacklisted_at TEXT;
