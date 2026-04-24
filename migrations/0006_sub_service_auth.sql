ALTER TABLE downstream_clients
  ADD COLUMN auth_token_hash TEXT;

ALTER TABLE downstream_clients
  ADD COLUMN sub_service_encryption_public_key TEXT;

ALTER TABLE downstream_clients
  ADD COLUMN auth_issued_at TEXT;

ALTER TABLE downstream_clients
  ADD COLUMN auth_last_success_at TEXT;

ALTER TABLE downstream_clients
  ADD COLUMN auth_last_failure_at TEXT;

CREATE INDEX IF NOT EXISTS idx_downstream_clients_service_auth
  ON downstream_clients (entry_kind, service_url, blacklisted_at);
