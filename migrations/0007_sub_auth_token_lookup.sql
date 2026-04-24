CREATE UNIQUE INDEX IF NOT EXISTS idx_downstream_clients_auth_token_hash
  ON downstream_clients (auth_token_hash)
  WHERE auth_token_hash IS NOT NULL;
