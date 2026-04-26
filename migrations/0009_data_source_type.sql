ALTER TABLE raw_records
  ADD COLUMN data_source_type TEXT NOT NULL DEFAULT 'batch_query';

ALTER TABLE secure_records
  ADD COLUMN data_source_type TEXT NOT NULL DEFAULT 'batch_query';

CREATE INDEX IF NOT EXISTS idx_raw_records_data_source_type
  ON raw_records (data_source_type, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_secure_records_data_source_type
  ON secure_records (data_source_type, updated_at DESC);
