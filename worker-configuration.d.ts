interface Env {
  ASSETS: Fetcher;
  DB: D1Database;
  EXPORT_BUCKET: R2Bucket;
  APP_NAME?: string;
  DEFAULT_ENCRYPT_FIELDS?: string;
  ENCRYPTION_KEY: string;
  INGEST_TOKEN?: string;
  SERVICE_ENCRYPTION_PRIVATE_KEY?: string;
  SERVICE_SIGNING_PRIVATE_KEY?: string;
  SUB_AUTH_MAX_FAILURES?: string;
  SUB_REPORT_MIN_INTERVAL_MS?: string;
  SUB_PULL_BATCH_SIZE?: string;
  SUB_PULL_RECORD_LIMIT?: string;
  SUB_PULL_TIMEOUT_MS?: string;
  RESEND_API_KEY?: string;
  EXPORT_EMAIL_TO?: string;
  EXPORT_EMAIL_FROM?: string;
}
