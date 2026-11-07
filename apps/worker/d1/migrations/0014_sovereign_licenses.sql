-- Active sovereign licenses used by the worker's QAL access middleware.
-- expires_at is a Unix timestamp in milliseconds; NULL means no expiry.
CREATE TABLE IF NOT EXISTS sovereign_licenses (
  identity TEXT PRIMARY KEY,
  tier TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  expires_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);

CREATE INDEX IF NOT EXISTS idx_sovereign_licenses_status_expiry
  ON sovereign_licenses(status, expires_at);
