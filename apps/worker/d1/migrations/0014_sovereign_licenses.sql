-- Active sovereign licenses used by the worker's QAL access middleware.
-- expires_at is a Unix timestamp in milliseconds; NULL or legacy zero means lifetime.
CREATE TABLE IF NOT EXISTS sovereign_licenses (
  identity TEXT PRIMARY KEY NOT NULL CHECK (length(identity) BETWEEN 1 AND 64),
  tier TEXT NOT NULL DEFAULT 'standard' CHECK (length(trim(tier)) > 0),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  expires_at INTEGER CHECK (expires_at IS NULL OR expires_at >= 0),
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);

CREATE INDEX IF NOT EXISTS idx_sovereign_licenses_lookup
  ON sovereign_licenses(identity, status);
