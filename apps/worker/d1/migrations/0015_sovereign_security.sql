-- Migration: 0015_sovereign_security.sql
-- Description: Establishes sovereign identity public key registry and atomic nonce tracking for zero-trust edge requests.

-- Table 1: Registered Sovereign Identities & Public Keys
CREATE TABLE IF NOT EXISTS sovereign_identities (
    identity TEXT PRIMARY KEY NOT NULL CHECK (length(identity) BETWEEN 1 AND 64),
    public_key TEXT NOT NULL CHECK (length(public_key) = 64),
    created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED'))
);

-- Table 2: Single-use nonce tracking for replay attack prevention.
CREATE TABLE IF NOT EXISTS sovereign_nonces (
    req_id TEXT PRIMARY KEY NOT NULL,
    identity TEXT NOT NULL REFERENCES sovereign_identities(identity) ON DELETE CASCADE,
    created_at INTEGER NOT NULL
);

-- Support expiration cleanup and identity-scoped nonce checks.
CREATE INDEX IF NOT EXISTS idx_sovereign_nonces_created
    ON sovereign_nonces(created_at);
CREATE INDEX IF NOT EXISTS idx_sovereign_nonces_identity_created
    ON sovereign_nonces(identity, created_at);
