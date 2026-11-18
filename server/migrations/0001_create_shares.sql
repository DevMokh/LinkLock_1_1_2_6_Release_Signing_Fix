CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY NOT NULL,
  iv TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  revoke_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_shares_expiry ON shares (expires_at);
CREATE INDEX IF NOT EXISTS idx_shares_revoked ON shares (revoked_at);
