ALTER TABLE shares ADD COLUMN key_id TEXT NOT NULL DEFAULT 'v1';

CREATE TABLE IF NOT EXISTS abuse_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  share_id TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (reason IN ('phishing', 'malware', 'spam', 'other')),
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_abuse_reports_share_created
  ON abuse_reports (share_id, created_at);
