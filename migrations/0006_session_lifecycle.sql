PRAGMA foreign_keys = ON;

-- Supports efficient cleanup of expired sessions without exposing token material.
CREATE INDEX IF NOT EXISTS idx_sessions_expired ON sessions(expires_at, id);
