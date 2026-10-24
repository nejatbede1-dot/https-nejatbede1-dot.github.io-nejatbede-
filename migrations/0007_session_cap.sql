PRAGMA foreign_keys = ON;

-- Supports deterministic trimming of old sessions per user.
CREATE INDEX IF NOT EXISTS idx_sessions_user_created ON sessions(user_id, created_at DESC, id DESC);
