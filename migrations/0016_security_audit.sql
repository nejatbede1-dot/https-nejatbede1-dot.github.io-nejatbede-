CREATE TABLE IF NOT EXISTS security_audit (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event TEXT NOT NULL CHECK (event IN ('password_changed','logout_all')),
  request_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_security_audit_user_created ON security_audit(user_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_security_audit_event_created ON security_audit(event, created_at DESC, id DESC);
