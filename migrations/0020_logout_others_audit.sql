-- v191: support an audit event for revoking every session except the current one.
CREATE TABLE security_audit_v191 (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event TEXT NOT NULL CHECK (event IN ('password_changed','logout_all','login_success','logout','session_revoked','logout_others')),
  request_id TEXT NOT NULL,
  session_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO security_audit_v191 (id, user_id, event, request_id, session_id, created_at)
  SELECT id, user_id, event, request_id, session_id, created_at FROM security_audit;
DROP TABLE security_audit;
ALTER TABLE security_audit_v191 RENAME TO security_audit;
CREATE INDEX idx_security_audit_user_created ON security_audit(user_id, created_at DESC, id DESC);
CREATE INDEX idx_security_audit_event_created ON security_audit(event, created_at DESC, id DESC);
