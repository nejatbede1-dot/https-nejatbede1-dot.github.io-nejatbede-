-- v197: optimize security-event queries filtered by the current user's session.
CREATE INDEX IF NOT EXISTS idx_security_audit_user_session_created
  ON security_audit(user_id, session_id, created_at DESC, id DESC);
