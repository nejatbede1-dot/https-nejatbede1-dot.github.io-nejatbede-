-- v198: optimize per-user security-audit queries filtered by event and time.
CREATE INDEX IF NOT EXISTS idx_security_audit_user_event_created
  ON security_audit(user_id, event, created_at DESC, id DESC);
