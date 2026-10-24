-- v200: optimize per-user security-audit queries ordered by time when no event/session filter is present.
CREATE INDEX IF NOT EXISTS idx_security_audit_user_created
  ON security_audit(user_id, created_at DESC, id DESC);
