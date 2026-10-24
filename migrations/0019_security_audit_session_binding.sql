-- v189: bind session-related security audit events to the affected session.
ALTER TABLE security_audit ADD COLUMN session_id TEXT;
