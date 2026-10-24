PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS order_status_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id TEXT NOT NULL,
  actor_user_id TEXT NOT NULL,
  from_status TEXT NOT NULL,
  to_status TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT,
  CHECK (from_status <> to_status),
  CHECK (from_status IN ('pending','cancelled','approved','rejected')),
  CHECK (to_status IN ('pending','cancelled','approved','rejected'))
);

CREATE INDEX IF NOT EXISTS idx_order_status_audit_order_created
  ON order_status_audit(order_id, created_at, id);
CREATE INDEX IF NOT EXISTS idx_order_status_audit_actor_created
  ON order_status_audit(actor_user_id, created_at, id);
