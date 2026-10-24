PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS payment_status_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  payment_id TEXT NOT NULL,
  order_id TEXT NOT NULL,
  actor_user_id TEXT NOT NULL,
  from_status TEXT NOT NULL CHECK (from_status IN ('pending','paid','failed','refunded')),
  to_status TEXT NOT NULL CHECK (to_status IN ('pending','paid','failed','refunded')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (payment_id) REFERENCES payments(id),
  FOREIGN KEY (order_id) REFERENCES orders(id),
  FOREIGN KEY (actor_user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_payment_status_audit_payment_created
  ON payment_status_audit(payment_id, created_at ASC, id ASC);

CREATE TRIGGER IF NOT EXISTS trg_payment_status_audit_integrity
BEFORE INSERT ON payment_status_audit
FOR EACH ROW
BEGIN
  SELECT CASE
    WHEN (SELECT order_id FROM payments WHERE id = NEW.payment_id) IS NULL
      THEN RAISE(ABORT, 'payment_audit_payment_not_found')
    WHEN NEW.order_id <> (SELECT order_id FROM payments WHERE id = NEW.payment_id)
      THEN RAISE(ABORT, 'payment_audit_order_mismatch')
    WHEN NEW.from_status = NEW.to_status
      THEN RAISE(ABORT, 'payment_audit_noop')
  END;
END;
