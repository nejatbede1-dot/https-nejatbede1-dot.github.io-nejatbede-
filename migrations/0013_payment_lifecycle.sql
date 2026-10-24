PRAGMA foreign_keys = ON;

-- Payment records are internal state records only; no external gateway charge is performed here.
CREATE TRIGGER IF NOT EXISTS trg_payment_integrity_insert
BEFORE INSERT ON payments
FOR EACH ROW
BEGIN
  SELECT CASE
    WHEN (SELECT id FROM orders WHERE id = NEW.order_id) IS NULL
      THEN RAISE(ABORT, 'payment_order_not_found')
    WHEN NEW.amount <> (SELECT total_amount FROM orders WHERE id = NEW.order_id)
      THEN RAISE(ABORT, 'payment_amount_mismatch')
    WHEN NEW.status NOT IN ('pending','paid','failed','refunded')
      THEN RAISE(ABORT, 'payment_status_invalid')
    WHEN NEW.status = 'paid' AND (SELECT status FROM orders WHERE id = NEW.order_id) <> 'approved'
      THEN RAISE(ABORT, 'payment_order_not_approved')
    WHEN NEW.status = 'refunded'
      THEN RAISE(ABORT, 'payment_refund_invalid')
  END;
END;

CREATE TRIGGER IF NOT EXISTS trg_payment_integrity_update
BEFORE UPDATE OF amount, status, order_id
ON payments
FOR EACH ROW
BEGIN
  SELECT CASE
    WHEN (SELECT id FROM orders WHERE id = NEW.order_id) IS NULL
      THEN RAISE(ABORT, 'payment_order_not_found')
    WHEN NEW.amount <> (SELECT total_amount FROM orders WHERE id = NEW.order_id)
      THEN RAISE(ABORT, 'payment_amount_mismatch')
    WHEN NEW.status NOT IN ('pending','paid','failed','refunded')
      THEN RAISE(ABORT, 'payment_status_invalid')
    WHEN NEW.status = 'paid' AND (SELECT status FROM orders WHERE id = NEW.order_id) <> 'approved'
      THEN RAISE(ABORT, 'payment_order_not_approved')
    WHEN OLD.status = 'refunded' AND NEW.status <> 'refunded'
      THEN RAISE(ABORT, 'payment_status_transition_invalid')
    WHEN OLD.status = 'paid' AND NEW.status NOT IN ('paid','refunded')
      THEN RAISE(ABORT, 'payment_status_transition_invalid')
    WHEN OLD.status = 'failed' AND NEW.status NOT IN ('failed','pending')
      THEN RAISE(ABORT, 'payment_status_transition_invalid')
    WHEN OLD.status = 'pending' AND NEW.status NOT IN ('pending','paid','failed')
      THEN RAISE(ABORT, 'payment_status_transition_invalid')
  END;
END;

CREATE INDEX IF NOT EXISTS idx_payments_status_created ON payments(status, created_at);
