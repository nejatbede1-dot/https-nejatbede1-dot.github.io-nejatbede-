PRAGMA foreign_keys = ON;

-- Extend the v154 status state machine with explicit admin review outcomes.
DROP TRIGGER IF EXISTS trg_orders_status_validate;
CREATE TRIGGER trg_orders_status_validate
BEFORE UPDATE OF status ON orders
FOR EACH ROW
WHEN NOT (
  (OLD.status = 'pending' AND NEW.status IN ('pending','cancelled','approved','rejected'))
  OR (OLD.status = 'approved' AND NEW.status = 'approved')
  OR (OLD.status = 'rejected' AND NEW.status = 'rejected')
  OR (OLD.status = 'cancelled' AND NEW.status = 'cancelled')
)
BEGIN
  SELECT RAISE(ABORT, 'invalid_order_status_transition');
END;

CREATE TRIGGER IF NOT EXISTS trg_orders_reject_restore_stock
AFTER UPDATE OF status ON orders
FOR EACH ROW
WHEN OLD.status = 'pending' AND NEW.status = 'rejected'
BEGIN
  UPDATE products
     SET remaining = remaining + (
       SELECT COALESCE(SUM(oi.quantity), 0)
       FROM order_items oi
       WHERE oi.order_id = NEW.id AND oi.product_id = products.id
     )
   WHERE id IN (SELECT product_id FROM order_items WHERE order_id = NEW.id);
END;
