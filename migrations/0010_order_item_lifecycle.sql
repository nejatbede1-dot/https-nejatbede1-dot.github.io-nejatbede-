PRAGMA foreign_keys = ON;

-- Order items are immutable once an order leaves the pending state.
-- This prevents stock from being silently changed after cancellation and
-- keeps the financial snapshot in order_items stable for the order lifetime.
CREATE TRIGGER IF NOT EXISTS trg_order_items_insert_pending_only
BEFORE INSERT ON order_items
FOR EACH ROW
WHEN COALESCE((SELECT status FROM orders WHERE id = NEW.order_id), '') <> 'pending'
BEGIN
  SELECT RAISE(ABORT, 'order_items_locked');
END;

CREATE TRIGGER IF NOT EXISTS trg_order_items_update_pending_only
BEFORE UPDATE ON order_items
FOR EACH ROW
WHEN COALESCE((SELECT status FROM orders WHERE id = OLD.order_id), '') <> 'pending'
  OR COALESCE((SELECT status FROM orders WHERE id = NEW.order_id), '') <> 'pending'
BEGIN
  SELECT RAISE(ABORT, 'order_items_locked');
END;

CREATE TRIGGER IF NOT EXISTS trg_order_items_delete_pending_only
BEFORE DELETE ON order_items
FOR EACH ROW
WHEN COALESCE((SELECT status FROM orders WHERE id = OLD.order_id), '') <> 'pending'
BEGIN
  SELECT RAISE(ABORT, 'order_items_locked');
END;
