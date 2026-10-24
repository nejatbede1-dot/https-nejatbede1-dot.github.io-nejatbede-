PRAGMA foreign_keys = ON;

CREATE INDEX IF NOT EXISTS idx_order_items_product ON order_items(product_id);
CREATE INDEX IF NOT EXISTS idx_orders_status_created ON orders(status, created_at);

CREATE TRIGGER IF NOT EXISTS order_item_check_stock
BEFORE INSERT ON order_items
FOR EACH ROW
BEGIN
  SELECT CASE
    WHEN (SELECT status FROM products WHERE id = NEW.product_id) IS NULL
      THEN RAISE(ABORT, 'product_not_found')
    WHEN (SELECT status FROM products WHERE id = NEW.product_id) <> 'active'
      THEN RAISE(ABORT, 'product_not_active')
    WHEN (SELECT remaining FROM products WHERE id = NEW.product_id) < NEW.quantity
      THEN RAISE(ABORT, 'insufficient_stock')
  END;
END;

CREATE TRIGGER IF NOT EXISTS order_item_decrement_stock
AFTER INSERT ON order_items
FOR EACH ROW
BEGIN
  UPDATE products
  SET remaining = remaining - NEW.quantity
  WHERE id = NEW.product_id;
END;
