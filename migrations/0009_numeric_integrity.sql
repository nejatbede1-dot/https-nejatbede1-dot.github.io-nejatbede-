PRAGMA foreign_keys = ON;

-- Keep values inside JavaScript's exact integer range as well as SQLite's range.
CREATE TRIGGER IF NOT EXISTS trg_products_numeric_integrity_insert
BEFORE INSERT ON products
FOR EACH ROW
WHEN typeof(NEW.sale_price) <> 'integer'
  OR NEW.sale_price < 0
  OR NEW.sale_price > 9007199254740991
  OR typeof(NEW.remaining) <> 'integer'
  OR NEW.remaining < 0
  OR NEW.remaining > 9007199254740991
BEGIN
  SELECT RAISE(ABORT, 'product_numeric_integrity');
END;

CREATE TRIGGER IF NOT EXISTS trg_products_numeric_integrity_update
BEFORE UPDATE OF sale_price, remaining ON products
FOR EACH ROW
WHEN typeof(NEW.sale_price) <> 'integer'
  OR NEW.sale_price < 0
  OR NEW.sale_price > 9007199254740991
  OR typeof(NEW.remaining) <> 'integer'
  OR NEW.remaining < 0
  OR NEW.remaining > 9007199254740991
BEGIN
  SELECT RAISE(ABORT, 'product_numeric_integrity');
END;

CREATE TRIGGER IF NOT EXISTS trg_orders_numeric_integrity_insert
BEFORE INSERT ON orders
FOR EACH ROW
WHEN typeof(NEW.total_amount) <> 'integer'
  OR NEW.total_amount < 0
  OR NEW.total_amount > 9007199254740991
BEGIN
  SELECT RAISE(ABORT, 'order_numeric_integrity');
END;

CREATE TRIGGER IF NOT EXISTS trg_orders_numeric_integrity_update
BEFORE UPDATE OF total_amount ON orders
FOR EACH ROW
WHEN typeof(NEW.total_amount) <> 'integer'
  OR NEW.total_amount < 0
  OR NEW.total_amount > 9007199254740991
BEGIN
  SELECT RAISE(ABORT, 'order_numeric_integrity');
END;

CREATE TRIGGER IF NOT EXISTS trg_order_items_numeric_integrity_insert
BEFORE INSERT ON order_items
FOR EACH ROW
WHEN typeof(NEW.quantity) <> 'integer'
  OR NEW.quantity <= 0
  OR NEW.quantity > 9007199254740991
  OR typeof(NEW.unit_price) <> 'integer'
  OR NEW.unit_price < 0
  OR NEW.unit_price > 9007199254740991
BEGIN
  SELECT RAISE(ABORT, 'order_item_numeric_integrity');
END;

CREATE TRIGGER IF NOT EXISTS trg_order_items_numeric_integrity_update
BEFORE UPDATE OF quantity, unit_price ON order_items
FOR EACH ROW
WHEN typeof(NEW.quantity) <> 'integer'
  OR NEW.quantity <= 0
  OR NEW.quantity > 9007199254740991
  OR typeof(NEW.unit_price) <> 'integer'
  OR NEW.unit_price < 0
  OR NEW.unit_price > 9007199254740991
BEGIN
  SELECT RAISE(ABORT, 'order_item_numeric_integrity');
END;

CREATE TRIGGER IF NOT EXISTS trg_payments_numeric_integrity_insert
BEFORE INSERT ON payments
FOR EACH ROW
WHEN typeof(NEW.amount) <> 'integer'
  OR NEW.amount < 0
  OR NEW.amount > 9007199254740991
BEGIN
  SELECT RAISE(ABORT, 'payment_numeric_integrity');
END;

CREATE TRIGGER IF NOT EXISTS trg_payments_numeric_integrity_update
BEFORE UPDATE OF amount ON payments
FOR EACH ROW
WHEN typeof(NEW.amount) <> 'integer'
  OR NEW.amount < 0
  OR NEW.amount > 9007199254740991
BEGIN
  SELECT RAISE(ABORT, 'payment_numeric_integrity');
END;
