PRAGMA foreign_keys = ON;

ALTER TABLE orders ADD COLUMN idempotency_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_customer_idempotency
ON orders(customer_user_id, idempotency_key)
WHERE idempotency_key IS NOT NULL;
