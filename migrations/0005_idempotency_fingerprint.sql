PRAGMA foreign_keys = ON;

ALTER TABLE orders ADD COLUMN idempotency_request_hash TEXT;
