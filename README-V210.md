# نجات بده v211 — frontend/backend contract alignment

v211 is based directly on v209.

## Real issue fixed
The v209 backend exposes `/api/products`, `/api/seller/products`, and the order contract `product_id + quantity`, while older frontend functions still called legacy `/api/packages` endpoints and sent `{id}` during checkout. That could make the visible site fail at real checkout or seller stock management.

## Fixes
- Seller publish/stock/delete now call the real `/api/seller/products` endpoints.
- Checkout now sends `product_id + quantity` and an `Idempotency-Key`.
- Order rendering uses `total_amount` and the actual server item fields.
- The existing v206-v209 backend/security/database foundation is retained.

## Verification
- v209 unit/security suite: PASS.
- v209 integration suite: PASS.
- Worker syntax: PASS.
- Frontend API contract scan: no active latest checkout/seller handlers use `/api/packages`.

## Still required before production
- Real D1 database ID.
- Production secrets (`ALLOWED_ORIGINS`, `CURSOR_SECRET`).
- Remote migrations.
- Real staging smoke test against Cloudflare.

## v211 production hygiene
- Worker name is now the stable production name `nejat-bede` instead of a stale versioned name.
- `/api/health` reports the actual release version `v211` for monitoring.
