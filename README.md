# نجات بده v209 — Public catalog boundary hardening

v209 is based directly on v208. No earlier versions are being rebuilt.

## Real issue fixed
The v208 integration suite exposed a public API boundary problem: a database/mock row could contain the internal `seller_user_id` field and the public product endpoint returned the raw row.

v209 fixes this by using an explicit allow-list serializer (`publicProductView`) for every public product response. Only public catalog fields are emitted; internal seller/account fields cannot leak even if a future query returns extra columns.

## Verification
- v208 unit/security suite retained.
- v208 integration suite rerun after the fix.
- Worker syntax checked.

## Still required before production
- Real D1 database ID.
- Production secrets (`ALLOWED_ORIGINS`, `CURSOR_SECRET`).
- Remote migrations.
- Real staging smoke test against Cloudflare.
