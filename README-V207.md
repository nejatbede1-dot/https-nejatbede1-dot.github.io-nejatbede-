# نجات بده v207 — Real integration foundation

v207 keeps the v206 production backend as the security/data foundation and connects the existing Persian UI to it.

## What changed
- Cloudflare Worker now serves the existing UI through Workers Assets; `/api/*` still runs in the Worker first.
- Browser API calls automatically attach the short-lived-in-practice D1 session bearer token returned by login.
- Public catalog reads from D1 `/api/products`; browser localStorage is only a cache.
- Seller application flow is server-authoritative: customer can apply, admin can approve/reject.
- Seller product creation, listing, stock changes and deactivation are server-authoritative.
- Product listing exposes only public shop name, never the seller account ID.
- Existing v206 order API remains the source of truth for pricing and stock; frontend adapter sends `product_id` + `quantity` and an `Idempotency-Key`.

## Production blockers still required
- Replace `REPLACE_WITH_DATABASE_ID` in `worker/wrangler.toml` with the real D1 database ID.
- Configure production `ALLOWED_ORIGINS` and `CURSOR_SECRET` as documented by v206.
- Run the existing v206 release/integration checks in a Node >=20 environment.
- Apply migrations remotely and perform a real smoke test before public launch.

## v208 security hardening
- Primary browser authentication now uses an HttpOnly, Secure, SameSite=Lax `__Host-NEJAT_SESSION` cookie.
- The browser no longer persists the session bearer token in localStorage.
- Legacy Authorization bearer requests remain accepted for compatibility with existing integrations.
- Logout, logout-all and password-change responses clear the session cookie when the current session is revoked.
