import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import worker from './worker/index.js';

const db = new DatabaseSync(':memory:');
for (const file of ['0001_initial.sql','0002_auth.sql','0003_orders.sql','0004_order_idempotency.sql','0005_idempotency_fingerprint.sql','0006_session_lifecycle.sql','0007_session_cap.sql','0008_order_status_lifecycle.sql','0009_numeric_integrity.sql','0010_order_item_lifecycle.sql','0011_order_review_lifecycle.sql','0012_order_status_audit.sql','0013_payment_lifecycle.sql','0014_payment_status_audit.sql','0015_session_cap_db_guard.sql','0016_security_audit.sql','0017_security_audit_login_logout.sql','0018_session_revoke_audit.sql','0019_security_audit_session_binding.sql','0020_logout_others_audit.sql','0021_security_audit_session_index.sql','0022_security_audit_event_index.sql','0023_security_audit_user_created_index.sql']) {
  db.exec(fs.readFileSync(new URL(`./migrations/${file}`, import.meta.url), 'utf8'));
}

const auditIndexPlan = db.prepare("EXPLAIN QUERY PLAN SELECT id, event, request_id, session_id, created_at FROM security_audit WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?").all('user-plan-check', 20, 0);
if (!auditIndexPlan.some(row => String(row.detail || '').includes('idx_security_audit_user_created'))) throw Error('security audit user-created index is not used by the base ordered query');

function prepare(sql) {
  let params = [];
  return {
    bind(...args) { params = args; return this; },
    async first() {
      const row = db.prepare(sql).get(...params);
      return row ? Object.fromEntries(Object.entries(row)) : null;
    },
    async all() {
      const rows = db.prepare(sql).all(...params);
      return { results: rows.map(r => Object.fromEntries(Object.entries(r))) };
    },
    async run() {
      const result = db.prepare(sql).run(...params);
      return { success: true, meta: { changes: Number(result.changes), last_row_id: Number(result.lastInsertRowid) } };
    }
  };
}

const env = { CURSOR_SECRET: 'integration-test-secret', DB: { prepare, async batch(statements) { db.exec('BEGIN'); try { const results=[]; for (const s of statements) { const result=db.prepare(s.sql).run(...s.params); results.push({success:true,meta:{changes:Number(result.changes),last_row_id:Number(result.lastInsertRowid)}}); } db.exec('COMMIT'); return results; } catch (e) { db.exec('ROLLBACK'); throw e; } } } };
// The Worker calls DB.prepare(...).bind(...), so expose bind-carrying statements for batch.
// Patch prepare() so statements retain their SQL/params for D1-like batch behavior.
const originalPrepare = env.DB.prepare;
env.DB.prepare = (sql) => {
  const s = originalPrepare(sql);
  s.sql = sql; s.params = [];
  const originalBind = s.bind;
  s.bind = (...args) => { s.params = args; originalBind(...args); return s; };
  return s;
};

async function req(method, path, body, headers = {}) {
  const request = new Request('https://example.com' + path, {
    method,
    headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  const response = await worker.fetch(request, env);
  let json = null;
  try { json = await response.json(); } catch {}
  return { response, json };
}

let x = await req('POST', '/api/health'); if (x.response.status !== 405 || x.json?.error !== 'method_not_allowed' || x.response.headers.get('Allow') !== 'GET, HEAD, OPTIONS') throw Error('health method integration failed');
x = await req('GET', '/api/health/db');
if (x.response.status !== 200 || x.json?.database !== 'reachable') throw Error('DB health integration failed');
// Input hardening: JSON must be an object and oversized auth/order payloads are rejected before D1 work.
x = await req('POST', '/api/auth/register', []);
if (x.response.status !== 400 || x.json?.error !== 'invalid_json') throw Error('JSON object guard integration failed');
x = await req('POST', '/api/auth/register', { phone: '+994501234567', password: 'x'.repeat(9000) });
if (x.response.status !== 413 || x.json?.error !== 'body_too_large') throw Error('register size guard integration failed');
x = await req('POST', '/api/orders', { items: [{ product_id: 'p1', quantity: 1 }], padding: 'x'.repeat(25000) }, { Authorization: 'Bearer malformed' });
if (x.response.status !== 401) throw Error('orders auth boundary changed unexpectedly');

x = await req('GET', '/api/db/stats');
if (x.response.status !== 403 || x.json?.error !== 'forbidden') throw Error('DB stats must be admin-only');
env.ALLOWED_ORIGINS = 'https://app.example';
x = await req('OPTIONS', '/api/db/stats', undefined, { Origin: 'https://app.example' });
if (x.response.status !== 204 || x.response.headers.get('Access-Control-Allow-Origin') !== 'https://app.example' || !x.response.headers.get('Access-Control-Allow-Headers')?.includes('Authorization')) throw Error('DB stats CORS preflight failed');
x = await req('GET', '/api/health', undefined, { Origin: 'https://app.example' });
if (x.response.headers.get('Access-Control-Allow-Origin') !== 'https://app.example' || x.response.headers.get('Vary') !== 'Origin') throw Error('allowed origin CORS failed');
x = await req('GET', '/api/health', undefined, { Origin: 'https://evil.example' });
if (x.response.headers.get('Access-Control-Allow-Origin')) throw Error('disallowed origin leaked CORS header');
x = await req('OPTIONS', '/api/auth/login', undefined, { Origin: 'https://evil.example' });
if (x.response.status !== 403) throw Error('disallowed preflight must be rejected');
x = await req('OPTIONS', '/api/auth/login', undefined, { Origin: 'https://app.example' });
if (x.response.status !== 204 || x.response.headers.get('Access-Control-Allow-Origin') !== 'https://app.example') throw Error('allowed preflight failed');
delete env.ALLOWED_ORIGINS;
x = await req('GET', '/api/health', undefined, { Origin: 'https://app.example' });
if (x.response.headers.get('Access-Control-Allow-Origin')) throw Error('unset ALLOWED_ORIGINS must fail closed');
x = await req('OPTIONS', '/api/auth/login', undefined, { Origin: 'https://app.example' });
if (x.response.status !== 403) throw Error('unset ALLOWED_ORIGINS preflight must fail closed');

x = await req('POST', '/api/auth/register', { phone: '+994501234567', password: 'password123' });
if (x.response.status !== 201 || !x.json?.user?.id) throw Error('register integration failed');
const userId = x.json.user.id;

db.prepare(`INSERT INTO products (id, seller_user_id, name, sale_price, remaining, status) VALUES (?, ?, ?, ?, ?, 'active')`).run('p1', userId, 'Test product', 1250, 3);
x = await req('GET', '/api/products/p1'); console.log('DEBUG PRODUCT', x.json);
if (x.response.status !== 200 || x.json?.product?.seller_user_id !== undefined) throw Error('public product leaked seller_user_id');
x = await req('GET', '/api/products');
if (x.response.status !== 200 || (x.json?.products || []).some(p => p.seller_user_id !== undefined)) throw Error('product list leaked seller_user_id');
if (!x.response.headers.get('ETag') || !x.response.headers.get('Cache-Control')?.includes('public')) throw Error('product list cache headers missing');
const productListEtag = x.response.headers.get('ETag');
x = await req('GET', `/api/products`, undefined, { 'If-None-Match': productListEtag });
if (x.response.status !== 304 || x.response.headers.get('ETag') !== productListEtag) throw Error('product list ETag revalidation failed');
x = await req('GET', '/api/products', undefined, { 'If-None-Match': `"not-this", W/${productListEtag}` });
if (x.response.status !== 304 || x.response.headers.get('ETag') !== productListEtag) throw Error('product list weak/multi ETag revalidation failed');
x = await req('HEAD', '/api/products', undefined, { 'If-None-Match': '*' });
if (x.response.status !== 304 || x.response.headers.get('ETag') !== productListEtag || (await x.response.text()) !== '') throw Error('product list HEAD wildcard ETag failed');
const stableEtagFirst = productListEtag;
x = await req('GET', '/api/products');
if (x.response.status !== 200 || x.response.headers.get('ETag') !== stableEtagFirst) throw Error('product list ETag was not stable for unchanged representation');
x = await req('HEAD', '/api/products');
if (x.response.status !== 200 || !x.response.headers.get('ETag') || (await x.response.text()) !== '') throw Error('product list HEAD failed');
x = await req('HEAD', '/api/products/p1');
if (x.response.status !== 200 || !x.response.headers.get('ETag') || (await x.response.text()) !== '') throw Error('product detail HEAD failed');
db.prepare(`INSERT INTO products (id, seller_user_id, name, sale_price, remaining, status, created_at) VALUES (?, ?, ?, ?, ?, 'active', ?)`).run('p2', userId, 'Test product 2', 1300, 4, '2026-10-01 10:00:00');
db.prepare(`INSERT INTO products (id, seller_user_id, name, sale_price, remaining, status, created_at) VALUES (?, ?, ?, ?, ?, 'active', ?)`).run('p3', userId, 'Test product 3', 1400, 5, '2026-10-01 10:00:00');
x = await req('GET', '/api/products?limit=2');
if (x.response.status !== 200 || x.json?.products?.length !== 2 || !x.json?.pagination?.has_more || !x.json?.pagination?.next_cursor) throw Error('product pagination first page failed');
const productPage1Ids = x.json.products.map(p => p.id);
const productCursor = x.json.pagination.next_cursor;
x = await req('GET', `/api/products?limit=2&cursor=${encodeURIComponent(productCursor)}`);
if (x.response.status !== 200 || x.json?.products?.length !== 1 || x.json.products.some(p => productPage1Ids.includes(p.id))) throw Error('product cursor second page failed');
if (x.json?.products?.[0]?.id !== 'p2' || x.json?.pagination?.cursor !== productCursor) throw Error('product cursor ordering failed');
const productTampered = productCursor.slice(0, -1) + (productCursor.endsWith('0') ? '1' : '0');
x = await req('GET', `/api/products?limit=2&cursor=${encodeURIComponent(productTampered)}`);
if (x.response.status !== 400 || x.json?.error !== 'invalid_cursor') throw Error('tampered product cursor was accepted');
const oldCursorPayload = JSON.stringify({ v: 2, scope: 'active-in-stock', created_at: '2026-10-01 10:00:00', id: 'p2', limit: 2, exp: Math.floor(Date.now() / 1000) + 900 });
const oldCursorEncoded = Buffer.from(oldCursorPayload).toString('base64url');
const oldCursorSignature = crypto.createHash('sha256').update(`${env.CURSOR_SECRET}.${oldCursorPayload}`).digest('hex');
const oldV2Cursor = `${oldCursorEncoded}.${oldCursorSignature}`;
x = await req('GET', `/api/products?limit=2&cursor=${encodeURIComponent(oldV2Cursor)}`);
if (x.response.status !== 400 || x.json?.error !== 'invalid_cursor') throw Error('legacy v2 product cursor was accepted');
const expiredPayload = JSON.stringify({ v: 3, scope: 'active-in-stock', created_at: '2026-10-01 10:00:00', id: 'p2', limit: 2, exp: Math.floor(Date.now() / 1000) - 1 });
const expiredSignature = crypto.createHmac('sha256', env.CURSOR_SECRET).update(expiredPayload).digest('hex');
const expiredCursor = `${Buffer.from(expiredPayload).toString('base64url')}.${expiredSignature}`;
x = await req('GET', `/api/products?limit=2&cursor=${encodeURIComponent(expiredCursor)}`);
if (x.response.status !== 400 || x.json?.error !== 'invalid_cursor') throw Error('expired product cursor was accepted');
x = await req('GET', `/api/products?limit=1&cursor=${encodeURIComponent(productCursor)}`);
if (x.response.status !== 400 || x.json?.error !== 'invalid_cursor') throw Error('product cursor limit mismatch was accepted');
x = await req('GET', `/api/products?limit=2&offset=0`);
if (x.response.status !== 200 || x.json?.products?.length !== 2 || x.json?.pagination?.next_offset !== 2) throw Error('product offset pagination failed');
x = await req('GET', `/api/products?limit=2&cursor=${encodeURIComponent(productCursor)}&offset=1`);
if (x.response.status !== 400 || x.json?.error !== 'invalid_pagination') throw Error('product cursor+offset was accepted');

x = await req('POST', '/api/auth/login', { phone: '+994501234567', password: 'password123' });
if (x.response.status !== 200 || !x.json?.token) throw Error('login integration failed');
const token = x.json.token;
// Password-change lifecycle: changing the password revokes every active session atomically.
x = await req('POST', '/api/auth/register', { phone: '+994501234568', password: 'password123' });
if (x.response.status !== 201 || !x.json?.user?.id) throw Error('password-change test user registration failed');
const passwordChangeUserId = x.json.user.id;
x = await req('POST', '/api/auth/login', { phone: '+994501234568', password: 'password123' });
if (x.response.status !== 200 || !x.json?.token) throw Error('password-change test login failed');
const passwordChangeToken = x.json.token;
x = await req('POST', '/api/auth/change-password', { current_password: 'wrong-password', new_password: 'password456' }, { Authorization: `Bearer ${passwordChangeToken}` });
if (x.response.status !== 401 || x.json?.error !== 'invalid_current_password') throw Error('wrong current password was accepted');
x = await req('POST', '/api/auth/change-password', { current_password: 'password123', new_password: 'password123' }, { Authorization: `Bearer ${passwordChangeToken}` });
if (x.response.status !== 400 || x.json?.error !== 'password_reuse') throw Error('password reuse was accepted');
x = await req('POST', '/api/auth/change-password', { current_password: 'password123', new_password: 'password456' }, { Authorization: `Bearer ${passwordChangeToken}` });
if (x.response.status !== 200 || x.json?.reauthenticate !== true || x.json?.sessions_revoked !== true) throw Error('password change failed');
x = await req('GET', '/api/auth/me', undefined, { Authorization: `Bearer ${passwordChangeToken}` });
if (x.response.status !== 401) throw Error('password change did not revoke old session');
x = await req('POST', '/api/auth/login', { phone: '+994501234568', password: 'password123' });
if (x.response.status !== 401) throw Error('old password remained valid after password change');
x = await req('POST', '/api/auth/login', { phone: '+994501234568', password: 'password456' });
if (x.response.status !== 200 || !x.json?.token) throw Error('new password login failed');
const passwordChangeNewToken = x.json.token;
x = await req('GET', '/api/auth/me', undefined, { Authorization: `Bearer ${passwordChangeNewToken}` });
if (x.response.status !== 200 || x.json?.user?.id !== passwordChangeUserId) throw Error('new password session failed');
const passwordAudit = db.prepare("SELECT event, request_id FROM security_audit WHERE user_id = ? AND event = 'password_changed' ORDER BY created_at DESC, id DESC LIMIT 1").get(passwordChangeUserId);
if (passwordAudit?.event !== 'password_changed' || !passwordAudit.request_id) throw Error('password change audit missing');

// v191: scheduled security-audit retention removes stale events without exposing a public purge endpoint.
db.prepare("INSERT INTO security_audit (id, user_id, event, request_id, created_at) VALUES (?, ?, 'logout_all', ?, datetime('now', '-91 days'))").run('old-security-audit', passwordChangeUserId, 'old-request');
db.prepare("INSERT INTO security_audit (id, user_id, event, request_id, created_at) VALUES (?, ?, 'logout_all', ?, datetime('now', '-10 days'))").run('recent-security-audit', passwordChangeUserId, 'recent-request');
await worker.scheduled({ cron: '0 3 * * *' }, env);
if (db.prepare("SELECT COUNT(*) AS count FROM security_audit WHERE id = 'old-security-audit'").get().count !== 0) throw Error('scheduled security audit retention did not remove stale event');
if (db.prepare("SELECT COUNT(*) AS count FROM security_audit WHERE id = 'recent-security-audit'").get().count !== 1) throw Error('scheduled security audit retention removed recent event');
env.SECURITY_AUDIT_RETENTION_DAYS = 30;
db.prepare("INSERT INTO security_audit (id, user_id, event, request_id, created_at) VALUES (?, ?, 'logout_all', ?, datetime('now', '-31 days'))").run('custom-old-security-audit', passwordChangeUserId, 'custom-old');
db.prepare("INSERT INTO security_audit (id, user_id, event, request_id, created_at) VALUES (?, ?, 'logout_all', ?, datetime('now', '-29 days'))").run('custom-recent-security-audit', passwordChangeUserId, 'custom-recent');
await worker.scheduled({ cron: '0 3 * * *' }, env);
if (db.prepare("SELECT COUNT(*) AS count FROM security_audit WHERE id = 'custom-old-security-audit'").get().count !== 0) throw Error('custom security audit retention did not remove stale event');
if (db.prepare("SELECT COUNT(*) AS count FROM security_audit WHERE id = 'custom-recent-security-audit'").get().count !== 1) throw Error('custom security audit retention removed recent event');
delete env.SECURITY_AUDIT_RETENTION_DAYS;
// v182: security-events reads are rate-limited per client IP to prevent audit scraping.
const securityReadIp = '198.51.100.182';
let securityReadLast = null;
for (let i = 0; i < 60; i++) {
  securityReadLast = await req('GET', '/api/auth/security-events?limit=1', undefined, { Authorization: `Bearer ${passwordChangeNewToken}`, 'CF-Connecting-IP': securityReadIp });
  if (securityReadLast.response.status !== 200) throw Error('security events read rate limit fired too early');
}
securityReadLast = await req('GET', '/api/auth/security-events?limit=1', undefined, { Authorization: `Bearer ${passwordChangeNewToken}`, 'CF-Connecting-IP': securityReadIp });
if (securityReadLast.response.status !== 429 || securityReadLast.json?.error !== 'rate_limited' || !securityReadLast.response.headers.get('Retry-After') || !securityReadLast.response.headers.get('X-Request-ID')) throw Error('security events read rate limit failed');

// Atomic rollback: if session revocation fails, the password update must also roll back.
db.exec(`CREATE TRIGGER fail_password_change_session_delete BEFORE DELETE ON sessions WHEN OLD.user_id = '${passwordChangeUserId}' BEGIN SELECT RAISE(ABORT, 'forced_password_change_failure'); END;`);
x = await req('POST', '/api/auth/change-password', { current_password: 'password456', new_password: 'password789' }, { Authorization: `Bearer ${passwordChangeNewToken}` });
if (x.response.status !== 503 || x.json?.error !== 'database_query_failed') throw Error('password change failure was not surfaced safely');
db.exec('DROP TRIGGER fail_password_change_session_delete');
x = await req('GET', '/api/auth/me', undefined, { Authorization: `Bearer ${passwordChangeNewToken}` });
if (x.response.status !== 200) throw Error('failed password change unexpectedly revoked session');
x = await req('POST', '/api/auth/login', { phone: '+994501234568', password: 'password456' });
if (x.response.status !== 200 || !x.json?.token) throw Error('atomic rollback did not preserve old password');
x = await req('POST', '/api/auth/login', { phone: '+994501234568', password: 'password789' });
if (x.response.status !== 401) throw Error('atomic rollback unexpectedly committed new password');

db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(userId);
x = await req('GET', '/api/db/stats', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || !x.json?.counts || typeof x.json.counts.users !== 'number') throw Error('admin DB stats failed');
for (let i = 0; i < 30; i++) { x = await req('GET', '/api/db/stats', undefined, { Authorization: `Bearer ${token}`, 'CF-Connecting-IP': '203.0.113.77' }); if (x.response.status !== 200) throw Error('admin DB stats rate-limit warmup failed'); }
x = await req('GET', '/api/db/stats', undefined, { Authorization: `Bearer ${token}`, 'CF-Connecting-IP': '203.0.113.77' });
if (x.response.status !== 429 || x.json?.error !== 'rate_limited' || !x.response.headers.get('Retry-After')) throw Error('admin DB stats rate limit failed');
// v191: admin order list reads are rate-limited independently from writes.
let adminOrderListRateResponse;
for (let i = 0; i < 61; i++) {
  adminOrderListRateResponse = await req('GET', '/api/admin/orders?limit=1', undefined, { Authorization: `Bearer ${token}`, 'X-Forwarded-For': '198.51.100.186' });
}
if (adminOrderListRateResponse.response.status !== 429 || adminOrderListRateResponse.json?.error !== 'rate_limited' || !adminOrderListRateResponse.response.headers.get('Retry-After') || !adminOrderListRateResponse.response.headers.get('X-Request-ID')) throw Error('admin order list rate limit failed');

db.prepare("UPDATE users SET role = 'customer' WHERE id = ?").run(userId);

// Strict bearer-token format: malformed tokens are treated as unauthenticated.
x = await req('GET', '/api/auth/me', undefined, { Authorization: 'Bearer not-a-real-token' });
if (x.response.status !== 401 || x.json?.error !== 'unauthorized') throw Error('strict bearer token validation failed');

// Login opportunistically removes expired sessions.
db.prepare("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now', '-1 day'))").run('expired-session-test', userId, 'expired-hash-test');
if (Number(db.prepare("SELECT COUNT(*) AS count FROM sessions WHERE id = 'expired-session-test'").get().count) !== 1) throw Error('expired session setup failed');
x = await req('POST', '/api/auth/login', { phone: '+994501234567', password: 'password123' });
if (x.response.status !== 200 || !x.json?.token) throw Error('session cleanup login failed');
if (Number(db.prepare("SELECT COUNT(*) AS count FROM sessions WHERE id = 'expired-session-test'").get().count) !== 0) throw Error('expired session was not cleaned');

x = await req('GET', '/api/auth/me', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.user?.id !== userId) throw Error('session integration failed');

x = await req('POST', '/api/orders', { items: [{ product_id: 'p1', quantity: 2 }] }, { Authorization: `Bearer ${token}` });
if (x.response.status !== 201 || x.json?.order?.total_amount !== 2500) throw Error('order creation integration failed');
const firstOrderId = x.json.order.id;
db.prepare('UPDATE products SET sale_price = ? WHERE id = ?').run(9999, 'p1');
x = await req('GET', `/api/orders/${firstOrderId}`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.order?.items?.[0]?.unit_price !== 1250) throw Error('order price snapshot changed after product price update');
db.prepare('UPDATE products SET sale_price = ? WHERE id = ?').run(1250, 'p1');

x = await req('POST', `/api/orders/${firstOrderId}/cancel`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.order?.status !== 'cancelled') throw Error('pending order cancellation failed');
const stockAfterCancel = db.prepare('SELECT remaining FROM products WHERE id = ?').get('p1');
if (Number(stockAfterCancel.remaining) !== 3) throw Error(`cancel did not restore stock exactly: ${stockAfterCancel.remaining}`);
x = await req('POST', `/api/orders/${firstOrderId}/cancel`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 409 || x.json?.error !== 'order_not_cancellable') throw Error('cancelled order was cancellable twice');
x = await req('GET', `/api/admin/orders/${firstOrderId}/status-history`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 403 || x.json?.error !== 'forbidden') throw Error('non-admin audit history was not forbidden');
x = await req('POST', '/api/orders', { items: [{ product_id: 'p1', quantity: 1 }] }, { Authorization: `Bearer ${token}` });
if (x.response.status !== 201 || !x.json?.order?.id) throw Error('review approval order setup failed');
const approvalOrderId = x.json.order.id;
const stockBeforeApproval = Number(db.prepare('SELECT remaining FROM products WHERE id = ?').get('p1').remaining);
x = await req('POST', `/api/admin/orders/${approvalOrderId}/status`, { status: 'approved' }, { Authorization: `Bearer ${token}` });
if (x.response.status !== 403 || x.json?.error !== 'forbidden') throw Error('non-admin order approval was not forbidden');
db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(userId);
const atomicReviewOrderId = 'atomic-review-test';
db.prepare(`INSERT INTO orders (id, customer_user_id, total_amount, status) VALUES (?, ?, ?, 'pending')`).run(atomicReviewOrderId, userId, 1250);
db.exec(`CREATE TRIGGER trg_force_review_audit_failure BEFORE INSERT ON order_status_audit WHEN NEW.order_id = 'atomic-review-test' BEGIN SELECT RAISE(ABORT, 'forced_review_audit_failure'); END`);
x = await req('POST', `/api/admin/orders/${atomicReviewOrderId}/status`, { status: 'approved' }, { Authorization: `Bearer ${token}` });
db.exec('DROP TRIGGER trg_force_review_audit_failure');
if (x.response.status !== 503) throw Error('atomic review failure status mismatch');
if (db.prepare('SELECT status FROM orders WHERE id = ?').get(atomicReviewOrderId).status !== 'pending') throw Error('atomic review did not rollback status');
if (Number(db.prepare('SELECT COUNT(*) AS c FROM order_status_audit WHERE order_id = ?').get(atomicReviewOrderId).c) !== 0) throw Error('atomic review left audit row');
db.prepare('DELETE FROM orders WHERE id = ?').run(atomicReviewOrderId);
x = await req('POST', `/api/admin/orders/${approvalOrderId}/status`, { status: 'approved' }, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.order?.status !== 'approved') throw Error('admin order approval failed');
x = await req('GET', `/api/admin/orders/${approvalOrderId}/status-history`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.history?.length !== 1 || x.json.history[0].from_status !== 'pending' || x.json.history[0].to_status !== 'approved' || x.json.history[0].actor_user_id !== userId) throw Error('approval audit history failed');
if (Number(db.prepare('SELECT remaining FROM products WHERE id = ?').get('p1').remaining) !== stockBeforeApproval) throw Error('approval unexpectedly restored stock');
x = await req('POST', `/api/admin/orders/${approvalOrderId}/status`, { status: 'approved' }, { Authorization: `Bearer ${token}` });
if (x.response.status !== 409 || x.json?.error !== 'order_not_reviewable') throw Error('approved order was reviewable twice');

x = await req('POST', '/api/orders', { items: [{ product_id: 'p1', quantity: 1 }] }, { Authorization: `Bearer ${token}` });
if (x.response.status !== 201 || !x.json?.order?.id) throw Error('review rejection order setup failed');
const rejectionOrderId = x.json.order.id;
const stockBeforeRejection = Number(db.prepare('SELECT remaining FROM products WHERE id = ?').get('p1').remaining);
x = await req('POST', `/api/admin/orders/${rejectionOrderId}/status`, { status: 'rejected' }, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.order?.status !== 'rejected') throw Error('admin order rejection failed');
if (Number(db.prepare('SELECT remaining FROM products WHERE id = ?').get('p1').remaining) !== stockBeforeRejection + 1) throw Error('rejection did not restore exactly one unit');
x = await req('GET', `/api/admin/orders/${rejectionOrderId}/status-history`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.history?.length !== 1 || x.json.history[0].from_status !== 'pending' || x.json.history[0].to_status !== 'rejected') throw Error('rejection audit history failed');
const cancelledAudit = db.prepare('SELECT from_status, to_status, actor_user_id FROM order_status_audit WHERE order_id = ? ORDER BY id').all(firstOrderId);
if (cancelledAudit.length !== 1 || cancelledAudit[0].from_status !== 'pending' || cancelledAudit[0].to_status !== 'cancelled' || cancelledAudit[0].actor_user_id !== userId) throw Error('cancellation audit row failed');

// v167 atomicity: audit failure must roll back status and trigger-driven stock restoration together.
const atomicCancelOrderId = 'atomic-cancel-test';
db.prepare(`INSERT INTO orders (id, customer_user_id, total_amount, status) VALUES (?, ?, ?, 'pending')`).run(atomicCancelOrderId, userId, 1250);
db.prepare(`INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (?, 'p1', 1, 1250)`).run(atomicCancelOrderId);
const atomicCancelStockBefore = Number(db.prepare('SELECT remaining FROM products WHERE id = ?').get('p1').remaining);
db.exec(`CREATE TRIGGER trg_force_audit_failure BEFORE INSERT ON order_status_audit WHEN NEW.order_id = 'atomic-cancel-test' BEGIN SELECT RAISE(ABORT, 'forced_audit_failure'); END`);
x = await req('POST', `/api/orders/${atomicCancelOrderId}/cancel`, undefined, { Authorization: `Bearer ${token}` });
db.exec('DROP TRIGGER trg_force_audit_failure');
if (x.response.status !== 503) throw Error('atomic cancellation failure status mismatch');
if (db.prepare('SELECT status FROM orders WHERE id = ?').get(atomicCancelOrderId).status !== 'pending') throw Error('atomic cancellation did not rollback status');
if (Number(db.prepare('SELECT remaining FROM products WHERE id = ?').get('p1').remaining) !== atomicCancelStockBefore) throw Error('atomic cancellation did not rollback stock');
if (Number(db.prepare('SELECT COUNT(*) AS c FROM order_status_audit WHERE order_id = ?').get(atomicCancelOrderId).c) !== 0) throw Error('atomic cancellation left audit row');
db.prepare("UPDATE products SET remaining = remaining + 1 WHERE id = 'p1'").run();
db.prepare('DELETE FROM order_items WHERE order_id = ?').run(atomicCancelOrderId);
db.prepare('DELETE FROM orders WHERE id = ?').run(atomicCancelOrderId);

db.prepare("UPDATE users SET role = 'customer' WHERE id = ?").run(userId);

// Database-level state machine rejects unsupported transitions too.
let transitionRejected = false;
try { db.prepare("UPDATE orders SET status = 'approved' WHERE id = ?").run(firstOrderId); } catch (e) { transitionRejected = String(e?.message || '').includes('invalid_order_status_transition'); }
if (!transitionRejected) throw Error('invalid order status transition was not rejected');
if (Number(db.prepare('SELECT COUNT(*) AS c FROM order_status_audit WHERE order_id = ?').get(firstOrderId).c) !== 1) throw Error('invalid direct transition unexpectedly created audit row');
db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(userId);
// v169: admin order list supports status filtering and HMAC cursor pagination.
// v167: admin status-history uses stable HMAC cursor pagination.
for (let i = 0; i < 3; i++) {
  db.prepare('INSERT INTO order_status_audit (order_id, actor_user_id, from_status, to_status, created_at) VALUES (?, ?, ?, ?, ?)' ).run(firstOrderId, userId, 'pending', i % 2 ? 'approved' : 'rejected', `2026-10-01 12:0${i}:00`);
}
x = await req('GET', `/api/admin/orders/${firstOrderId}/status-history?limit=2`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.history?.length !== 2 || !x.json?.pagination?.next_cursor) throw Error('audit cursor first page failed');
const auditCursor = x.json.pagination.next_cursor;
const auditIds1 = x.json.history.map(r => r.id);
x = await req('GET', `/api/admin/orders/${firstOrderId}/status-history?limit=2&cursor=${encodeURIComponent(auditCursor)}`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || !x.json?.history?.length || x.json.history.some(r => auditIds1.includes(r.id))) throw Error('audit cursor pagination duplicated rows');
x = await req('GET', `/api/admin/orders/${firstOrderId}/status-history?limit=3&cursor=${encodeURIComponent(auditCursor)}`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_cursor') throw Error('audit cursor limit mismatch was not rejected');
const tamperedAuditCursor = auditCursor.slice(0, -1) + (auditCursor.endsWith('a') ? 'b' : 'a');
x = await req('GET', `/api/admin/orders/${firstOrderId}/status-history?limit=2&cursor=${encodeURIComponent(tamperedAuditCursor)}`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_cursor') throw Error('tampered audit cursor was not rejected');
db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(userId);
for (let i = 1; i <= 3; i++) {
  db.prepare("INSERT INTO orders (id, customer_user_id, total_amount, status, created_at) VALUES (?, ?, ?, 'pending', ?)").run(`admin-list-test-${i}`, userId, i * 100, `2026-10-01 13:0${i}:00`);
}

x = await req('GET', '/api/admin/orders?limit=2&status=pending', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.orders?.length !== 2 || x.json?.orders?.some(o => o.status !== 'pending') || !x.json?.pagination?.next_cursor) throw Error('admin order list filtered first page failed');
const adminOrderCursor = x.json.pagination.next_cursor;
x = await req('GET', `/api/admin/orders?limit=2&status=pending&cursor=${encodeURIComponent(adminOrderCursor)}`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.orders?.some(o => o.status !== 'pending')) throw Error('admin order list cursor page failed');
if (x.json?.orders?.some(o => o.id === adminOrderCursor)) throw Error('admin order list cursor leaked as order id');
x = await req('GET', `/api/admin/orders?limit=3&status=pending&cursor=${encodeURIComponent(adminOrderCursor)}`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_cursor') throw Error('admin order cursor limit mismatch accepted');
const tamperedAdminCursor = adminOrderCursor.slice(0, -1) + (adminOrderCursor.endsWith('a') ? 'b' : 'a');
x = await req('GET', `/api/admin/orders?limit=2&status=pending&cursor=${encodeURIComponent(tamperedAdminCursor)}`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_cursor') throw Error('admin order cursor tamper accepted');
x = await req('GET', '/api/admin/orders?limit=2&status=bogus', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_order_status_filter') throw Error('admin order invalid status filter accepted');
x = await req('GET', `/api/admin/orders?limit=2&status=pending&cursor=${encodeURIComponent(adminOrderCursor)}&offset=0`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_pagination') throw Error('admin order cursor+offset accepted');
x = await req('GET', '/api/admin/orders?limit=2&status=approved', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.orders?.some(o => o.status !== 'approved')) throw Error('admin order approved filter failed');

db.prepare("UPDATE users SET role = 'customer' WHERE id = ?").run(userId);
x = await req('GET', '/api/admin/orders?limit=2', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 403 || x.json?.error !== 'forbidden') throw Error('non-admin admin order list access failed');
db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(userId);
db.prepare("DELETE FROM orders WHERE id LIKE 'admin-list-test-%'").run();

// v169: internal payment record lifecycle; no external gateway is charged.
const paymentOrderId = `payment-test-${Date.now()}`;
db.prepare("INSERT INTO orders (id, customer_user_id, total_amount, status, created_at) VALUES (?, ?, 2500, 'approved', '2026-10-01 14:00:00')").run(paymentOrderId, userId);
x = await req('POST', `/api/orders/${paymentOrderId}/payment`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || !x.json?.payment || x.json.payment.amount !== 2500 || x.json.payment.status !== 'pending') throw Error('payment creation failed');
const paymentId = x.json.payment.id;
x = await req('POST', `/api/orders/${paymentOrderId}/payment`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || !x.json?.replay || x.json.payment.id !== paymentId) throw Error('payment idempotent replay failed');
x = await req('GET', `/api/orders/${paymentOrderId}/payment`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.payment?.id !== paymentId) throw Error('payment get failed');
x = await req('POST', `/api/admin/orders/${paymentOrderId}/payment-status`, { status: 'paid' }, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.payment?.status !== 'paid') throw Error('payment paid transition failed');
x = await req('POST', `/api/admin/orders/${paymentOrderId}/payment-status`, { status: 'failed' }, { Authorization: `Bearer ${token}` });
if (x.response.status !== 409 || x.json?.error !== 'payment_status_transition_invalid') throw Error('paid to failed transition was accepted');
x = await req('POST', `/api/admin/orders/${paymentOrderId}/payment-status`, { status: 'refunded' }, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.payment?.status !== 'refunded') throw Error('payment refund transition failed');
x = await req('GET', `/api/admin/orders/${paymentOrderId}/payment-history?limit=1`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.history?.length !== 1 || x.json.history[0].from_status !== 'pending' || x.json.history[0].to_status !== 'paid' || !x.json?.pagination?.next_cursor) throw Error('payment history first page failed');
const paymentHistoryCursor = x.json.pagination.next_cursor;
// v191: admin order-status audit reads are rate-limited independently from writes.
let adminOrderAuditRateResponse;
for (let i = 0; i < 61; i++) {
  adminOrderAuditRateResponse = await req('GET', `/api/admin/orders/${paymentOrderId}/status-history`, undefined, { Authorization: `Bearer ${token}`, 'X-Forwarded-For': '198.51.100.187' });
}
if (adminOrderAuditRateResponse.response.status !== 429 || adminOrderAuditRateResponse.json?.error !== 'rate_limited' || !adminOrderAuditRateResponse.response.headers.get('Retry-After') || !adminOrderAuditRateResponse.response.headers.get('X-Request-ID')) throw Error('admin order audit rate limit failed');
x = await req('GET', `/api/admin/orders/${paymentOrderId}/payment-history?limit=1&cursor=${encodeURIComponent(paymentHistoryCursor)}`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.history?.length !== 1 || x.json.history[0].from_status !== 'paid' || x.json.history[0].to_status !== 'refunded') throw Error('payment history cursor page failed');
x = await req('GET', `/api/admin/orders/${paymentOrderId}/payment-history?limit=2&cursor=${encodeURIComponent(paymentHistoryCursor)}`, undefined, { Authorization: `Bearer ${token}` });
// v191: payment-status audit reads are rate-limited independently from writes.
let adminPaymentAuditRateResponse;
for (let i = 0; i < 61; i++) {
  adminPaymentAuditRateResponse = await req('GET', `/api/admin/orders/${paymentOrderId}/payment-history?limit=1`, undefined, { Authorization: `Bearer ${token}`, 'X-Forwarded-For': '198.51.100.188' });
}
if (adminPaymentAuditRateResponse.response.status !== 429 || adminPaymentAuditRateResponse.json?.error !== 'rate_limited' || !adminPaymentAuditRateResponse.response.headers.get('Retry-After') || !adminPaymentAuditRateResponse.response.headers.get('X-Request-ID')) throw Error('admin payment audit rate limit failed');
if (x.response.status !== 400 || x.json?.error !== 'invalid_cursor') throw Error('payment history cursor limit binding failed');
x = await req('POST', `/api/admin/orders/${paymentOrderId}/payment-status`, { status: 'paid' }, { Authorization: `Bearer ${token}` });
if (x.response.status !== 409 || x.json?.error !== 'payment_status_transition_invalid') throw Error('refunded payment was reopened');
// v179: rate limiter prefers Cloudflare client IP and keeps in-isolate buckets bounded.
let adminRateResponse;
for (let i = 0; i < 21; i++) {
  adminRateResponse = await req('POST', `/api/admin/orders/${paymentOrderId}/payment-status`, { status: 'paid' }, { Authorization: `Bearer ${token}`, 'X-Forwarded-For': '198.51.100.173' });
}
if (adminRateResponse.response.status !== 429 || adminRateResponse.json?.error !== 'rate_limited' || !adminRateResponse.response.headers.get('Retry-After') || !adminRateResponse.response.headers.get('X-Request-ID')) throw Error('admin payment rate limit failed');

// Payment status + audit are atomic: an audit failure must roll back the payment status change.
const atomicOrderId = `payment-atomic-${Date.now()}`;
db.prepare("INSERT INTO orders (id, customer_user_id, total_amount, status, created_at) VALUES (?, ?, 2500, 'approved', '2026-10-01 14:30:00')").run(atomicOrderId, userId);
db.prepare("INSERT INTO payments (id, order_id, amount, status) VALUES ('payment-atomic-1', ?, 2500, 'pending')").run(atomicOrderId);
db.exec("CREATE TRIGGER payment_audit_fail BEFORE INSERT ON payment_status_audit BEGIN SELECT RAISE(ABORT, 'payment_audit_test_failure'); END;");
x = await req('POST', `/api/admin/orders/${atomicOrderId}/payment-status`, { status: 'paid' }, { Authorization: `Bearer ${token}` });
if (x.response.status !== 503 || x.json?.error !== 'database_query_failed') throw Error('payment audit failure did not surface as controlled error');
const atomicPayment = db.prepare("SELECT status FROM payments WHERE id = 'payment-atomic-1'").get();
if (atomicPayment.status !== 'pending') throw Error('payment status changed despite audit failure');
db.exec("DROP TRIGGER payment_audit_fail");
db.prepare("DELETE FROM payment_status_audit WHERE payment_id = 'payment-atomic-1'").run();
db.prepare("DELETE FROM payments WHERE id = 'payment-atomic-1'").run();
db.prepare("DELETE FROM orders WHERE id = ?").run(atomicOrderId);

// DB-level amount integrity.
let paymentIntegrityRejected = 0;
try { db.prepare("INSERT INTO payments (id, order_id, amount, status) VALUES ('bad-payment-amount', ?, 2499, 'pending')").run(paymentOrderId); } catch (e) { if (String(e?.message || '').includes('payment_amount_mismatch')) paymentIntegrityRejected++; }
if (paymentIntegrityRejected !== 1) throw Error('payment amount integrity trigger failed');
db.prepare("DELETE FROM payment_status_audit WHERE payment_id = ?").run(paymentId);
db.prepare("DELETE FROM payments WHERE order_id = ?").run(paymentOrderId);
db.prepare("DELETE FROM orders WHERE id = ?").run(paymentOrderId);


// Cancelled orders are immutable at the item level: no new stock can be consumed,
// and the historical price/quantity snapshot cannot be edited or deleted.
const firstItem = db.prepare('SELECT id, quantity, unit_price FROM order_items WHERE order_id = ? LIMIT 1').get(firstOrderId);
let itemLifecycleRejected = 0;
try { db.prepare("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (?, 'p1', 1, 1250)").run(firstOrderId); } catch (e) { if (String(e?.message || '').includes('order_items_locked')) itemLifecycleRejected++; }
try { db.prepare('UPDATE order_items SET quantity = 1 WHERE id = ?').run(firstItem.id); } catch (e) { if (String(e?.message || '').includes('order_items_locked')) itemLifecycleRejected++; }
try { db.prepare('DELETE FROM order_items WHERE id = ?').run(firstItem.id); } catch (e) { if (String(e?.message || '').includes('order_items_locked')) itemLifecycleRejected++; }
if (itemLifecycleRejected !== 3) throw Error('cancelled order item lifecycle was not locked');
const itemAfterLifecycle = db.prepare('SELECT quantity, unit_price FROM order_items WHERE id = ?').get(firstItem.id);
if (Number(itemAfterLifecycle.quantity) !== 2 || Number(itemAfterLifecycle.unit_price) !== 1250) throw Error('cancelled order item snapshot changed');

// Database numeric-integrity guardrails reject unsafe/non-integer financial and stock values.
db.prepare("INSERT INTO orders (id, customer_user_id, total_amount, status) VALUES ('numeric-order-test', ?, 0, 'pending')").run(userId);
const numericCases = [
  ["UPDATE products SET remaining = -1 WHERE id = 'p1'", 'product_numeric_integrity'],
  ["UPDATE products SET sale_price = 9007199254740992 WHERE id = 'p1'", 'product_numeric_integrity'],
  ["INSERT INTO orders (id, customer_user_id, total_amount, status) VALUES ('bad-order-1', ?, 9007199254740992, 'pending')", 'order_numeric_integrity'],
  ["INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES ('numeric-order-test', 'p1', 0, 1250)", 'order_item_numeric_integrity'],
  ["INSERT INTO payments (id, order_id, amount) VALUES ('bad-payment-1', ?, 9007199254740992)", 'payment_amount_mismatch']
];
for (const [sql, expected] of numericCases) {
  let rejected = false;
  try {
    if (sql.startsWith("INSERT INTO orders")) db.prepare(sql).run(userId);
    else if (sql.startsWith("INSERT INTO order_items")) db.prepare(sql).run();
    else if (sql.includes('bad-payment-1')) db.prepare(sql).run(firstOrderId);
    else db.prepare(sql).run();
  } catch (e) { rejected = String(e?.message || '').includes(expected); }
  if (!rejected) throw Error(`database numeric guard failed: ${expected}`);
}
db.prepare("DELETE FROM orders WHERE id = 'numeric-order-test'").run();

const stockBeforeIdempotency = db.prepare('SELECT remaining FROM products WHERE id = ?').get('p1');
if (Number(stockBeforeIdempotency.remaining) !== 2) throw Error(`unexpected stock before idempotency: ${stockBeforeIdempotency.remaining}`);
x = await req('POST', '/api/orders', { items: [{ product_id: 'p1', quantity: 1 }] }, { Authorization: `Bearer ${token}`, 'Idempotency-Key': 'checkout-145-002' });
if (x.response.status !== 201 || !x.json?.order?.id) throw Error('idempotent order creation setup failed');
const idempotentOrderId = x.json.order.id;
const stockAfterIdempotent = db.prepare('SELECT remaining FROM products WHERE id = ?').get('p1');
if (Number(stockAfterIdempotent.remaining) !== 1) throw Error(`idempotency setup stock failed: ${stockAfterIdempotent.remaining}`);
x = await req('POST', '/api/orders', { items: [{ product_id: 'p1', quantity: 1 }] }, { Authorization: `Bearer ${token}`, 'Idempotency-Key': 'checkout-145-002' });
if (x.response.status !== 200 || !x.json?.replay || x.json?.order?.id !== idempotentOrderId) throw Error('idempotency replay failed');

const stock = db.prepare('SELECT remaining FROM products WHERE id = ?').get('p1');
if (Number(stock.remaining) !== 1) throw Error(`idempotent replay changed stock: ${stock.remaining}`);

x = await req('POST', '/api/orders', { items: [{ product_id: 'p1', quantity: 999 }] }, { Authorization: `Bearer ${token}`, 'Idempotency-Key': 'checkout-145-002' });
if (x.response.status !== 409 || x.json?.error !== 'idempotency_key_reused') throw Error('idempotency key payload mismatch was not rejected');

x = await req('GET', '/api/orders?limit=2&offset=0', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.orders?.length !== 2 || !x.json?.pagination?.has_more || x.json.pagination.next_offset !== 2) throw Error('order pagination first page failed');
const firstPageIds = x.json.orders.map(o => o.id);
x = await req('GET', '/api/orders?limit=2&offset=2', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.orders?.length !== 2 || x.json?.pagination?.has_more || x.json.pagination.next_offset !== null) throw Error('order pagination second page failed');
if (x.json.orders.some(o => firstPageIds.includes(o.id))) throw Error('order pagination returned duplicate page item');
x = await req('GET', '/api/orders?limit=0', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_pagination') throw Error('invalid order pagination was accepted');
x = await req('GET', '/api/orders?limit=51', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_pagination') throw Error('oversized order pagination was accepted');
const cursorPage1 = await req('GET', '/api/orders?limit=2&offset=0', undefined, { Authorization: `Bearer ${token}` });
if (cursorPage1.response.status !== 200 || !cursorPage1.json?.pagination?.next_cursor) throw Error('cursor pagination first page failed');
const cursor = cursorPage1.json.pagination.next_cursor;
x = await req('GET', `/api/orders?limit=2&cursor=${encodeURIComponent(cursor)}`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.orders?.some(o => cursorPage1.json.orders.map(z => z.id).includes(o.id))) throw Error('cursor pagination returned duplicate page item');
if (x.json?.pagination?.cursor !== cursor) throw Error('cursor pagination response cursor mismatch');
const tampered = cursor.slice(0, -1) + (cursor.endsWith('0') ? '1' : '0');
x = await req('GET', `/api/orders?limit=2&cursor=${encodeURIComponent(tampered)}`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_cursor') throw Error('tampered cursor was accepted');
x = await req('GET', `/api/orders?limit=3&cursor=${encodeURIComponent(cursor)}`, undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_cursor') throw Error('cursor limit mismatch was accepted');


// v206: database health validates required tables and critical columns, not just connectivity.
x = await req('GET', '/api/health/db');
if (x.response.status !== 200 || x.json?.ok !== true || x.json?.database !== 'reachable' || x.json?.schema !== 'ready') throw Error('database schema readiness health failed');
x = await req('HEAD', '/api/health/db');
if (x.response.status !== 200) throw Error('database schema readiness HEAD failed');

// v206: a connected DB with an incomplete critical schema must not report ready.
const partialDb = new DatabaseSync(':memory:');
partialDb.exec(`CREATE TABLE users (id TEXT, phone TEXT, role TEXT, password_hash TEXT, status TEXT, created_at TEXT); CREATE TABLE products (id TEXT, seller_user_id TEXT, name TEXT, sale_price INTEGER, remaining INTEGER, status TEXT, created_at TEXT); CREATE TABLE sessions (id TEXT, user_id TEXT, token_hash TEXT, expires_at TEXT, created_at TEXT); CREATE TABLE orders (id TEXT, customer_user_id TEXT, total_amount INTEGER, status TEXT, created_at TEXT); CREATE TABLE order_items (id INTEGER, order_id TEXT, product_id TEXT, quantity INTEGER); CREATE TABLE payments (id TEXT, order_id TEXT, amount INTEGER, status TEXT, provider_ref TEXT, created_at TEXT); CREATE TABLE order_status_audit (id INTEGER, order_id TEXT, actor_user_id TEXT, from_status TEXT, to_status TEXT, created_at TEXT); CREATE TABLE payment_status_audit (id INTEGER, payment_id TEXT, order_id TEXT, actor_user_id TEXT, from_status TEXT, to_status TEXT, created_at TEXT); CREATE TABLE security_audit (id TEXT, user_id TEXT, event TEXT, request_id TEXT, session_id TEXT, created_at TEXT);`);
const partialEnv = { CURSOR_SECRET: 'integration-test-secret', DB: { prepare(sql) { let params=[]; return { bind(...args){params=args;return this;}, async first(){ const row=partialDb.prepare(sql).get(...params); return row ? Object.fromEntries(Object.entries(row)) : null; }, async all(){ const rows=partialDb.prepare(sql).all(...params); return { results: rows.map(r=>Object.fromEntries(Object.entries(r))) }; } }; } } };
const partialResponse = await worker.fetch(new Request('https://example.com/api/health/db'), partialEnv);
const partialJson = await partialResponse.json();
if (partialResponse.status !== 503 || partialJson.error !== 'database_schema_not_ready') throw Error('incomplete critical schema was reported ready');

const loginAudit = db.prepare("SELECT event, request_id, session_id FROM security_audit WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 1").get(userId);
if (loginAudit?.event !== 'login_success' || !loginAudit.request_id) throw Error('login-success audit missing');

// v206: security-events supports one or more validated event filters and binds the normalized filter set into signed cursors.
x = await req('GET', '/api/auth/security-events?event=login_success,logout&limit=10', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.items?.some(item => !['login_success', 'logout'].includes(item.event)) || x.json?.pagination?.event !== 'login_success,logout') throw Error('multi security event filter failed');
x = await req('GET', '/api/auth/security-events?event=logout,login_success,logout&limit=10', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.pagination?.event !== 'logout,login_success') throw Error('security event filter normalization failed');
x = await req('GET', '/api/auth/security-events?event=login_success,not-a-real-event', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_event_filter') throw Error('invalid security event filter was accepted');
x = await req('GET', '/api/auth/security-events?offset=10001', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_pagination') throw Error('security-event offset upper bound failed');
x = await req('GET', '/api/auth/security-events?offset=10000&limit=1', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200) throw Error('security-event maximum offset failed');
x = await req('GET', '/api/auth/security-events?since=2099-01-01T00:00:00Z&until=2099-01-02T00:00:00Z&limit=10', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || x.json?.items?.length !== 0 || x.json?.pagination?.since !== '2099-01-01 00:00:00' || x.json?.pagination?.until !== '2099-01-02 00:00:00') throw Error('security-event time range filter failed');
x = await req('GET', '/api/auth/security-events?since=2099-01-02T00:00:00Z&until=2099-01-01T00:00:00Z', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_time_filter') throw Error('reversed security-event time range was accepted');
x = await req('GET', '/api/auth/security-events?since=not-a-time', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 400 || x.json?.error !== 'invalid_time_filter') throw Error('invalid security-event since filter was accepted');
x = await req('GET', '/api/auth/security-events?since=2099-01-01T00:00:00Z&until=2099-01-02T00:00:00Z&limit=1', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200 || !x.json?.pagination) throw Error('security-event time cursor setup failed');
if (x.json.pagination.next_cursor) {
  const timeCursor = x.json.pagination.next_cursor;
  x = await req('GET', `/api/auth/security-events?since=2099-01-01T00:00:00Z&until=2099-01-03T00:00:00Z&limit=1&cursor=${encodeURIComponent(timeCursor)}`, undefined, { Authorization: `Bearer ${token}` });
  if (x.response.status !== 400 || x.json?.error !== 'invalid_cursor') throw Error('security-event time cursor binding failed');
}

x = await req('POST', '/api/auth/logout', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 200) throw Error('logout integration failed');
const logoutAuditNormal = db.prepare("SELECT event, request_id, session_id FROM security_audit WHERE user_id = ? AND event = 'logout' ORDER BY created_at DESC, id DESC LIMIT 1").get(userId);
if (logoutAuditNormal?.event !== 'logout' || !logoutAuditNormal.request_id) throw Error('logout audit missing');

// v206: logout endpoints have dedicated authenticated-operation rate limits + security-event filters.
const logoutRateToken = token;
for (let i = 0; i < 20; i++) {
  x = await req('POST', '/api/auth/logout', undefined, { Authorization: `Bearer ${logoutRateToken}`, 'CF-Connecting-IP': '203.0.113.190' });
  if (x.response.status !== 200 && x.response.status !== 401) throw Error(`logout rate-limit warmup failed: ${x.response.status}`);
}
x = await req('POST', '/api/auth/logout', undefined, { Authorization: `Bearer ${logoutRateToken}`, 'CF-Connecting-IP': '203.0.113.190' });
if (x.response.status !== 429 || !x.response.headers.get('Retry-After')) throw Error('logout rate limit failed');


x = await req('GET', '/api/auth/me', undefined, { Authorization: `Bearer ${token}` });
if (x.response.status !== 401) throw Error('logout invalidation failed');

// Logout-all revokes every active session for the authenticated account.
const allLogoutTokens = [];
for (let i = 0; i < 3; i++) {
  x = await req('POST', '/api/auth/login', { phone: '+994501234567', password: 'password123' });
  if (x.response.status !== 200 || !x.json?.token) throw Error(`logout-all login ${i + 1} failed`);
  allLogoutTokens.push(x.json.token);
}
x = await req('POST', '/api/auth/logout-all', undefined, { Authorization: `Bearer ${allLogoutTokens[0]}` });
if (x.response.status !== 200 || Number(x.json?.revoked_sessions) < 3) throw Error('logout-all did not revoke all sessions');
const logoutAudit = db.prepare("SELECT event, request_id, session_id FROM security_audit WHERE user_id = ? AND event = 'logout_all' ORDER BY created_at DESC, id DESC LIMIT 1").get(userId);
if (logoutAudit?.event !== 'logout_all' || !logoutAudit.request_id) throw Error('logout-all audit missing');

const logoutAllRateToken = allLogoutTokens[0];
for (let i = 0; i < 5; i++) {
  x = await req('POST', '/api/auth/logout-all', undefined, { Authorization: `Bearer ${logoutAllRateToken}`, 'CF-Connecting-IP': '203.0.113.191' });
  if (x.response.status !== 200 && x.response.status !== 401) throw Error(`logout-all rate-limit warmup failed: ${x.response.status}`);
}
x = await req('POST', '/api/auth/logout-all', undefined, { Authorization: `Bearer ${logoutAllRateToken}`, 'CF-Connecting-IP': '203.0.113.191' });
if (x.response.status !== 429 || !x.response.headers.get('Retry-After')) throw Error('logout-all rate limit failed');
for (const t of allLogoutTokens) {
  x = await req('GET', '/api/auth/me', undefined, { Authorization: `Bearer ${t}` });
  if (x.response.status !== 401) throw Error('logout-all left a session active');
}

// Session cap: multiple devices are allowed, but the account keeps only the newest five sessions.
db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
const capTokens = [];
for (let i = 0; i < 6; i++) {
  x = await req('POST', '/api/auth/login', { phone: '+994501234567', password: 'password123' }, { 'X-Forwarded-For': `198.51.100.${10 + i}` });
  if (x.response.status !== 200 || !x.json?.token) throw Error(`session cap login ${i + 1} failed: ${x.response.status}`);
  capTokens.push(x.json.token);
}
const sessionCount = Number(db.prepare('SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?').get(userId).count);
if (sessionCount !== 5) throw Error(`session cap failed: expected 5, got ${sessionCount}`);
const tokenHash = (token) => crypto.createHash('sha256').update(token).digest('hex');
const retained = new Set(db.prepare('SELECT token_hash FROM sessions WHERE user_id = ?').all(userId).map(row => row.token_hash));
const evictedCount = capTokens.filter(token => !retained.has(tokenHash(token))).length;
if (evictedCount !== 1) throw Error(`session cap evicted ${evictedCount} tokens; expected exactly 1`);
const newestHash = db.prepare('SELECT token_hash FROM sessions WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 1').get(userId).token_hash;
if (!retained.has(newestHash)) throw Error('newest retained session lookup failed');
const newestToken = capTokens.find(token => tokenHash(token) === newestHash);
if (!newestToken) throw Error('newest retained session was not one of the cap logins');
x = await req('GET', '/api/auth/me', undefined, { Authorization: `Bearer ${newestToken}` });
if (x.response.status !== 200) throw Error('newest retained session was not usable');

// v191: users can inspect active sessions and revoke a different session without exposing token material.
x = await req('GET', '/api/auth/sessions', undefined, { Authorization: `Bearer ${newestToken}` });
if (x.response.status !== 200 || !Array.isArray(x.json?.sessions) || x.json.sessions.length !== 5) throw Error('session listing failed');
if (!x.json.sessions.some(s => s.current === true) || x.json.sessions.some(s => Object.prototype.hasOwnProperty.call(s, 'token_hash'))) throw Error('session listing current/token exposure failed');
const currentSessionHash = crypto.createHash('sha256').update(newestToken).digest('hex');
const currentSession = db.prepare('SELECT id FROM sessions WHERE token_hash = ?').get(currentSessionHash);
if (!currentSession?.id) throw Error('current session lookup failed');
const revokeTarget = x.json.sessions.find(s => s.id !== currentSession.id);
if (!revokeTarget) throw Error('no revocable session found');
x = await req('POST', `/api/auth/sessions/${encodeURIComponent(revokeTarget.id)}`, undefined, { Authorization: `Bearer ${newestToken}` });
if (x.response.status !== 200 || x.json?.revoked_session_id !== revokeTarget.id) throw Error('session revoke failed');
const revokedToken = capTokens.find((token) => { const h = crypto.createHash('sha256').update(token).digest('hex'); const row = db.prepare('SELECT id FROM sessions WHERE token_hash = ?').get(h); return !row; });
if (!revokedToken) throw Error('revoked session token mapping failed');
x = await req('GET', '/api/auth/me', undefined, { Authorization: `Bearer ${revokedToken}` });
if (x.response.status !== 401) throw Error('revoked session remained active');
x = await req('POST', `/api/auth/sessions/${encodeURIComponent(currentSession.id)}`, undefined, { Authorization: `Bearer ${newestToken}` });
if (x.response.status !== 400 || x.json?.error !== 'cannot_revoke_current_session') throw Error('current session revoke guard failed');
const sessionRevokeAudit = db.prepare("SELECT event, request_id, session_id FROM security_audit WHERE user_id = ? AND event = 'session_revoked' ORDER BY created_at DESC, id DESC LIMIT 1").get(userId);
if (sessionRevokeAudit?.event !== 'session_revoked' || !sessionRevokeAudit.request_id) throw Error('session revoke audit missing');

// v191: revoke every other active session while preserving the authenticated current session.
db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
const otherTokens = [];
for (let i = 0; i < 3; i++) {
  x = await req('POST', '/api/auth/login', { phone: '+994501234567', password: 'password123' }, { 'X-Forwarded-For': `198.51.100.${40 + i}` });
  if (x.response.status !== 200 || !x.json?.token) throw Error(`logout-others login ${i + 1} failed: ${x.response.status}`);
  otherTokens.push(x.json.token);
}
const keepToken = otherTokens[0];
const otherTokenHashes = otherTokens.slice(1).map(tokenHash);
x = await req('POST', '/api/auth/logout-others', undefined, { Authorization: `Bearer ${keepToken}` });
if (x.response.status !== 200 || Number(x.json?.revoked_sessions) !== 2 || x.json?.current_session_preserved !== true) throw Error('logout-others did not revoke only other sessions');
x = await req('GET', '/api/auth/me', undefined, { Authorization: `Bearer ${keepToken}` });
if (x.response.status !== 200) throw Error('logout-others revoked current session');
for (const t of otherTokens.slice(1)) {
  x = await req('GET', '/api/auth/me', undefined, { Authorization: `Bearer ${t}` });
  if (x.response.status !== 401) throw Error('logout-others left another session active');
}
const logoutOthersAudit = db.prepare("SELECT event, request_id, session_id FROM security_audit WHERE user_id = ? AND event = 'logout_others' ORDER BY created_at DESC, id DESC LIMIT 1").get(userId);
const keptSession = db.prepare('SELECT id FROM sessions WHERE token_hash = ?').get(tokenHash(keepToken));
if (logoutOthersAudit?.event !== 'logout_others' || !logoutOthersAudit.request_id || logoutOthersAudit.session_id !== keptSession?.id) throw Error('logout-others audit binding missing');



// v179: database-level session cap is enforced even for direct inserts.
db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
const directSessionIds = [];
for (let i = 0; i < 7; i++) {
  const id = `db-cap-${i}`;
  directSessionIds.push(id);
  db.prepare("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now', '+30 days'))").run(id, userId, `db-cap-token-${i}`);
}
const directSessionCount = Number(db.prepare('SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?').get(userId).count);
if (directSessionCount !== 5) throw Error(`database session cap failed: expected 5, got ${directSessionCount}`);
const newestDirect = db.prepare('SELECT id FROM sessions WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 1').get(userId)?.id;
if (!directSessionIds.includes(newestDirect)) throw Error('database session cap did not retain newest direct session');

console.log('v206 D1 + scheduled security-audit retention + security-event filters + bounded rate limiter + admin order list + HMAC-signed product cursor + order cursor pagination + order review + order-item lifecycle + security + idempotency integration tests: PASS');
