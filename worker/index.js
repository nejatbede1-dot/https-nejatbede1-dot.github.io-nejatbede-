const allowedOrigins = (env) => String(env?.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);

const apiHeaders = (extra = {}) => ({
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  ...extra
});

const validRequestId = (value) => /^[A-Za-z0-9._:-]{1,100}$/.test(String(value || ''));
const makeRequestId = () => crypto.randomUUID();

const etagForJson = async (body) => `"${await sha256Hex(JSON.stringify(body))}"`;

const ifNoneMatchMatches = (request, etag) => {
  const value = request.headers.get('If-None-Match');
  if (!value) return false;
  if (value.trim() === '*') return true;
  return value.split(',').some((candidate) => candidate.trim().replace(/^W\//i, '') === etag);
};

const productCursorExpiry = () => (Math.floor(Date.now() / 900000) + 1) * 900;

// Public catalog responses are an explicit allow-list. Never pass raw D1 product rows
// to the public API, even if a future query/mock adds internal columns such as
// seller_user_id. This keeps the API boundary safe by construction.
const publicProductView = (product) => ({
  id: product?.id,
  name: product?.name,
  sale_price: product?.sale_price,
  remaining: product?.remaining,
  status: product?.status,
  created_at: product?.created_at,
  ...(product?.shop_name !== undefined ? { shop_name: product.shop_name } : {})
});


const jsonResponse = (body, status = 200, extra = {}) => Response.json(body, {
  status,
  headers: apiHeaders(extra)
});

const corsHeaders = (request, env, extra = {}) => {
  const origin = request.headers.get('Origin');
  const configured = allowedOrigins(env);
  const allowOrigin = origin && (configured.includes('*') || configured.includes(origin)) ? (configured.includes('*') ? '*' : origin) : '';
  return apiHeaders({
    ...(allowOrigin ? { 'Access-Control-Allow-Origin': allowOrigin, 'Vary': 'Origin' } : {}),
    ...extra
  });
};

const corsPreflight = (request, env, methods, headers = 'Content-Type', requestId = '') => {
  const origin = request.headers.get('Origin');
  const configured = allowedOrigins(env);
  const allowed = !origin || configured.includes('*') || configured.includes(origin);
  if (!allowed) return new Response(null, { status: 403, headers: apiHeaders({ 'X-Content-Type-Options': 'nosniff' }) });
  const extra = {
    'Access-Control-Allow-Methods': methods,
    'Access-Control-Allow-Headers': headers,
    'Access-Control-Max-Age': '600',
    ...(requestId ? { 'X-Request-ID': requestId } : {})
  };
  if (origin) { extra['Access-Control-Allow-Origin'] = configured.includes('*') ? '*' : origin; extra['Vary'] = 'Origin'; }
  return new Response(null, { status: 204, headers: corsHeaders(request, env, extra) });
};

const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
const randomHex = (length = 32) => {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
};

const hashPassword = async (password, saltHex = randomHex(16)) => {
  const encoder = new TextEncoder();
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map((x) => parseInt(x, 16)));
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 120000, hash: 'SHA-256' }, key, 256);
  return `pbkdf2_sha256$120000$${saltHex}$${bytesToHex(new Uint8Array(bits))}`;
};

const verifyPassword = async (password, stored) => {
  const parts = String(stored || '').split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2_sha256') return false;
  const candidate = await hashPassword(password, parts[2]);
  return candidate === stored;
};

const parseCookie = (request, name) => {
  const raw = request.headers.get('Cookie') || '';
  for (const part of raw.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return rest.join('=').trim();
  }
  return '';
};

const SESSION_COOKIE = '__Host-NEJAT_SESSION';
const authTokenFromRequest = (request) => {
  const cookieToken = parseCookie(request, SESSION_COOKIE);
  if (/^[0-9a-f]{64}$/i.test(cookieToken)) return cookieToken;
  const value = request.headers.get('Authorization') || '';
  if (!/^Bearer\s+/i.test(value)) return '';
  const token = value.replace(/^Bearer\s+/i, '').trim();
  return /^[0-9a-f]{64}$/i.test(token) ? token : '';
};

const sessionCookie = (token) => `${SESSION_COOKIE}=${token}; Max-Age=2592000; Path=/; Secure; HttpOnly; SameSite=Lax`;
const clearSessionCookie = () => `${SESSION_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`;

const cleanupExpiredSessions = async (env) => {
  if (!env.DB || typeof env.DB.prepare !== 'function') return;
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at <= CURRENT_TIMESTAMP').run();
};

const getSessionUser = async (request, env) => {
  const token = authTokenFromRequest(request);
  if (!token || !env.DB || typeof env.DB.prepare !== 'function') return null;
  const row = await env.DB.prepare(
    `SELECT u.id, u.phone, u.role, u.status
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP AND u.status = 'active'
     LIMIT 1`
  ).bind(await hashToken(token)).first();
  return row || null;
};

const sha256Hex = async (value) => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return bytesToHex(new Uint8Array(digest));
};

const hashToken = async (token) => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return bytesToHex(new Uint8Array(digest));
};

const SECURITY_AUDIT_RETENTION_DAYS_DEFAULT = 90;

const normalizeSecurityAuditTime = (value) => {
  const raw = String(value || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(raw)) return null;
  const parsed = Date.parse(raw);
  if (!Number.isFinite(parsed)) return null;
  const d = new Date(parsed);
  return d.toISOString().slice(0, 19).replace('T', ' ');
};

const securityAuditRetentionDays = (env) => {
  const raw = Number(env?.SECURITY_AUDIT_RETENTION_DAYS);
  return Number.isInteger(raw) && raw >= 30 && raw <= 365 ? raw : SECURITY_AUDIT_RETENTION_DAYS_DEFAULT;
};

const cleanupSecurityAudit = async (env) => {
  if (!env.DB || typeof env.DB.prepare !== 'function') throw new Error('database_not_configured');
  const days = securityAuditRetentionDays(env);
  return env.DB.prepare(
    `DELETE FROM security_audit WHERE created_at < datetime('now', '-' || ? || ' days')`
  ).bind(days).run();
};

const auditSecurityEvent = async (env, { userId, event, requestId }) => {
  if (!env.DB || typeof env.DB.prepare !== 'function') throw new Error('database_not_configured');
  return env.DB.prepare(
    `INSERT INTO security_audit (id, user_id, event, request_id) VALUES (?, ?, ?, ?)`
  ).bind(crypto.randomUUID(), userId, event, requestId).run();
};

const base64urlEncode = (value) => {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

const base64urlDecode = (value) => {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return new Uint8Array([...binary].map(ch => ch.charCodeAt(0)));
};

const makeOrderCursor = async (token, payload) => {
  const body = JSON.stringify(payload);
  const sessionBinding = await hashToken(token);
  const signature = await sha256Hex(`${sessionBinding}.${body}`);
  return `${base64urlEncode(body)}.${signature}`;
};

const parseOrderCursor = async (token, cursor) => {
  try {
    if (!/^[A-Za-z0-9_-]+\.[0-9a-f]{64}$/i.test(cursor) || cursor.length > 1024) return null;
    const dot = cursor.lastIndexOf('.');
    const encoded = cursor.slice(0, dot);
    const signature = cursor.slice(dot + 1).toLowerCase();
    const body = new TextDecoder().decode(base64urlDecode(encoded));
    const expected = await sha256Hex(`${await hashToken(token)}.${body}`);
    if (signature !== expected) return null;
    const payload = JSON.parse(body);
    if (!payload || payload.v !== 1 || typeof payload.user_id !== 'string' || typeof payload.created_at !== 'string' || typeof payload.id !== 'string') return null;
    if (!Number.isInteger(payload.limit) || payload.limit < 1 || payload.limit > 50) return null;
    if (!Number.isInteger(payload.exp) || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
};

const productCursorSecret = (env) => String(env?.CURSOR_SECRET || '');
const configurationError = (env) => {
  if (String(env?.ENVIRONMENT || '').trim().toLowerCase() !== 'production') return null;
  const secret = productCursorSecret(env);
  if (secret.length < 32) return 'cursor_secret_not_configured';
  if (allowedOrigins(env).length === 0) return 'allowed_origins_not_configured';
  return null;
};
const hmacSha256 = async (secret, value) => {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
  return { key, data: new TextEncoder().encode(value) };
};
const hmacSha256Hex = async (secret, value) => {
  const { key, data } = await hmacSha256(secret, value);
  const signature = await crypto.subtle.sign('HMAC', key, data);
  return bytesToHex(new Uint8Array(signature));
};
const makeProductCursor = async (env, payload) => {
  const secret = productCursorSecret(env);
  if (!secret) return null;
  const body = JSON.stringify(payload);
  const signature = await hmacSha256Hex(secret, body);
  return `${base64urlEncode(body)}.${signature}`;
};
const makeAuditCursor = async (env, payload) => {
  const secret = productCursorSecret(env);
  if (!secret) return null;
  const body = JSON.stringify(payload);
  const signature = await hmacSha256Hex(secret, body);
  return `${base64urlEncode(body)}.${signature}`;
};
const makeSecurityAuditCursor = async (env, payload) => {
  const secret = productCursorSecret(env);
  if (!secret) return null;
  const body = JSON.stringify(payload);
  const signature = await hmacSha256Hex(secret, body);
  return `${base64urlEncode(body)}.${signature}`;
};
const parseSecurityAuditCursor = async (env, cursor) => {
  try {
    const secret = productCursorSecret(env);
    if (!secret || !/^[A-Za-z0-9_-]+\.[0-9a-f]{64}$/i.test(cursor) || cursor.length > 1024) return null;
    const dot = cursor.lastIndexOf('.');
    const encoded = cursor.slice(0, dot);
    const signatureHex = cursor.slice(dot + 1);
    const body = new TextDecoder().decode(base64urlDecode(encoded));
    const { key, data } = await hmacSha256(secret, body);
    const signatureBytes = new Uint8Array(signatureHex.match(/../g).map(x => parseInt(x, 16)));
    if (!await crypto.subtle.verify('HMAC', key, signatureBytes, data)) return null;
    const payload = JSON.parse(body);
    if (!payload || payload.v !== 1 || payload.scope !== 'security-audit' || typeof payload.user_id !== 'string' || typeof payload.created_at !== 'string' || typeof payload.id !== 'string') return null;
    if (!Number.isInteger(payload.limit) || payload.limit < 1 || payload.limit > 50) return null;
    if (!Number.isInteger(payload.exp) || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
};
const makeAdminOrdersCursor = async (env, payload) => {
  const secret = productCursorSecret(env);
  if (!secret) return null;
  const body = JSON.stringify(payload);
  const signature = await hmacSha256Hex(secret, body);
  return `${base64urlEncode(body)}.${signature}`;
};
const parseAdminOrdersCursor = async (env, cursor) => {
  try {
    const secret = productCursorSecret(env);
    if (!secret || !/^[A-Za-z0-9_-]+\.[0-9a-f]{64}$/i.test(cursor) || cursor.length > 1024) return null;
    const dot = cursor.lastIndexOf('.');
    const encoded = cursor.slice(0, dot);
    const signatureHex = cursor.slice(dot + 1);
    const body = new TextDecoder().decode(base64urlDecode(encoded));
    const { key, data } = await hmacSha256(secret, body);
    const signatureBytes = new Uint8Array(signatureHex.match(/../g).map(x => parseInt(x, 16)));
    const validSignature = await crypto.subtle.verify('HMAC', key, signatureBytes, data);
    if (!validSignature) return null;
    const payload = JSON.parse(body);
    if (!payload || payload.v !== 1 || payload.scope !== 'admin-orders' || typeof payload.status !== 'string' || typeof payload.created_at !== 'string' || typeof payload.id !== 'string') return null;
    if (!Number.isInteger(payload.limit) || payload.limit < 1 || payload.limit > 50) return null;
    if (!Number.isInteger(payload.exp) || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
};

const parseAuditCursor = async (env, cursor) => {
  try {
    const secret = productCursorSecret(env);
    if (!secret || !/^[A-Za-z0-9_-]+\.[0-9a-f]{64}$/i.test(cursor) || cursor.length > 1024) return null;
    const dot = cursor.lastIndexOf('.');
    const encoded = cursor.slice(0, dot);
    const signatureHex = cursor.slice(dot + 1);
    const body = new TextDecoder().decode(base64urlDecode(encoded));
    const { key, data } = await hmacSha256(secret, body);
    const signatureBytes = new Uint8Array(signatureHex.match(/../g).map(x => parseInt(x, 16)));
    const validSignature = await crypto.subtle.verify('HMAC', key, signatureBytes, data);
    if (!validSignature) return null;
    const payload = JSON.parse(body);
    if (!payload || payload.v !== 1 || payload.scope !== 'order-status-history' || typeof payload.admin_user_id !== 'string' || typeof payload.order_id !== 'string' || typeof payload.created_at !== 'string' || !Number.isInteger(payload.id)) return null;
    if (!Number.isInteger(payload.limit) || payload.limit < 1 || payload.limit > 50) return null;
    if (!Number.isInteger(payload.exp) || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
};

const parsePaymentAuditCursor = async (env, cursor) => {
  try {
    const secret = productCursorSecret(env);
    if (!secret || !/^[A-Za-z0-9_-]+\.[0-9a-f]{64}$/i.test(cursor) || cursor.length > 1024) return null;
    const dot = cursor.lastIndexOf('.');
    const encoded = cursor.slice(0, dot);
    const signatureHex = cursor.slice(dot + 1);
    const body = new TextDecoder().decode(base64urlDecode(encoded));
    const { key, data } = await hmacSha256(secret, body);
    const signatureBytes = new Uint8Array(signatureHex.match(/../g).map(x => parseInt(x, 16)));
    if (!await crypto.subtle.verify('HMAC', key, signatureBytes, data)) return null;
    const payload = JSON.parse(body);
    if (!payload || payload.v !== 1 || payload.scope !== 'payment-status-history' || typeof payload.admin_user_id !== 'string' || typeof payload.order_id !== 'string' || typeof payload.payment_id !== 'string' || typeof payload.created_at !== 'string' || !Number.isInteger(payload.id)) return null;
    if (!Number.isInteger(payload.limit) || payload.limit < 1 || payload.limit > 50) return null;
    if (!Number.isInteger(payload.exp) || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
};

const parseProductCursor = async (env, cursor) => {
  try {
    const secret = productCursorSecret(env);
    if (!secret || !/^[A-Za-z0-9_-]+\.[0-9a-f]{64}$/i.test(cursor) || cursor.length > 1024) return null;
    const dot = cursor.lastIndexOf('.');
    const encoded = cursor.slice(0, dot);
    const signatureHex = cursor.slice(dot + 1);
    const body = new TextDecoder().decode(base64urlDecode(encoded));
    const { key, data } = await hmacSha256(secret, body);
    const signatureBytes = new Uint8Array(signatureHex.match(/../g).map(x => parseInt(x, 16)));
    const validSignature = await crypto.subtle.verify('HMAC', key, signatureBytes, data);
    if (!validSignature) return null;
    const payload = JSON.parse(body);
    if (!payload || payload.v !== 3 || payload.scope !== 'active-in-stock' || typeof payload.created_at !== 'string' || typeof payload.id !== 'string') return null;
    if (!Number.isInteger(payload.limit) || payload.limit < 1 || payload.limit > 100) return null;
    if (!Number.isInteger(payload.exp) || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
};

const validPhone = (phone) => /^\+?[0-9]{8,15}$/.test(phone);

// Lightweight per-isolate rate limiter. This is a first defense only; production
// should additionally use Cloudflare WAF/Rate Limiting for durable edge enforcement.
const rateBuckets = new Map();
const RATE_WINDOW_MS = 60_000;
const MAX_RATE_BUCKETS = 10_000;
const RATE_LIMITS = { register: 5, login: 10, changePassword: 5, securityRead: 60, orderWrite: 20, adminOrderWrite: 20, adminPaymentWrite: 20, adminDbStatsRead: 30, adminOrderListRead: 60, adminOrderAuditRead: 60, adminPaymentAuditRead: 60, sessionRead: 60, sessionRevoke: 20, logout: 20, logoutAll: 5, logoutOthers: 5 };
// Behind Cloudflare, CF-Connecting-IP is the authoritative client address.
// X-Forwarded-For remains only as a local/test fallback.
const clientKey = (request) => request.headers.get('CF-Connecting-IP') || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
const rateLimit = (request, bucket, limit, requestId = '') => {
  const now = Date.now();
  // Remove expired buckets so a long-lived isolate cannot retain stale IP keys forever.
  for (const [key, value] of rateBuckets) {
    if (now - value.start >= RATE_WINDOW_MS) rateBuckets.delete(key);
  }
  const key = `${bucket}:${clientKey(request)}`;
  if (!rateBuckets.has(key) && rateBuckets.size >= MAX_RATE_BUCKETS) {
    // Keep the in-isolate guard bounded. Durable edge rate limiting belongs in Cloudflare WAF/Rate Limiting.
    const oldest = rateBuckets.keys().next().value;
    if (oldest !== undefined) rateBuckets.delete(oldest);
  }
  const current = rateBuckets.get(key);
  if (!current || now - current.start >= RATE_WINDOW_MS) {
    rateBuckets.set(key, { start: now, count: 1 });
    return null;
  }
  current.count += 1;
  if (current.count > limit) {
    const retryAfter = Math.max(1, Math.ceil((RATE_WINDOW_MS - (now - current.start)) / 1000));
    return jsonResponse({ ok: false, error: 'rate_limited' }, 429, { 'Retry-After': String(retryAfter), ...(requestId ? { 'X-Request-ID': requestId } : {}) });
  }
  return null;
};

const utf8ByteLength = (value) => new TextEncoder().encode(String(value ?? '')).byteLength;

const jsonBody = async (request, maxBytes = 16 * 1024) => {
  const contentLengthHeader = request.headers.get('Content-Length');
  if (contentLengthHeader !== null && (!/^\d+$/.test(contentLengthHeader.trim()) || Number(contentLengthHeader) > maxBytes)) {
    throw Object.assign(new Error('body_too_large'), { code: 'body_too_large' });
  }
  const raw = await request.text();
  if (!raw) throw Object.assign(new Error('invalid_json'), { code: 'invalid_json' });
  if (utf8ByteLength(raw) > maxBytes) throw Object.assign(new Error('body_too_large'), { code: 'body_too_large' });
  let parsed;
  try { parsed = JSON.parse(raw); } catch { throw Object.assign(new Error('invalid_json'), { code: 'invalid_json' }); }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw Object.assign(new Error('invalid_json'), { code: 'invalid_json' });
  }
  return parsed;
};

const parseBody = async (request, maxBytes) => {
  try { return { body: await jsonBody(request, maxBytes) }; }
  catch (error) { return { error }; }
};

const requireJsonContentType = (request) => {
  const type = request.headers.get('Content-Type') || '';
  return type.toLowerCase().startsWith('application/json');
};

export default {
  async scheduled(event, env) {
    const startedAt = Date.now();
    try {
      const result = await cleanupSecurityAudit(env);
      const deleted = Number(result?.meta?.changes ?? 0);
      console.log(JSON.stringify({ event: 'security_audit_cleanup', ok: true, deleted, duration_ms: Date.now() - startedAt }));
    } catch (error) {
      const errorCode = error && typeof error === 'object' && typeof error.code === 'string' && /^[a-z0-9_]{1,64}$/.test(error.code) ? error.code : 'cleanup_failed';
      console.error(JSON.stringify({ event: 'security_audit_cleanup', ok: false, error: errorCode, duration_ms: Date.now() - startedAt }));
      throw error;
    }
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    const configError = configurationError(env);
    const suppliedRequestId = request.headers.get('X-Request-ID') || '';
    const requestId = validRequestId(suppliedRequestId) ? suppliedRequestId : makeRequestId();
    const respond = (body, status = 200, extra = {}) => {
      const headers = corsHeaders(request, env, { 'X-Request-ID': requestId, ...extra });
      return Response.json(body, { status, headers });
    };
    const methodNotAllowed = (allow) => respond({ ok: false, error: 'method_not_allowed' }, 405, { Allow: allow });
    if (configError && !((url.pathname === '/api/health' || url.pathname === '/api/health/config' || url.pathname === '/api/db/stats') && (request.method === 'GET' || request.method === 'HEAD' || request.method === 'OPTIONS'))) {
      return respond({ ok: false, error: 'configuration_not_ready' }, 503);
    }



    if (url.pathname.startsWith('/api/auth/') && request.method === 'OPTIONS') {
      return corsPreflight(request, env, 'GET, POST, OPTIONS', 'Content-Type, Authorization, Idempotency-Key', requestId);
    }

    if (url.pathname === '/api/auth/register' && request.method === 'POST') {
      const limited = rateLimit(request, 'register', RATE_LIMITS.register, requestId);
      if (limited) return limited;
      if (!requireJsonContentType(request)) return respond({ ok: false, error: 'content_type_required' }, 415);
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      let body;
      const parsed = await parseBody(request, 8 * 1024);
      if (parsed.error) return respond({ ok: false, error: parsed.error.code || 'invalid_json' }, parsed.error.code === 'body_too_large' ? 413 : 400);
      body = parsed.body;
      const phone = String(body?.phone || '').trim();
      const password = String(body?.password || '');
      if (utf8ByteLength(phone) > 32 || !validPhone(phone)) return respond({ ok: false, error: 'invalid_phone' }, 400);
      if (utf8ByteLength(password) > 128 || password.length < 8 || password.length > 128) return respond({ ok: false, error: 'invalid_password' }, 400);
      try {
        const existing = await env.DB.prepare('SELECT id FROM users WHERE phone = ? LIMIT 1').bind(phone).first();
        if (existing) return respond({ ok: false, error: 'phone_already_registered' }, 409);
        const userId = crypto.randomUUID();
        const passwordHash = await hashPassword(password);
        await env.DB.prepare(
          `INSERT INTO users (id, phone, role, password_hash, status) VALUES (?, ?, 'customer', ?, 'active')`
        ).bind(userId, phone, passwordHash).run();
        return respond({ ok: true, user: { id: userId, phone, role: 'customer' } }, 201);
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      const limited = rateLimit(request, 'login', RATE_LIMITS.login, requestId);
      if (limited) return limited;
      if (!requireJsonContentType(request)) return respond({ ok: false, error: 'content_type_required' }, 415);
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      let body;
      const parsed = await parseBody(request, 8 * 1024);
      if (parsed.error) return respond({ ok: false, error: parsed.error.code || 'invalid_json' }, parsed.error.code === 'body_too_large' ? 413 : 400);
      body = parsed.body;
      const phone = String(body?.phone || '').trim();
      const password = String(body?.password || '');
      if (utf8ByteLength(phone) > 32 || !validPhone(phone) || utf8ByteLength(password) > 128 || !password) return respond({ ok: false, error: 'invalid_credentials' }, 401);
      try {
        const user = await env.DB.prepare(
          `SELECT id, phone, role, password_hash, status FROM users WHERE phone = ? LIMIT 1`
        ).bind(phone).first();
        if (!user || user.status !== 'active' || !(await verifyPassword(password, user.password_hash))) {
          return respond({ ok: false, error: 'invalid_credentials' }, 401);
        }
        await cleanupExpiredSessions(env);
        const token = randomHex(32);
        const tokenHash = await hashToken(token);
        const sessionId = crypto.randomUUID();
        await env.DB.batch([
          env.DB.prepare(
            `INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now', '+30 days'))`
          ).bind(sessionId, user.id, tokenHash),
          env.DB.prepare(
            `INSERT INTO security_audit (id, user_id, event, request_id, session_id) VALUES (?, ?, ?, ?, ?)`
          ).bind(crypto.randomUUID(), user.id, 'login_success', requestId, sessionId)
        ]);
        // Keep a bounded number of active sessions per account while allowing
        // multiple devices. The newest five sessions are retained.
        await env.DB.prepare(
          `DELETE FROM sessions
           WHERE user_id = ?
             AND id NOT IN (
               SELECT id FROM sessions WHERE user_id = ?
               ORDER BY created_at DESC, id DESC LIMIT 5
             )`
        ).bind(user.id, user.id).run();
        return respond({ ok: true, token, expires_in: 2592000, user: { id: user.id, phone: user.phone, role: user.role } }, 200, { 'Set-Cookie': sessionCookie(token) });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname === '/api/auth/change-password' && request.method === 'POST') {
      const limited = rateLimit(request, 'changePassword', RATE_LIMITS.changePassword, requestId);
      if (limited) return limited;
      if (!requireJsonContentType(request)) return respond({ ok: false, error: 'content_type_required' }, 415);
      if (!env.DB || typeof env.DB.prepare !== 'function' || typeof env.DB.batch !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      const token = authTokenFromRequest(request);
      if (!token) return respond({ ok: false, error: 'unauthorized' }, 401);
      const parsed = await parseBody(request, 8 * 1024);
      if (parsed.error) return respond({ ok: false, error: parsed.error.code || 'invalid_json' }, parsed.error.code === 'body_too_large' ? 413 : 400);
      const currentPassword = String(parsed.body?.current_password || '');
      const newPassword = String(parsed.body?.new_password || '');
      if (utf8ByteLength(currentPassword) > 128 || utf8ByteLength(newPassword) > 128 || newPassword.length < 8 || newPassword.length > 128 || !currentPassword) {
        return respond({ ok: false, error: 'invalid_password' }, 400);
      }
      try {
        const user = await getSessionUser(request, env);
        if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
        const account = await env.DB.prepare("SELECT password_hash FROM users WHERE id = ? AND status = 'active' LIMIT 1").bind(user.id).first();
        if (!account || !(await verifyPassword(currentPassword, account.password_hash))) return respond({ ok: false, error: 'invalid_current_password' }, 401);
        if (await verifyPassword(newPassword, account.password_hash)) return respond({ ok: false, error: 'password_reuse' }, 400);
        const newPasswordHash = await hashPassword(newPassword);
        await env.DB.batch([
          env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ? AND status = 'active'").bind(newPasswordHash, user.id),
          env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
          env.DB.prepare('INSERT INTO security_audit (id, user_id, event, request_id) VALUES (?, ?, ?, ?)').bind(crypto.randomUUID(), user.id, 'password_changed', requestId)
        ]);
        return respond({ ok: true, sessions_revoked: true, reauthenticate: true }, 200, { 'Set-Cookie': clearSessionCookie() });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname === '/api/auth/me' && request.method === 'GET') {
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      try {
        const user = await getSessionUser(request, env);
        if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
        return respond({ ok: true, user });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname === '/api/auth/logout' && request.method === 'POST') {
      const limited = rateLimit(request, 'logout', RATE_LIMITS.logout, requestId);
      if (limited) return limited;
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      const token = authTokenFromRequest(request);
      if (!token) return respond({ ok: false, error: 'unauthorized' }, 401);
      try {
        const user = await getSessionUser(request, env);
        if (!user) return respond({ ok: true });
        const tokenHash = await hashToken(token);
        const currentSession = await env.DB.prepare('SELECT id FROM sessions WHERE token_hash = ? AND user_id = ? LIMIT 1').bind(tokenHash, user.id).first();
        await env.DB.batch([
          env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash),
          env.DB.prepare('INSERT INTO security_audit (id, user_id, event, request_id, session_id) VALUES (?, ?, ?, ?, ?)').bind(crypto.randomUUID(), user.id, 'logout', requestId, currentSession?.id || null)
        ]);
        return respond({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie() });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname === '/api/auth/logout-all' && request.method === 'POST') {
      const limited = rateLimit(request, 'logoutAll', RATE_LIMITS.logoutAll, requestId);
      if (limited) return limited;
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      const token = authTokenFromRequest(request);
      if (!token) return respond({ ok: false, error: 'unauthorized' }, 401);
      try {
        const user = await getSessionUser(request, env);
        if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
        const activeSessions = await env.DB.prepare('SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?').bind(user.id).first();
        const revokedSessions = Number(activeSessions?.count || 0);
        await env.DB.batch([
          env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
          env.DB.prepare('INSERT INTO security_audit (id, user_id, event, request_id) VALUES (?, ?, ?, ?)').bind(crypto.randomUUID(), user.id, 'logout_all', requestId)
        ]);
        return respond({ ok: true, revoked_sessions: revokedSessions }, 200, { 'Set-Cookie': clearSessionCookie() });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname === '/api/auth/logout-others' && request.method === 'POST') {
      const limited = rateLimit(request, 'logoutOthers', RATE_LIMITS.logoutOthers, requestId);
      if (limited) return limited;
      if (!env.DB || typeof env.DB.prepare !== 'function' || typeof env.DB.batch !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      const token = authTokenFromRequest(request);
      if (!token) return respond({ ok: false, error: 'unauthorized' }, 401);
      try {
        const user = await getSessionUser(request, env);
        if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
        const tokenHash = await hashToken(token);
        const currentSession = await env.DB.prepare('SELECT id FROM sessions WHERE token_hash = ? AND user_id = ? AND expires_at > CURRENT_TIMESTAMP LIMIT 1').bind(tokenHash, user.id).first();
        if (!currentSession?.id) return respond({ ok: false, error: 'unauthorized' }, 401);
        const others = await env.DB.prepare('SELECT COUNT(*) AS count FROM sessions WHERE user_id = ? AND id <> ? AND expires_at > CURRENT_TIMESTAMP').bind(user.id, currentSession.id).first();
        const revokedSessions = Number(others?.count || 0);
        await env.DB.batch([
          env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND id <> ?').bind(user.id, currentSession.id),
          env.DB.prepare('INSERT INTO security_audit (id, user_id, event, request_id, session_id) VALUES (?, ?, ?, ?, ?)').bind(crypto.randomUUID(), user.id, 'logout_others', requestId, currentSession.id)
        ]);
        return respond({ ok: true, revoked_sessions: revokedSessions, current_session_preserved: true });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname === '/api/auth/sessions' && request.method === 'GET') {
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      const user = await getSessionUser(request, env);
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      const limited = rateLimit(request, 'sessionRead', RATE_LIMITS.sessionRead, requestId);
      if (limited) return limited;
      try {
        const token = authTokenFromRequest(request);
        const tokenHash = await hashToken(token);
        const rows = await env.DB.prepare(
          `SELECT id, created_at, expires_at, CASE WHEN token_hash = ? THEN 1 ELSE 0 END AS current
           FROM sessions WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP
           ORDER BY created_at DESC, id DESC`
        ).bind(tokenHash, user.id).all();
        return respond({ ok: true, sessions: (rows?.results || []).map((row) => ({
          id: row.id, created_at: row.created_at, expires_at: row.expires_at, current: Number(row.current) === 1
        })) });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname.startsWith('/api/auth/sessions/') && request.method === 'POST') {
      if (!env.DB || typeof env.DB.prepare !== 'function' || typeof env.DB.batch !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      const user = await getSessionUser(request, env);
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      const limited = rateLimit(request, 'sessionRevoke', RATE_LIMITS.sessionRevoke, requestId);
      if (limited) return limited;
      const sessionId = decodeURIComponent(url.pathname.slice('/api/auth/sessions/'.length));
      if (!/^[0-9a-f-]{36}$/i.test(sessionId)) return respond({ ok: false, error: 'invalid_session_id' }, 400);
      try {
        const target = await env.DB.prepare(
          `SELECT id FROM sessions WHERE id = ? AND user_id = ? AND expires_at > CURRENT_TIMESTAMP LIMIT 1`
        ).bind(sessionId, user.id).first();
        if (!target) return respond({ ok: false, error: 'session_not_found' }, 404);
        const currentTokenHash = await hashToken(authTokenFromRequest(request));
        const current = await env.DB.prepare('SELECT id FROM sessions WHERE token_hash = ? AND user_id = ? LIMIT 1').bind(currentTokenHash, user.id).first();
        if (current?.id === sessionId) return respond({ ok: false, error: 'cannot_revoke_current_session' }, 400);
        await env.DB.batch([
          env.DB.prepare('DELETE FROM sessions WHERE id = ? AND user_id = ?').bind(sessionId, user.id),
          env.DB.prepare('INSERT INTO security_audit (id, user_id, event, request_id, session_id) VALUES (?, ?, ?, ?, ?)').bind(crypto.randomUUID(), user.id, 'session_revoked', requestId, sessionId)
        ]);
        return respond({ ok: true, revoked_session_id: sessionId });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname === '/api/auth/security-events' && request.method === 'GET') {
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      const user = await getSessionUser(request, env);
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      const limited = rateLimit(request, 'securityRead', RATE_LIMITS.securityRead, requestId);
      if (limited) return limited;
      const rawLimit = url.searchParams.get('limit');
      const rawOffset = url.searchParams.get('offset');
      const rawCursor = url.searchParams.get('cursor');
      const rawEvent = url.searchParams.get('event');
      const rawSessionId = url.searchParams.get('session_id');
      const rawSince = url.searchParams.get('since');
      const rawUntil = url.searchParams.get('until');
      const event = rawEvent === null || rawEvent === '' ? '' : String(rawEvent).trim();
      const sessionId = rawSessionId === null || rawSessionId === '' ? '' : String(rawSessionId).trim();
      const since = rawSince === null || rawSince === '' ? '' : normalizeSecurityAuditTime(rawSince);
      const until = rawUntil === null || rawUntil === '' ? '' : normalizeSecurityAuditTime(rawUntil);
      if ((rawSince !== null && rawSince !== '' && !since) || (rawUntil !== null && rawUntil !== '' && !until)) return respond({ ok: false, error: 'invalid_time_filter' }, 400);
      if (since && until && since > until) return respond({ ok: false, error: 'invalid_time_filter' }, 400);
      const securityAuditEvents = ['password_changed', 'logout_all', 'login_success', 'logout', 'session_revoked', 'logout_others'];
      const eventFilters = event ? [...new Set(event.split(',').map((value) => value.trim()).filter(Boolean))] : [];
      if (eventFilters.some((value) => !securityAuditEvents.includes(value))) return respond({ ok: false, error: 'invalid_event_filter' }, 400);
      if (event && eventFilters.length === 0) return respond({ ok: false, error: 'invalid_event_filter' }, 400);
      if (sessionId && !/^[0-9a-f-]{36}$/i.test(sessionId)) return respond({ ok: false, error: 'invalid_session_filter' }, 400);
      const normalizedEvent = eventFilters.join(',');
      const limit = rawLimit === null || rawLimit === '' ? 20 : Number(rawLimit);
      if (!Number.isInteger(limit) || limit < 1 || limit > 50) return respond({ ok: false, error: 'invalid_pagination' }, 400);
      if (rawCursor && rawOffset !== null) return respond({ ok: false, error: 'invalid_pagination' }, 400);
      try {
        let rows;
        let nextCursor = null;
        let nextOffset = null;
        if (rawCursor) {
          const cursor = await parseSecurityAuditCursor(env, rawCursor);
          if (!cursor || cursor.user_id !== user.id || cursor.limit !== limit || (cursor.event || '') !== normalizedEvent || (cursor.session_id || '') !== sessionId || (cursor.since || '') !== since || (cursor.until || '') !== until) return respond({ ok: false, error: 'invalid_cursor' }, 400);
          const eventClause = eventFilters.length ? `AND event IN (${eventFilters.map(() => '?').join(', ')})` : '';
          const sessionClause = sessionId ? 'AND session_id = ?' : '';
          const sinceClause = since ? 'AND created_at >= ?' : '';
          const untilClause = until ? 'AND created_at <= ?' : '';
          const binds = [user.id, ...(eventFilters.length ? eventFilters : []), ...(sessionId ? [sessionId] : []), ...(since ? [since] : []), ...(until ? [until] : []), cursor.created_at, cursor.created_at, cursor.id, limit + 1];
          rows = await env.DB.prepare(
            `SELECT id, event, request_id, session_id, created_at FROM security_audit
             WHERE user_id = ? ${eventClause} ${sessionClause} ${sinceClause} ${untilClause} AND (created_at < ? OR (created_at = ? AND id < ?))
             ORDER BY created_at DESC, id DESC LIMIT ?`
          ).bind(...binds).all();
          if ((rows.results || []).length > limit) {
            const page = rows.results.slice(0, limit);
            const last = page[page.length - 1];
            nextCursor = await makeSecurityAuditCursor(env, { v: 1, scope: 'security-audit', user_id: user.id, event: normalizedEvent, session_id: sessionId, since, until, created_at: last.created_at, id: last.id, limit, exp: Math.floor(Date.now() / 1000) + 900 });
            rows.results = page;
          }
        } else {
          const offset = rawOffset === null || rawOffset === '' ? 0 : Number(rawOffset);
          if (!Number.isInteger(offset) || offset < 0 || offset > 10000) return respond({ ok: false, error: 'invalid_pagination' }, 400);
          const eventClause = eventFilters.length ? `AND event IN (${eventFilters.map(() => '?').join(', ')})` : '';
          const sessionClause = sessionId ? 'AND session_id = ?' : '';
          const sinceClause = since ? 'AND created_at >= ?' : '';
          const untilClause = until ? 'AND created_at <= ?' : '';
          const binds = [user.id, ...(eventFilters.length ? eventFilters : []), ...(sessionId ? [sessionId] : []), ...(since ? [since] : []), ...(until ? [until] : []), limit + 1, offset];
          rows = await env.DB.prepare(
            `SELECT id, event, request_id, session_id, created_at FROM security_audit
             WHERE user_id = ? ${eventClause} ${sessionClause} ${sinceClause} ${untilClause} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
          ).bind(...binds).all();
          if ((rows.results || []).length > limit) {
            rows.results = rows.results.slice(0, limit);
            nextOffset = offset + limit;
          }
        }
        const items = rows.results || [];
        return respond({ ok: true, items, pagination: { limit, event: normalizedEvent || null, session_id: sessionId || null, since: since || null, until: until || null, has_more: Boolean(nextCursor || nextOffset !== null), cursor: rawCursor || null, next_cursor: nextCursor, offset: rawOffset === null || rawOffset === '' ? 0 : Number(rawOffset), next_offset: nextOffset } });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname === '/api/admin/orders' && request.method === 'OPTIONS') {
      return corsPreflight(request, env, 'GET, OPTIONS', 'Content-Type, Authorization', requestId);
    }

    if (url.pathname === '/api/admin/orders' && request.method === 'GET') {
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      let user;
      try { user = await getSessionUser(request, env); } catch { user = null; }
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      if (user.role !== 'admin') return respond({ ok: false, error: 'forbidden' }, 403);
      const limited = rateLimit(request, 'adminOrderListRead', RATE_LIMITS.adminOrderListRead, requestId);
      if (limited) return limited;
      const rawLimit = url.searchParams.get('limit');
      const rawOffset = url.searchParams.get('offset');
      const rawCursor = url.searchParams.get('cursor');
      const rawStatus = url.searchParams.get('status');
      const status = rawStatus === null || rawStatus === '' ? '' : String(rawStatus).trim();
      if (status && !['pending', 'approved', 'rejected', 'cancelled'].includes(status)) return respond({ ok: false, error: 'invalid_order_status_filter' }, 400);
      const limit = rawLimit === null || rawLimit === '' ? 20 : Number(rawLimit);
      if (!Number.isInteger(limit) || limit < 1 || limit > 50) return respond({ ok: false, error: 'invalid_pagination' }, 400);
      if (rawCursor && rawOffset !== null) return respond({ ok: false, error: 'invalid_pagination' }, 400);
      try {
        let rows;
        let nextCursor = null;
        if (rawCursor) {
          const cursor = await parseAdminOrdersCursor(env, rawCursor);
          if (!cursor || cursor.status !== status || cursor.limit !== limit) return respond({ ok: false, error: 'invalid_cursor' }, 400);
          const statusClause = status ? 'AND o.status = ?' : '';
          const binds = status
            ? [status, cursor.created_at, cursor.created_at, cursor.id, limit + 1]
            : [cursor.created_at, cursor.created_at, cursor.id, limit + 1];
          rows = await env.DB.prepare(
            `SELECT o.id, o.customer_user_id, u.phone AS customer_phone, o.total_amount, o.status, o.created_at
             FROM orders o JOIN users u ON u.id = o.customer_user_id
             WHERE 1=1 ${statusClause}
               AND (o.created_at < ? OR (o.created_at = ? AND o.id < ?))
             ORDER BY o.created_at DESC, o.id DESC LIMIT ?`
          ).bind(...binds).all();
        } else {
          const offset = rawOffset === null || rawOffset === '' ? 0 : Number(rawOffset);
          if (!Number.isInteger(offset) || offset < 0 || offset > 10000) return respond({ ok: false, error: 'invalid_pagination' }, 400);
          const statusClause = status ? 'WHERE o.status = ?' : '';
          const binds = status ? [status, limit + 1, offset] : [limit + 1, offset];
          rows = await env.DB.prepare(
            `SELECT o.id, o.customer_user_id, u.phone AS customer_phone, o.total_amount, o.status, o.created_at
             FROM orders o JOIN users u ON u.id = o.customer_user_id
             ${statusClause}
             ORDER BY o.created_at DESC, o.id DESC LIMIT ? OFFSET ?`
          ).bind(...binds).all();
        }
        const resultRows = rows.results || [];
        const hasMore = resultRows.length > limit;
        const orders = hasMore ? resultRows.slice(0, limit) : resultRows;
        if (hasMore) {
          const last = orders[orders.length - 1];
          nextCursor = await makeAdminOrdersCursor(env, { v: 1, scope: 'admin-orders', status, created_at: last.created_at, id: last.id, limit, exp: Math.floor(Date.now() / 1000) + 900 });
        }
        const offset = rawOffset === null || rawOffset === '' ? 0 : Number(rawOffset);
        return respond({ ok: true, orders, pagination: { limit, status: status || null, has_more: hasMore, cursor: rawCursor || null, next_cursor: nextCursor, offset: rawCursor ? null : offset, next_offset: rawCursor ? null : (hasMore ? offset + limit : null) } });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname.startsWith('/api/admin/orders/') && request.method === 'OPTIONS') {
      return corsPreflight(request, env, 'GET, POST, OPTIONS', 'Content-Type, Authorization', requestId);
    }

    if (url.pathname.startsWith('/api/admin/orders/') && request.method === 'GET' && url.pathname.endsWith('/status-history')) {
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      let user;
      try { user = await getSessionUser(request, env); } catch { user = null; }
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      if (user.role !== 'admin') return respond({ ok: false, error: 'forbidden' }, 403);
      const limited = rateLimit(request, 'adminOrderAuditRead', RATE_LIMITS.adminOrderAuditRead, requestId);
      if (limited) return limited;
      const orderId = url.pathname.slice('/api/admin/orders/'.length, -'/status-history'.length);
      if (!orderId || orderId.includes('/') || orderId.includes('%')) return respond({ ok: false, error: 'invalid_order_id' }, 400);
      try {
        const order = await env.DB.prepare('SELECT id FROM orders WHERE id = ? LIMIT 1').bind(orderId).first();
        if (!order) return respond({ ok: false, error: 'order_not_found' }, 404);
        const rawLimit = url.searchParams.get('limit');
        const rawOffset = url.searchParams.get('offset');
        const rawCursor = url.searchParams.get('cursor');
        const limit = rawLimit === null || rawLimit === '' ? 20 : Number(rawLimit);
        if (!Number.isInteger(limit) || limit < 1 || limit > 50) return respond({ ok: false, error: 'invalid_pagination' }, 400);
        if (rawCursor && rawOffset !== null) return respond({ ok: false, error: 'invalid_pagination' }, 400);
        let rows;
        let nextCursor = null;
        if (rawCursor) {
          const cursor = await parseAuditCursor(env, rawCursor);
          if (!cursor || cursor.order_id !== orderId || cursor.admin_user_id !== user.id || cursor.limit !== limit) return respond({ ok: false, error: 'invalid_cursor' }, 400);
          rows = await env.DB.prepare(
            `SELECT a.id, a.order_id, a.actor_user_id, u.phone AS actor_phone, a.from_status, a.to_status, a.created_at
             FROM order_status_audit a JOIN users u ON u.id = a.actor_user_id
             WHERE a.order_id = ? AND (a.created_at > ? OR (a.created_at = ? AND a.id > ?))
             ORDER BY a.created_at ASC, a.id ASC LIMIT ?`
          ).bind(orderId, cursor.created_at, cursor.created_at, cursor.id, limit + 1).all();
        } else {
          const offset = rawOffset === null || rawOffset === '' ? 0 : Number(rawOffset);
          if (!Number.isInteger(offset) || offset < 0 || offset > 10000) return respond({ ok: false, error: 'invalid_pagination' }, 400);
          rows = await env.DB.prepare(
            `SELECT a.id, a.order_id, a.actor_user_id, u.phone AS actor_phone, a.from_status, a.to_status, a.created_at
             FROM order_status_audit a JOIN users u ON u.id = a.actor_user_id
             WHERE a.order_id = ? ORDER BY a.created_at ASC, a.id ASC LIMIT ? OFFSET ?`
          ).bind(orderId, limit + 1, offset).all();
        }
        const resultRows = rows.results || [];
        const hasMore = resultRows.length > limit;
        const history = hasMore ? resultRows.slice(0, limit) : resultRows;
        if (hasMore) {
          const last = history[history.length - 1];
          nextCursor = await makeAuditCursor(env, { v: 1, scope: 'order-status-history', admin_user_id: user.id, order_id: orderId, created_at: last.created_at, id: Number(last.id), limit, exp: Math.floor(Date.now() / 1000) + 900 });
        }
        const offset = rawOffset === null || rawOffset === '' ? 0 : Number(rawOffset);
        return respond({ ok: true, history, pagination: { limit, has_more: hasMore, cursor: rawCursor || null, next_cursor: nextCursor, offset: rawCursor ? null : offset, next_offset: rawCursor ? null : (hasMore ? offset + limit : null) } });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname.startsWith('/api/admin/orders/') && request.method === 'POST' && url.pathname.endsWith('/status')) {
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      let user;
      try { user = await getSessionUser(request, env); } catch { user = null; }
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      if (user.role !== 'admin') return respond({ ok: false, error: 'forbidden' }, 403);
      const limited = rateLimit(request, 'adminOrderWrite', RATE_LIMITS.adminOrderWrite, requestId);
      if (limited) return limited;
      const orderId = url.pathname.slice('/api/admin/orders/'.length, -'/status'.length);
      if (!orderId || orderId.includes('/') || orderId.includes('%')) return respond({ ok: false, error: 'invalid_order_id' }, 400);
      if (!requireJsonContentType(request)) return respond({ ok: false, error: 'content_type_required' }, 415);
      const parsed = await parseBody(request, 8 * 1024);
      if (parsed.error) return respond({ ok: false, error: parsed.error.code || 'invalid_json' }, parsed.error.code === 'body_too_large' ? 413 : 400);
      const nextStatus = String(parsed.body?.status || '').trim();
      if (!['approved', 'rejected'].includes(nextStatus)) return respond({ ok: false, error: 'invalid_order_status' }, 400);
      try {
        const order = await env.DB.prepare('SELECT id, total_amount, status, created_at FROM orders WHERE id = ? LIMIT 1').bind(orderId).first();
        if (!order) return respond({ ok: false, error: 'order_not_found' }, 404);
        if (order.status !== 'pending') return respond({ ok: false, error: 'order_not_reviewable', status: order.status }, 409);
        if (typeof env.DB.batch !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
        const batchResult = await env.DB.batch([
          env.DB.prepare("UPDATE orders SET status = ? WHERE id = ? AND status = 'pending'").bind(nextStatus, orderId),
          env.DB.prepare(
            'INSERT INTO order_status_audit (order_id, actor_user_id, from_status, to_status) VALUES (?, ?, ?, ?)'
          ).bind(orderId, user.id, 'pending', nextStatus)
        ]);
        if (Number(batchResult?.[0]?.meta?.changes || 0) !== 1) return respond({ ok: false, error: 'order_not_reviewable' }, 409);
        const updated = await env.DB.prepare('SELECT id, total_amount, status, created_at FROM orders WHERE id = ? LIMIT 1').bind(orderId).first();
        return respond({ ok: true, order: updated });
      } catch (error) {
        const message = String(error?.message || '');
        if (message.includes('invalid_order_status_transition')) return respond({ ok: false, error: 'order_status_transition_invalid' }, 409);
        return respond({ ok: false, error: 'database_query_failed' }, 503);
      }
    }

    if (url.pathname === '/api/orders' && request.method === 'OPTIONS') {
      return corsPreflight(request, env, 'GET, POST, OPTIONS', 'Content-Type, Authorization, Idempotency-Key', requestId);
    }

    if (url.pathname === '/api/orders' && (request.method === 'POST' || request.method === 'GET')) {
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      let user;
      try { user = await getSessionUser(request, env); } catch { user = null; }
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);

      if (request.method === 'GET') {
        const rawLimit = url.searchParams.get('limit');
        const rawOffset = url.searchParams.get('offset');
        const rawCursor = url.searchParams.get('cursor');
        const limit = rawLimit === null || rawLimit === '' ? 20 : Number(rawLimit);
        if (!Number.isInteger(limit) || limit < 1 || limit > 50) return respond({ ok: false, error: 'invalid_pagination' }, 400);
        if (rawCursor && rawOffset) return respond({ ok: false, error: 'invalid_pagination' }, 400);
        const token = authTokenFromRequest(request);
        if (!token) return respond({ ok: false, error: 'unauthorized' }, 401);
        try {
          if (rawCursor) {
            const cursor = await parseOrderCursor(token, rawCursor);
            if (!cursor || cursor.user_id !== user.id || cursor.limit !== limit) return respond({ ok: false, error: 'invalid_cursor' }, 400);
            const result = await env.DB.prepare(
              `SELECT id, total_amount, status, created_at
               FROM orders WHERE customer_user_id = ?
                 AND (created_at < ? OR (created_at = ? AND id < ?))
               ORDER BY created_at DESC, id DESC LIMIT ?`
            ).bind(user.id, cursor.created_at, cursor.created_at, cursor.id, limit + 1).all();
            const rows = result.results || [];
            const hasMore = rows.length > limit;
            const orders = hasMore ? rows.slice(0, limit) : rows;
            const last = orders[orders.length - 1];
            const nextCursor = hasMore && last ? await makeOrderCursor(token, { v: 1, user_id: user.id, created_at: last.created_at, id: last.id, limit, exp: Math.floor(Date.now() / 1000) + 900 }) : null;
            return respond({ ok: true, orders, pagination: { limit, has_more: hasMore, cursor: rawCursor, next_cursor: nextCursor, offset: null, next_offset: null } });
          }
          const offset = rawOffset === null || rawOffset === '' ? 0 : Number(rawOffset);
          if (!Number.isInteger(offset) || offset < 0 || offset > 1000000) return respond({ ok: false, error: 'invalid_pagination' }, 400);
          const result = await env.DB.prepare(
            `SELECT id, total_amount, status, created_at
             FROM orders WHERE customer_user_id = ? ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
          ).bind(user.id, limit + 1, offset).all();
          const rows = result.results || [];
          const hasMore = rows.length > limit;
          const orders = hasMore ? rows.slice(0, limit) : rows;
          const last = orders[orders.length - 1];
          const nextCursor = hasMore && last ? await makeOrderCursor(token, { v: 1, user_id: user.id, created_at: last.created_at, id: last.id, limit, exp: Math.floor(Date.now() / 1000) + 900 }) : null;
          return respond({ ok: true, orders, pagination: { limit, offset, has_more: hasMore, next_offset: hasMore ? offset + limit : null, next_cursor: nextCursor } });
        } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
      }

      const limited = rateLimit(request, 'orderWrite', RATE_LIMITS.orderWrite, requestId);
      if (limited) return limited;
      if (!requireJsonContentType(request)) return respond({ ok: false, error: 'content_type_required' }, 415);
      const idempotencyKey = request.headers.get('Idempotency-Key')?.trim() || '';
      if (idempotencyKey && !/^[A-Za-z0-9._:-]{1,128}$/.test(idempotencyKey)) {
        return respond({ ok: false, error: 'invalid_idempotency_key' }, 400);
      }
      let body;
      const parsed = await parseBody(request, 24 * 1024);
      if (parsed.error) return respond({ ok: false, error: parsed.error.code || 'invalid_json' }, parsed.error.code === 'body_too_large' ? 413 : 400);
      body = parsed.body;
      const items = Array.isArray(body?.items) ? body.items : null;
      if (!items || items.length < 1 || items.length > 20) return respond({ ok: false, error: 'invalid_items' }, 400);

      const normalized = [];
      const seen = new Set();
      for (const item of items) {
        const productId = String(item?.product_id || '').trim();
        const quantity = Number(item?.quantity);
        if (!productId || utf8ByteLength(productId) > 128 || productId.includes('/') || !Number.isInteger(quantity) || quantity < 1 || quantity > 1000) {
          return respond({ ok: false, error: 'invalid_item' }, 400);
        }
        if (seen.has(productId)) return respond({ ok: false, error: 'duplicate_product' }, 400);
        seen.add(productId);
        normalized.push({ productId, quantity });
      }

      const requestFingerprint = idempotencyKey ? await sha256Hex(JSON.stringify(normalized)) : null;
      try {
        if (idempotencyKey) {
          const existing = await env.DB.prepare(
            `SELECT id, total_amount, status, created_at, idempotency_request_hash FROM orders WHERE customer_user_id = ? AND idempotency_key = ? LIMIT 1`
          ).bind(user.id, idempotencyKey).first();
          if (existing) {
            if (existing.idempotency_request_hash !== requestFingerprint) {
              return respond({ ok: false, error: 'idempotency_key_reused' }, 409);
            }
            const { id, total_amount, status, created_at } = existing;
            return respond({ ok: true, replay: true, order: { id, total_amount, status, created_at } }, 200);
          }
        }
        const placeholders = normalized.map(() => '?').join(',');
        const productResult = await env.DB.prepare(
          `SELECT id, name, sale_price, remaining, status FROM products WHERE id IN (${placeholders})`
        ).bind(...normalized.map(x => x.productId)).all();
        const products = new Map((productResult.results || []).map(p => [p.id, p]));
        for (const item of normalized) {
          const product = products.get(item.productId);
          if (!product || product.status !== 'active') return respond({ ok: false, error: 'product_not_found', product_id: item.productId }, 404);
          if (!Number.isSafeInteger(Number(product.remaining)) || Number(product.remaining) < 0) return respond({ ok: false, error: 'product_data_invalid' }, 503);
          const unitPrice = Number(product.sale_price);
          if (!Number.isSafeInteger(unitPrice) || unitPrice < 0 || unitPrice > Math.floor(Number.MAX_SAFE_INTEGER / item.quantity)) return respond({ ok: false, error: 'product_price_invalid' }, 503);
          if (Number(product.remaining) < item.quantity) return respond({ ok: false, error: 'insufficient_stock', product_id: item.productId }, 409);
        }

        const total = normalized.reduce((sum, item) => sum + Number(products.get(item.productId).sale_price) * item.quantity, 0);
        if (!Number.isSafeInteger(total) || total < 0) return respond({ ok: false, error: 'invalid_total' }, 400);
        const orderId = crypto.randomUUID();
        const statements = [env.DB.prepare(
          `INSERT INTO orders (id, customer_user_id, total_amount, status, idempotency_key, idempotency_request_hash) VALUES (?, ?, ?, 'pending', ?, ?)`
        ).bind(orderId, user.id, total, idempotencyKey || null, requestFingerprint)];
        for (const item of normalized) {
          statements.push(env.DB.prepare(
            `INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (?, ?, ?, ?)`
          ).bind(orderId, item.productId, item.quantity, Number(products.get(item.productId).sale_price)));
        }
        await env.DB.batch(statements);
        return respond({ ok: true, order: { id: orderId, total_amount: total, status: 'pending' } }, 201);
      } catch (error) {
        const message = String(error?.message || '');
        if (idempotencyKey && (message.includes('UNIQUE constraint failed') || message.includes('orders.customer_user_id, orders.idempotency_key'))) {
          const existing = await env.DB.prepare(
            `SELECT id, total_amount, status, created_at, idempotency_request_hash FROM orders WHERE customer_user_id = ? AND idempotency_key = ? LIMIT 1`
          ).bind(user.id, idempotencyKey).first();
          if (existing) {
            if (existing.idempotency_request_hash !== requestFingerprint) return respond({ ok: false, error: 'idempotency_key_reused' }, 409);
            const { id, total_amount, status, created_at } = existing;
            return respond({ ok: true, replay: true, order: { id, total_amount, status, created_at } }, 200);
          }
        }
        if (message.includes('insufficient_stock')) return respond({ ok: false, error: 'insufficient_stock' }, 409);
        if (message.includes('product_not_found') || message.includes('product_not_active')) return respond({ ok: false, error: 'product_not_found' }, 404);
        if (message.includes('product_data_invalid') || message.includes('product_price_invalid')) return respond({ ok: false, error: 'product_data_invalid' }, 503);
        return respond({ ok: false, error: 'database_query_failed' }, 503);
      }
    }


    if (url.pathname.startsWith('/api/orders/') && request.method === 'OPTIONS') {
      return corsPreflight(request, env, 'GET, POST, OPTIONS', 'Content-Type, Authorization, Idempotency-Key', requestId);
    }

    // Internal payment record lifecycle. This endpoint never charges an external gateway.
    if (url.pathname.startsWith('/api/orders/') && request.method === 'POST' && url.pathname.endsWith('/payment')) {
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      let user;
      try { user = await getSessionUser(request, env); } catch { user = null; }
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      const orderId = url.pathname.slice('/api/orders/'.length, -'/payment'.length);
      if (!orderId || orderId.includes('/') || orderId.includes('%')) return respond({ ok: false, error: 'invalid_order_id' }, 400);
      try {
        const order = await env.DB.prepare('SELECT id, total_amount, status, created_at FROM orders WHERE id = ? AND customer_user_id = ? LIMIT 1').bind(orderId, user.id).first();
        if (!order) return respond({ ok: false, error: 'order_not_found' }, 404);
        if (order.status === 'cancelled' || order.status === 'rejected') return respond({ ok: false, error: 'order_not_payable', status: order.status }, 409);
        const existing = await env.DB.prepare('SELECT id, order_id, amount, status, created_at FROM payments WHERE order_id = ? LIMIT 1').bind(orderId).first();
        if (existing) return respond({ ok: true, payment: existing, replay: true }, 200);
        const paymentId = randomHex(16);
        await env.DB.prepare("INSERT INTO payments (id, order_id, amount, status) VALUES (?, ?, ?, 'pending')").bind(paymentId, order.id, order.total_amount).run();
        const payment = await env.DB.prepare('SELECT id, order_id, amount, status, created_at FROM payments WHERE id = ? LIMIT 1').bind(paymentId).first();
        return respond({ ok: true, payment });
      } catch (error) {
        const message = String(error?.message || '');
        if (message.includes('UNIQUE constraint failed') || message.includes('payment_order')) {
          const payment = await env.DB.prepare('SELECT id, order_id, amount, status, created_at FROM payments WHERE order_id = ? LIMIT 1').bind(orderId).first();
          if (payment) return respond({ ok: true, payment, replay: true }, 200);
        }
        return respond({ ok: false, error: 'database_query_failed' }, 503);
      }
    }

    if (url.pathname.startsWith('/api/orders/') && request.method === 'GET' && url.pathname.endsWith('/payment')) {
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      let user;
      try { user = await getSessionUser(request, env); } catch { user = null; }
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      const orderId = url.pathname.slice('/api/orders/'.length, -'/payment'.length);
      if (!orderId || orderId.includes('/') || orderId.includes('%')) return respond({ ok: false, error: 'invalid_order_id' }, 400);
      try {
        const payment = await env.DB.prepare(
          `SELECT p.id, p.order_id, p.amount, p.status, p.created_at
           FROM payments p JOIN orders o ON o.id = p.order_id
           WHERE p.order_id = ? AND o.customer_user_id = ? LIMIT 1`
        ).bind(orderId, user.id).first();
        if (!payment) return respond({ ok: false, error: 'payment_not_found' }, 404);
        return respond({ ok: true, payment });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname.startsWith('/api/admin/orders/') && request.method === 'GET' && url.pathname.endsWith('/payment-history')) {
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      let user;
      try { user = await getSessionUser(request, env); } catch { user = null; }
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      if (user.role !== 'admin') return respond({ ok: false, error: 'forbidden' }, 403);
      const limited = rateLimit(request, 'adminPaymentAuditRead', RATE_LIMITS.adminPaymentAuditRead, requestId);
      if (limited) return limited;
      const orderId = url.pathname.slice('/api/admin/orders/'.length, -'/payment-history'.length);
      if (!orderId || orderId.includes('/') || orderId.includes('%')) return respond({ ok: false, error: 'invalid_order_id' }, 400);
      try {
        const payment = await env.DB.prepare('SELECT id FROM payments WHERE order_id = ? LIMIT 1').bind(orderId).first();
        if (!payment) return respond({ ok: false, error: 'payment_not_found' }, 404);
        const rawLimit = url.searchParams.get('limit');
        const rawOffset = url.searchParams.get('offset');
        const rawCursor = url.searchParams.get('cursor');
        const limit = rawLimit === null || rawLimit === '' ? 20 : Number(rawLimit);
        if (!Number.isInteger(limit) || limit < 1 || limit > 50) return respond({ ok: false, error: 'invalid_pagination' }, 400);
        if (rawCursor && rawOffset !== null) return respond({ ok: false, error: 'invalid_pagination' }, 400);
        let rows;
        let nextCursor = null;
        if (rawCursor) {
          const cursor = await parsePaymentAuditCursor(env, rawCursor);
          if (!cursor || cursor.admin_user_id !== user.id || cursor.order_id !== orderId || cursor.payment_id !== payment.id || cursor.limit !== limit) return respond({ ok: false, error: 'invalid_cursor' }, 400);
          rows = await env.DB.prepare(
            `SELECT a.id, a.payment_id, a.order_id, a.actor_user_id, u.phone AS actor_phone, a.from_status, a.to_status, a.created_at
             FROM payment_status_audit a JOIN users u ON u.id = a.actor_user_id
             WHERE a.payment_id = ? AND a.order_id = ? AND (a.created_at > ? OR (a.created_at = ? AND a.id > ?))
             ORDER BY a.created_at ASC, a.id ASC LIMIT ?`
          ).bind(payment.id, orderId, cursor.created_at, cursor.created_at, cursor.id, limit + 1).all();
        } else {
          const offset = rawOffset === null || rawOffset === '' ? 0 : Number(rawOffset);
          if (!Number.isInteger(offset) || offset < 0 || offset > 10000) return respond({ ok: false, error: 'invalid_pagination' }, 400);
          rows = await env.DB.prepare(
            `SELECT a.id, a.payment_id, a.order_id, a.actor_user_id, u.phone AS actor_phone, a.from_status, a.to_status, a.created_at
             FROM payment_status_audit a JOIN users u ON u.id = a.actor_user_id
             WHERE a.payment_id = ? AND a.order_id = ? ORDER BY a.created_at ASC, a.id ASC LIMIT ? OFFSET ?`
          ).bind(payment.id, orderId, limit + 1, offset).all();
        }
        const resultRows = rows.results || [];
        const hasMore = resultRows.length > limit;
        const history = hasMore ? resultRows.slice(0, limit) : resultRows;
        if (hasMore) {
          const last = history[history.length - 1];
          nextCursor = await makeAuditCursor(env, { v: 1, scope: 'payment-status-history', admin_user_id: user.id, order_id: orderId, payment_id: payment.id, created_at: last.created_at, id: Number(last.id), limit, exp: Math.floor(Date.now() / 1000) + 900 });
        }
        const offset = rawOffset === null || rawOffset === '' ? 0 : Number(rawOffset);
        return respond({ ok: true, history, pagination: { limit, has_more: hasMore, cursor: rawCursor || null, next_cursor: nextCursor, offset: rawCursor ? null : offset, next_offset: rawCursor ? null : (hasMore ? offset + limit : null) } });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname.startsWith('/api/admin/orders/') && request.method === 'POST' && url.pathname.endsWith('/payment-status')) {
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      let user;
      try { user = await getSessionUser(request, env); } catch { user = null; }
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      if (user.role !== 'admin') return respond({ ok: false, error: 'forbidden' }, 403);
      const limited = rateLimit(request, 'adminPaymentWrite', RATE_LIMITS.adminPaymentWrite, requestId);
      if (limited) return limited;
      const orderId = url.pathname.slice('/api/admin/orders/'.length, -'/payment-status'.length);
      if (!orderId || orderId.includes('/') || orderId.includes('%')) return respond({ ok: false, error: 'invalid_order_id' }, 400);
      if (!requireJsonContentType(request)) return respond({ ok: false, error: 'content_type_required' }, 415);
      const parsed = await parseBody(request, 8 * 1024);
      if (parsed.error) return respond({ ok: false, error: parsed.error.code || 'invalid_json' }, parsed.error.code === 'body_too_large' ? 413 : 400);
      const nextStatus = String(parsed.body?.status || '').trim();
      if (!['paid','failed','refunded'].includes(nextStatus)) return respond({ ok: false, error: 'invalid_payment_status' }, 400);
      try {
        const payment = await env.DB.prepare(
          `SELECT p.id, p.order_id, p.amount, p.status, p.created_at, o.status AS order_status
           FROM payments p JOIN orders o ON o.id = p.order_id WHERE p.order_id = ? LIMIT 1`
        ).bind(orderId).first();
        if (!payment) return respond({ ok: false, error: 'payment_not_found' }, 404);
        if (payment.status === nextStatus) return respond({ ok: true, payment: { id: payment.id, order_id: payment.order_id, amount: payment.amount, status: payment.status, created_at: payment.created_at }, replay: true });
        if (nextStatus === 'paid' && payment.order_status !== 'approved') return respond({ ok: false, error: 'payment_order_not_approved' }, 409);
        if (payment.status === 'refunded') return respond({ ok: false, error: 'payment_status_transition_invalid' }, 409);
        if (nextStatus === 'refunded' && payment.status !== 'paid') return respond({ ok: false, error: 'payment_status_transition_invalid' }, 409);
        if (nextStatus === 'failed' && payment.status !== 'pending') return respond({ ok: false, error: 'payment_status_transition_invalid' }, 409);
        if (typeof env.DB.batch !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
        const batchResult = await env.DB.batch([
          env.DB.prepare('UPDATE payments SET status = ? WHERE id = ? AND status = ?').bind(nextStatus, payment.id, payment.status),
          env.DB.prepare(
            'INSERT INTO payment_status_audit (payment_id, order_id, actor_user_id, from_status, to_status) VALUES (?, ?, ?, ?, ?)'
          ).bind(payment.id, payment.order_id, user.id, payment.status, nextStatus)
        ]);
        if (Number(batchResult?.[0]?.meta?.changes || 0) !== 1) return respond({ ok: false, error: 'payment_status_transition_invalid' }, 409);
        const updated = await env.DB.prepare('SELECT id, order_id, amount, status, created_at FROM payments WHERE id = ? LIMIT 1').bind(payment.id).first();
        return respond({ ok: true, payment: updated });
      } catch (error) {
        const message = String(error?.message || '');
        if (message.includes('payment_status_transition_invalid')) return respond({ ok: false, error: 'payment_status_transition_invalid' }, 409);
        if (message.includes('payment_order_not_approved')) return respond({ ok: false, error: 'payment_order_not_approved' }, 409);
        return respond({ ok: false, error: 'database_query_failed' }, 503);
      }
    }

    if (url.pathname.startsWith('/api/orders/') && request.method === 'POST' && url.pathname.endsWith('/cancel')) {
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      let user;
      try { user = await getSessionUser(request, env); } catch { user = null; }
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      const orderId = url.pathname.slice('/api/orders/'.length, -'/cancel'.length);
      if (!orderId || orderId.includes('/') || orderId.includes('%')) return respond({ ok: false, error: 'invalid_order_id' }, 400);
      try {
        const order = await env.DB.prepare(
          `SELECT id, total_amount, status, created_at FROM orders WHERE id = ? AND customer_user_id = ? LIMIT 1`
        ).bind(orderId, user.id).first();
        if (!order) return respond({ ok: false, error: 'order_not_found' }, 404);
        if (order.status !== 'pending') return respond({ ok: false, error: 'order_not_cancellable', status: order.status }, 409);
        if (typeof env.DB.batch !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
        const batchResult = await env.DB.batch([
          env.DB.prepare(`UPDATE orders SET status = 'cancelled' WHERE id = ? AND customer_user_id = ? AND status = 'pending'`).bind(orderId, user.id),
          env.DB.prepare(
            'INSERT INTO order_status_audit (order_id, actor_user_id, from_status, to_status) VALUES (?, ?, ?, ?)'
          ).bind(orderId, user.id, 'pending', 'cancelled')
        ]);
        if (Number(batchResult?.[0]?.meta?.changes || 0) !== 1) return respond({ ok: false, error: 'order_not_cancellable' }, 409);
        const updated = await env.DB.prepare(
          `SELECT id, total_amount, status, created_at FROM orders WHERE id = ? AND customer_user_id = ? LIMIT 1`
        ).bind(orderId, user.id).first();
        return respond({ ok: true, order: updated });
      } catch (error) {
        const message = String(error?.message || '');
        if (message.includes('invalid_order_status_transition')) return respond({ ok: false, error: 'order_status_transition_invalid' }, 409);
        return respond({ ok: false, error: 'database_query_failed' }, 503);
      }
    }

    if (url.pathname.startsWith('/api/orders/') && request.method === 'GET') {
      if (!env.DB || typeof env.DB.prepare !== 'function') return respond({ ok: false, error: 'database_not_configured' }, 503);
      let user;
      try { user = await getSessionUser(request, env); } catch { user = null; }
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      let orderId = '';
      try { orderId = decodeURIComponent(url.pathname.slice('/api/orders/'.length)); } catch { return respond({ ok: false, error: 'invalid_order_id' }, 400); }
      if (!orderId || orderId.includes('/')) return respond({ ok: false, error: 'invalid_order_id' }, 400);
      try {
        const order = await env.DB.prepare(
          `SELECT id, total_amount, status, created_at FROM orders WHERE id = ? AND customer_user_id = ? LIMIT 1`
        ).bind(orderId, user.id).first();
        if (!order) return respond({ ok: false, error: 'order_not_found' }, 404);
        const result = await env.DB.prepare(
          `SELECT oi.product_id, p.name, oi.quantity, oi.unit_price
           FROM order_items oi JOIN products p ON p.id = oi.product_id
           WHERE oi.order_id = ? ORDER BY oi.id`
        ).bind(orderId).all();
        return respond({ ok: true, order: { ...order, items: result.results || [] } });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if ((url.pathname === '/api/products' || url.pathname.startsWith('/api/products/')) && request.method === 'OPTIONS') {
      return corsPreflight(request, env, 'GET, OPTIONS', 'Content-Type', requestId);
    }

    if (url.pathname.startsWith('/api/products/') && (request.method === 'GET' || request.method === 'HEAD')) {
      let productId = '';
      try {
        productId = decodeURIComponent(url.pathname.slice('/api/products/'.length));
      } catch (error) {
        return respond({ ok: false, error: 'invalid_product_id' }, 400);
      }
      if (!productId) {
        return respond({ ok: false, error: 'product_id_required' }, 400);
      }
      if (productId.includes('/')) {
        return respond({ ok: false, error: 'invalid_product_id' }, 400);
      }
      if (!env.DB || typeof env.DB.prepare !== 'function') {
        return respond({ ok: false, error: 'database_not_configured' }, 503);
      }
      try {
        const product = await env.DB.prepare(
          `SELECT p.id, p.name, p.sale_price, p.remaining, p.status, p.created_at, COALESCE(sa.shop_name, '') AS shop_name
           FROM products p LEFT JOIN seller_applications sa ON sa.user_id=p.seller_user_id AND sa.status='approved'
           WHERE p.id = ? AND p.status = 'active' AND remaining > 0
           LIMIT 1`
        ).bind(productId).first();
        if (!product) {
          return respond({ ok: false, error: 'product_not_found' }, 404);
        }
        const responseBody = { ok: true, product: publicProductView(product) };
        const etag = await etagForJson(responseBody);
        const cacheHeaders = { 'Cache-Control': 'public, max-age=30, stale-while-revalidate=30', 'ETag': etag, 'Vary': 'Origin' };
        if (ifNoneMatchMatches(request, etag)) {
          return new Response(null, { status: 304, headers: corsHeaders(request, env, { 'X-Request-ID': requestId, ...cacheHeaders }) });
        }
        if (request.method === 'HEAD') {
          return new Response(null, { status: 200, headers: corsHeaders(request, env, { 'X-Request-ID': requestId, ...cacheHeaders }) });
        }
        return respond(responseBody, 200, cacheHeaders);
      } catch (error) {
        return respond({ ok: false, error: 'database_query_failed' }, 503);
      }
    }


    // v207 — real seller/application/product management. The browser is no longer
    // allowed to invent seller approval or catalog state; D1 is authoritative.
    if (url.pathname === '/api/seller/apply' && request.method === 'OPTIONS') {
      return corsPreflight(request, env, 'POST, OPTIONS', 'Content-Type, Authorization', requestId);
    }
    if (url.pathname === '/api/seller/apply' && request.method === 'POST') {
      const user = await getSessionUser(request, env);
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      if (user.role !== 'customer') return respond({ ok: false, error: 'seller_application_not_allowed' }, 403);
      if (!requireJsonContentType(request)) return respond({ ok: false, error: 'content_type_required' }, 415);
      const parsed = await parseBody(request, 8 * 1024);
      if (parsed.error) return respond({ ok: false, error: parsed.error.code || 'invalid_json' }, 400);
      const shopName = String(parsed.body?.shop_name || '').trim();
      if (utf8ByteLength(shopName) < 2 || utf8ByteLength(shopName) > 160) return respond({ ok: false, error: 'invalid_shop_name' }, 400);
      try {
        const existing = await env.DB.prepare(`SELECT id,status FROM seller_applications WHERE user_id=? ORDER BY created_at DESC LIMIT 1`).bind(user.id).first();
        if (existing?.status === 'pending') return respond({ ok: false, error: 'application_pending' }, 409);
        const id = crypto.randomUUID();
        await env.DB.prepare(`INSERT INTO seller_applications (id,user_id,shop_name,status) VALUES (?,?,?,'pending')`).bind(id,user.id,shopName).run();
        return respond({ ok: true, application: { id, shop_name: shopName, status: 'pending' } }, 201);
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname === '/api/admin/seller-applications' && request.method === 'OPTIONS') {
      return corsPreflight(request, env, 'GET, OPTIONS', 'Content-Type, Authorization', requestId);
    }
    if (url.pathname === '/api/admin/seller-applications' && request.method === 'GET') {
      const user = await getSessionUser(request, env);
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      if (user.role !== 'admin') return respond({ ok: false, error: 'forbidden' }, 403);
      try {
        const rows = await env.DB.prepare(`SELECT sa.id,sa.user_id,sa.shop_name,sa.status,sa.created_at,u.phone FROM seller_applications sa JOIN users u ON u.id=sa.user_id ORDER BY sa.created_at DESC LIMIT 100`).all();
        return respond({ ok: true, applications: rows.results || [] });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    const sellerDecision = url.pathname.match(/^\/api\/admin\/seller-applications\/([^/]+)\/(approve|reject)$/);
    if (sellerDecision && request.method === 'OPTIONS') return corsPreflight(request, env, 'POST, OPTIONS', 'Content-Type, Authorization', requestId);
    if (sellerDecision && request.method === 'POST') {
      const user = await getSessionUser(request, env);
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      if (user.role !== 'admin') return respond({ ok: false, error: 'forbidden' }, 403);
      const applicationId = decodeURIComponent(sellerDecision[1]);
      const decision = sellerDecision[2];
      try {
        const app = await env.DB.prepare(`SELECT id,user_id,status FROM seller_applications WHERE id=? LIMIT 1`).bind(applicationId).first();
        if (!app) return respond({ ok: false, error: 'application_not_found' }, 404);
        if (app.status !== 'pending') return respond({ ok: false, error: 'application_already_reviewed' }, 409);
        if (decision === 'approve') {
          await env.DB.batch([
            env.DB.prepare(`UPDATE seller_applications SET status='approved' WHERE id=?`).bind(applicationId),
            env.DB.prepare(`UPDATE users SET role='seller' WHERE id=? AND status='active'`).bind(app.user_id)
          ]);
        } else {
          await env.DB.prepare(`UPDATE seller_applications SET status='rejected' WHERE id=?`).bind(applicationId).run();
        }
        return respond({ ok: true, status: decision === 'approve' ? 'approved' : 'rejected' });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname === '/api/seller/products' && request.method === 'OPTIONS') return corsPreflight(request, env, 'GET, POST, OPTIONS', 'Content-Type, Authorization', requestId);
    if (url.pathname === '/api/seller/products' && (request.method === 'GET' || request.method === 'POST')) {
      const user = await getSessionUser(request, env);
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      if (user.role !== 'seller') return respond({ ok: false, error: 'seller_only' }, 403);
      if (request.method === 'GET') {
        try {
          const rows = await env.DB.prepare(`SELECT id,name,sale_price,remaining,status,created_at FROM products WHERE seller_user_id=? ORDER BY created_at DESC LIMIT 100`).bind(user.id).all();
          return respond({ ok: true, products: rows.results || [] });
        } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
      }
      if (!requireJsonContentType(request)) return respond({ ok: false, error: 'content_type_required' }, 415);
      const parsed = await parseBody(request, 8 * 1024);
      if (parsed.error) return respond({ ok: false, error: parsed.error.code || 'invalid_json' }, 400);
      const name = String(parsed.body?.name || '').trim();
      const salePrice = Number(parsed.body?.sale_price);
      const remaining = Number(parsed.body?.remaining ?? 0);
      if (utf8ByteLength(name) < 2 || utf8ByteLength(name) > 200 || !Number.isSafeInteger(salePrice) || salePrice < 0 || !Number.isSafeInteger(remaining) || remaining < 0) return respond({ ok: false, error: 'invalid_product' }, 400);
      try {
        const id = crypto.randomUUID();
        await env.DB.prepare(`INSERT INTO products (id,seller_user_id,name,sale_price,remaining,status) VALUES (?,?,?,?,?,'active')`).bind(id,user.id,name,salePrice,remaining).run();
        return respond({ ok: true, product: { id, name, sale_price: salePrice, remaining, status: 'active' } }, 201);
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    const sellerProduct = url.pathname.match(/^\/api\/seller\/products\/([^/]+)(?:\/(stock))?$/);
    if (sellerProduct && request.method === 'OPTIONS') return corsPreflight(request, env, 'POST, DELETE, OPTIONS', 'Content-Type, Authorization', requestId);
    if (sellerProduct && (request.method === 'POST' || request.method === 'DELETE')) {
      const user = await getSessionUser(request, env);
      if (!user) return respond({ ok: false, error: 'unauthorized' }, 401);
      if (user.role !== 'seller') return respond({ ok: false, error: 'seller_only' }, 403);
      const id = decodeURIComponent(sellerProduct[1]);
      try {
        const product = await env.DB.prepare(`SELECT id,name,sale_price,remaining,status FROM products WHERE id=? AND seller_user_id=? LIMIT 1`).bind(id,user.id).first();
        if (!product) return respond({ ok: false, error: 'product_not_found' }, 404);
        if (request.method === 'DELETE') {
          if (product.remaining < 0) return respond({ ok: false, error: 'invalid_stock' }, 409);
          await env.DB.prepare(`UPDATE products SET status='inactive' WHERE id=? AND seller_user_id=?`).bind(id,user.id).run();
          return respond({ ok: true });
        }
        if (!sellerProduct[2]) return respond({ ok: false, error: 'stock_endpoint_required' }, 400);
        if (!requireJsonContentType(request)) return respond({ ok: false, error: 'content_type_required' }, 415);
        const parsed = await parseBody(request, 2048);
        if (parsed.error) return respond({ ok: false, error: parsed.error.code || 'invalid_json' }, 400);
        const delta = Number(parsed.body?.delta);
        if (!Number.isSafeInteger(delta) || delta === 0 || Math.abs(delta) > 100000) return respond({ ok: false, error: 'invalid_stock_delta' }, 400);
        const next = Number(product.remaining) + delta;
        if (!Number.isSafeInteger(next) || next < 0) return respond({ ok: false, error: 'insufficient_stock' }, 409);
        await env.DB.prepare(`UPDATE products SET remaining=?, status='active' WHERE id=? AND seller_user_id=?`).bind(next,id,user.id).run();
        return respond({ ok: true, product: { ...product, remaining: next, status: 'active' } });
      } catch { return respond({ ok: false, error: 'database_query_failed' }, 503); }
    }

    if (url.pathname === '/api/products' && (request.method === 'GET' || request.method === 'HEAD')) {
      if (!env.DB || typeof env.DB.prepare !== 'function') {
        return respond({ ok: false, error: 'database_not_configured' }, 503);
      }
      const rawLimit = Number(url.searchParams.get('limit') || 50);
      if (!Number.isInteger(rawLimit) || rawLimit < 1 || rawLimit > 100) {
        return respond({ ok: false, error: 'invalid_pagination' }, 400);
      }
      const limit = rawLimit;
      const cursorRaw = url.searchParams.get('cursor');
      const offsetRaw = url.searchParams.get('offset');
      if (cursorRaw && offsetRaw !== null) return respond({ ok: false, error: 'invalid_pagination' }, 400);
      try {
        if (cursorRaw) {
          const cursor = await parseProductCursor(env, cursorRaw);
          if (!cursor || cursor.limit !== limit) return respond({ ok: false, error: 'invalid_cursor' }, 400);
          const result = await env.DB.prepare(
            `SELECT p.id, p.name, p.sale_price, p.remaining, p.status, p.created_at, COALESCE(sa.shop_name, '') AS shop_name
             FROM products p LEFT JOIN seller_applications sa ON sa.user_id=p.seller_user_id AND sa.status='approved'
             WHERE p.status = 'active' AND p.remaining > 0
               AND (p.created_at < ? OR (p.created_at = ? AND p.id < ?))
             ORDER BY p.created_at DESC, p.id DESC LIMIT ?`
          ).bind(cursor.created_at, cursor.created_at, cursor.id, limit + 1).all();
          const rows = result.results || [];
          const hasMore = rows.length > limit;
          const products = rows.slice(0, limit).map(publicProductView);
          const last = products[products.length - 1];
          const nextCursor = hasMore && last ? await makeProductCursor(env, { v: 3, scope: 'active-in-stock', created_at: last.created_at, id: last.id, limit, exp: productCursorExpiry() }) : null;
          const responseBody = { ok: true, products, pagination: { limit, has_more: hasMore, cursor: cursorRaw, next_cursor: nextCursor } };
          const etag = await etagForJson(responseBody);
          const cacheHeaders = { 'Cache-Control': 'public, max-age=30, stale-while-revalidate=30', 'ETag': etag, 'Vary': 'Origin' };
          if (ifNoneMatchMatches(request, etag)) return new Response(null, { status: 304, headers: corsHeaders(request, env, { 'X-Request-ID': requestId, ...cacheHeaders }) });
          if (request.method === 'HEAD') return new Response(null, { status: 200, headers: corsHeaders(request, env, { 'X-Request-ID': requestId, ...cacheHeaders }) });
          return respond(responseBody, 200, cacheHeaders);
        }
        const offset = offsetRaw === null ? 0 : Number(offsetRaw);
        if (!Number.isInteger(offset) || offset < 0 || offset > 1000000) return respond({ ok: false, error: 'invalid_pagination' }, 400);
        const result = await env.DB.prepare(
          `SELECT id, name, sale_price, remaining, status, created_at
           FROM products
           WHERE status = 'active' AND remaining > 0
           ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
        ).bind(limit + 1, offset).all();
        const rows = result.results || [];
        const hasMore = rows.length > limit;
        const products = rows.slice(0, limit).map(publicProductView);
        const last = products[products.length - 1];
        const nextCursor = hasMore && last ? await makeProductCursor(env, { v: 3, scope: 'active-in-stock', created_at: last.created_at, id: last.id, limit, exp: productCursorExpiry() }) : null;
        const responseBody = { ok: true, products, pagination: { limit, has_more: hasMore, next_cursor: nextCursor, offset, next_offset: hasMore ? offset + limit : null } };
        const etag = await etagForJson(responseBody);
        const cacheHeaders = { 'Cache-Control': 'public, max-age=30, stale-while-revalidate=30', 'ETag': etag, 'Vary': 'Origin' };
        if (ifNoneMatchMatches(request, etag)) return new Response(null, { status: 304, headers: corsHeaders(request, env, { 'X-Request-ID': requestId, ...cacheHeaders }) });
        if (request.method === 'HEAD') return new Response(null, { status: 200, headers: corsHeaders(request, env, { 'X-Request-ID': requestId, ...cacheHeaders }) });
        return respond(responseBody, 200, cacheHeaders);
      } catch (error) {
        return respond({ ok: false, error: 'database_query_failed' }, 503);
      }
    }

    if (url.pathname === '/api/db/stats' && request.method === 'OPTIONS') {
      return corsPreflight(request, env, 'GET, OPTIONS', 'Content-Type, Authorization', requestId);
    }

    if (url.pathname === '/api/db/stats' && request.method === 'GET') {
      const limited = rateLimit(request, 'adminDbStatsRead', RATE_LIMITS.adminDbStatsRead, requestId);
      if (limited) return limited;
      if (!env.DB || typeof env.DB.prepare !== 'function') {
        return respond({ ok: false, error: 'database_not_configured' }, 503);
      }
      try {
        const user = await getSessionUser(request, env);
        if (!user || user.role !== 'admin') return respond({ ok: false, error: 'forbidden' }, 403);
        const tables = ['users', 'seller_applications', 'products', 'orders', 'order_items', 'payments'];
        const counts = {};
        for (const table of tables) {
          const row = await env.DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first();
          counts[table] = Number(row?.count || 0);
        }
        return respond({ ok: true, counts });
      } catch (error) {
        return respond({ ok: false, error: 'database_query_failed' }, 503);
      }
    }

    if (url.pathname === '/api/health' && request.method === 'OPTIONS') {
      return corsPreflight(request, env, 'GET, HEAD, OPTIONS', 'Content-Type', requestId);
    }

    if (url.pathname === '/api/health' && request.method === 'HEAD') {
      return new Response(null, { status: configError ? 503 : 200, headers: corsHeaders(request, env, { 'X-Request-ID': requestId }) });
    }

    if (url.pathname === '/api/health' && request.method === 'GET') {
      return respond({
        ok: !configError,
        service: 'nejat-bede-api',
        version: 'v211',
        timestamp: new Date().toISOString(),
        ...(configError ? { error: 'configuration_not_ready' } : {})
      }, configError ? 503 : 200);
    }

    if (url.pathname === '/api/health/config' && request.method === 'OPTIONS') {
      return corsPreflight(request, env, 'GET, HEAD, OPTIONS', 'Content-Type', requestId);
    }

    if (url.pathname === '/api/health/config' && request.method === 'HEAD') {
      return new Response(null, { status: configError ? 503 : 200, headers: corsHeaders(request, env, { 'X-Request-ID': requestId }) });
    }

    if (url.pathname === '/api/health/config' && request.method === 'GET') {
      const production = String(env?.ENVIRONMENT || '').trim().toLowerCase() === 'production';
      const secretConfigured = productCursorSecret(env).length >= 32;
      const originsConfigured = allowedOrigins(env).length > 0;
      return respond({ ok: !configError, environment: production ? 'production' : 'non-production', checks: { cursor_secret: secretConfigured, allowed_origins: originsConfigured } }, configError ? 503 : 200);
    }

    if (url.pathname === '/api/health/db' && (request.method === 'GET' || request.method === 'HEAD')) {
      if (!env.DB || typeof env.DB.prepare !== 'function') {
        if (request.method === 'HEAD') return new Response(null, { status: 503, headers: corsHeaders(request, env, { 'X-Request-ID': requestId }) });
        return respond({ ok: false, error: 'database_not_configured' }, 503);
      }
      try {
        await env.DB.prepare('SELECT 1 AS ok').first();
        const requiredSchema = {
          users: ['id','phone','role','password_hash','status','created_at'],
          products: ['id','seller_user_id','name','sale_price','remaining','status','created_at'],
          sessions: ['id','user_id','token_hash','expires_at','created_at'],
          orders: ['id','customer_user_id','total_amount','status','created_at'],
          order_items: ['id','order_id','product_id','quantity','unit_price'],
          payments: ['id','order_id','amount','status','provider_ref','created_at'],
          order_status_audit: ['id','order_id','actor_user_id','from_status','to_status','created_at'],
          payment_status_audit: ['id','payment_id','order_id','actor_user_id','from_status','to_status','created_at'],
          security_audit: ['id','user_id','event','request_id','session_id','created_at']
        };
        const requiredTables = Object.keys(requiredSchema);
        const tableRows = await env.DB.prepare(
          `SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (${requiredTables.map(() => '?').join(', ')})`
        ).bind(...requiredTables).all();
        const foundTables = new Set((tableRows.results || []).map((row) => row.name));
        if (requiredTables.some((name) => !foundTables.has(name))) {
          if (request.method === 'HEAD') return new Response(null, { status: 503, headers: corsHeaders(request, env, { 'X-Request-ID': requestId }) });
          return respond({ ok: false, error: 'database_schema_not_ready' }, 503);
        }
        for (const [table, columns] of Object.entries(requiredSchema)) {
          const rows = await env.DB.prepare(`SELECT name FROM pragma_table_info(?)`).bind(table).all();
          const foundColumns = new Set((rows.results || []).map((row) => row.name));
          if (columns.some((column) => !foundColumns.has(column))) {
            if (request.method === 'HEAD') return new Response(null, { status: 503, headers: corsHeaders(request, env, { 'X-Request-ID': requestId }) });
            return respond({ ok: false, error: 'database_schema_not_ready' }, 503);
          }
        }
        if (request.method === 'HEAD') return new Response(null, { status: 200, headers: corsHeaders(request, env, { 'X-Request-ID': requestId }) });
        return respond({ ok: true, database: 'reachable', schema: 'ready' });
      } catch (error) {
        if (request.method === 'HEAD') return new Response(null, { status: 503, headers: corsHeaders(request, env, { 'X-Request-ID': requestId }) });
        return respond({ ok: false, error: 'database_unreachable' }, 503);
      }
    }

    if (url.pathname === '/api/health') {
      return methodNotAllowed('GET, HEAD, OPTIONS');
    }

    if (url.pathname === '/api/health/db') return methodNotAllowed('GET, HEAD, OPTIONS');
    if (url.pathname === '/api/health/config') return methodNotAllowed('GET, HEAD, OPTIONS');
    if (url.pathname === '/api/auth/register') return methodNotAllowed('POST, OPTIONS');
    if (url.pathname === '/api/auth/login') return methodNotAllowed('POST, OPTIONS');
    if (url.pathname === '/api/auth/me') return methodNotAllowed('GET, OPTIONS');
    if (url.pathname === '/api/auth/change-password') return methodNotAllowed('POST, OPTIONS');
    if (url.pathname === '/api/auth/logout') return methodNotAllowed('POST, OPTIONS');
    if (url.pathname === '/api/auth/logout-all') return methodNotAllowed('POST, OPTIONS');
    if (url.pathname === '/api/auth/logout-others') return methodNotAllowed('POST, OPTIONS');
    if (url.pathname === '/api/orders') return methodNotAllowed('GET, POST, OPTIONS');
    if (url.pathname === '/api/products') return methodNotAllowed('GET, HEAD, OPTIONS');
    if (url.pathname === '/api/seller/apply') return methodNotAllowed('POST, OPTIONS');
    if (url.pathname === '/api/admin/seller-applications') return methodNotAllowed('GET, OPTIONS');
    if (url.pathname === '/api/seller/products') return methodNotAllowed('GET, POST, OPTIONS');
    if (url.pathname === '/api/db/stats') return methodNotAllowed('GET, OPTIONS');

    return respond({ ok: false, error: 'not_found' }, 404);
  }
};
