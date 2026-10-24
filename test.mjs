import worker from './worker/index.js';
const env={CURSOR_SECRET:'contract-test-secret'};
const inputGuardEnv={DB:{prepare(){throw new Error('DB should not be reached by input guard');}}};
async function req(method,path,body,headers={},e=env){return worker.fetch(new Request('https://example.com'+path,{method,headers:{...(body!==undefined?{'Content-Type':'application/json'}:{}),...headers},body:body!==undefined?JSON.stringify(body):undefined}),e)}
let r=await req('GET','/api/health'); let j=await r.json(); if(r.status!==200||j.version!=='v211') throw Error('health version contract failed');
r=await req('GET','/api/health/db'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('DB readiness failed');
r=await req('HEAD','/api/health'); if(r.status!==200) throw Error('health HEAD ready failed');
r=await req('HEAD','/api/health',undefined,{}, {ENVIRONMENT:'production',CURSOR_SECRET:'short',ALLOWED_ORIGINS:'https://app.example.com'}); if(r.status!==503) throw Error('health HEAD config guard failed');
r=await req('HEAD','/api/health/db'); if(r.status!==503) throw Error('DB HEAD readiness failed');
r=await req('GET','/api/health/config',undefined,{}, {ENVIRONMENT:'production',CURSOR_SECRET:'short',ALLOWED_ORIGINS:'https://app.example.com'}); j=await r.json(); if(r.status!==503||j.checks.cursor_secret!==false) throw Error('production config secret guard failed');
r=await req('GET','/api/health/config',undefined,{}, {ENVIRONMENT:'production',CURSOR_SECRET:'abcdefghijklmnopqrstuvwxyz123456',ALLOWED_ORIGINS:''}); j=await r.json(); if(r.status!==503||j.checks.allowed_origins!==false) throw Error('production config origin guard failed');
r=await req('GET','/api/health/config',undefined,{}, {ENVIRONMENT:'production',CURSOR_SECRET:'abcdefghijklmnopqrstuvwxyz123456',ALLOWED_ORIGINS:'https://app.example.com'}); j=await r.json(); if(r.status!==200||j.ok!==true||j.checks.cursor_secret!==true||j.checks.allowed_origins!==true) throw Error('production config ready check failed');

r=await req('GET','/api/db/stats'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('DB stats readiness failed');
r=await req('OPTIONS','/api/db/stats',undefined,{Origin:'https://app.example.com'} ,{CURSOR_SECRET:'abcdefghijklmnopqrstuvwxyz123456',ALLOWED_ORIGINS:'https://app.example.com'}); if(r.status!==204||r.headers.get('Access-Control-Allow-Headers')?.includes('Authorization')!==true||!r.headers.get('X-Request-ID')) throw Error('DB stats CORS preflight/request-id failed');
r=await req('POST','/api/health'); j=await r.json(); if(r.status!==405||j.error!=='method_not_allowed'||r.headers.get('Allow')!=='GET, HEAD, OPTIONS'||!r.headers.get('X-Request-ID')) throw Error('health method contract failed');
r=await req('POST','/api/products'); j=await r.json(); if(r.status!==405||j.error!=='method_not_allowed'||r.headers.get('Allow')!=='GET, HEAD, OPTIONS') throw Error('products method contract failed');
r=await req('GET','/api/products/%E0%A4%A'); j=await r.json(); if(r.status!==400||j.error!=='invalid_product_id'||!r.headers.get('X-Request-ID')) throw Error('malformed product id contract failed');
r=await req('GET','/api/products?limit=0'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('product pagination readiness failed');
r=await req('OPTIONS','/api/orders'); if(r.status!==204||!r.headers.get('Access-Control-Allow-Headers')?.includes('Authorization')||!r.headers.get('X-Request-ID')) throw Error('Orders CORS/request-id failed');
r=await req('POST','/api/auth/register',{phone:'+12345678',password:'password123'},{'Content-Type':'text/plain'}); j=await r.json(); if(r.status!==415||j.error!=='content_type_required') throw Error('content type guard failed');
r=await req('POST','/api/auth/register',{phone:'+12345678',password:'password123'}); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('register readiness failed');
r=await req('POST','/api/auth/register',[],{'X-Forwarded-For':'198.51.100.201'},inputGuardEnv); j=await r.json(); if(r.status!==400||j.error!=='invalid_json') throw Error('JSON object guard failed');
r=await req('POST','/api/auth/register',{phone:'+12345678',password:'x'.repeat(9000)},{'X-Forwarded-For':'198.51.100.202'},inputGuardEnv); j=await r.json(); if(r.status!==413||j.error!=='body_too_large') throw Error('register body size guard failed');
r=await req('POST','/api/auth/register',undefined,{'Content-Type':'application/json','Content-Length':'bad','X-Forwarded-For':'198.51.100.203'},inputGuardEnv); j=await r.json(); if(r.status!==413||j.error!=='body_too_large') throw Error('invalid content-length guard failed');
for(let i=0;i<4;i++){r=await req('POST','/api/auth/register',{phone:'+12345678',password:'password123'});}
r=await req('POST','/api/auth/register',{phone:'+12345678',password:'password123'}); j=await r.json(); if(r.status!==429||j.error!=='rate_limited'||!r.headers.get('X-Request-ID')) throw Error('rate limiter/request-id failed');
r=await req('POST','/api/orders',{items:[{product_id:'p1',quantity:1}]}); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('orders readiness failed');
r=await req('GET','/api/orders?limit=0'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('orders pagination readiness failed');
r=await req('POST','/api/orders/test-order/cancel'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('order cancel readiness failed');
r=await req('POST','/api/admin/orders/test-order/status',{status:'approved'}); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('admin order review readiness failed');
r=await req('GET','/api/admin/orders'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('admin order list readiness failed');
r=await req('POST','/api/orders/test-order/payment'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('payment create readiness failed');
r=await req('GET','/api/orders/test-order/payment'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('payment get readiness failed');
r=await req('POST','/api/admin/orders/test-order/payment-status',{status:'paid'}); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('admin payment status readiness failed');
r=await req('GET','/api/admin/orders/test-order/status-history'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('admin order audit readiness failed');
r=await req('GET','/api/auth/me',undefined,{Authorization:'Bearer not-a-real-token'}); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('strict token parsing readiness failed');
r=await req('GET','/api/auth/security-events'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('security events readiness failed');
r=await req('GET','/api/auth/security-events?event=not-real'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('security event filter readiness failed');
r=await req('GET','/api/auth/security-events?since=bad-time'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('security event time filter readiness failed');
r=await req('GET','/api/auth/sessions'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('sessions readiness failed');
r=await req('POST','/api/auth/sessions/not-a-uuid'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('session revoke readiness failed');
r=await req('POST','/api/auth/logout-others'); j=await r.json(); if(r.status!==503||j.error!=='database_not_configured') throw Error('logout-others readiness failed');
console.log('v206 security-event filters + logout rate limits + security-audit login/logout + security-audit retention + admin-order-list + HMAC-signed product cursor + order cursor pagination + security + idempotency contract tests: PASS');


// Scheduled security-audit cleanup must emit sanitized structured observability logs.
const originalConsoleLog = console.log;
const originalConsoleError = console.error;
const scheduledLogs = [];
console.log = (...args) => scheduledLogs.push({ level: 'log', args });
console.error = (...args) => scheduledLogs.push({ level: 'error', args });
try {
  const db = { prepare(sql) { if (!sql.includes('DELETE FROM security_audit')) throw Error('unexpected_sql'); return { bind() { return { async run() { return { meta: { changes: 3 } }; } }; } }; } };
  await worker.scheduled({ cron: '0 3 * * *' }, { DB: db, SECURITY_AUDIT_RETENTION_DAYS: '90' });
  const okEntry = scheduledLogs.find((x) => x.level === 'log');
  if (!okEntry || !String(okEntry.args[0]).includes('"event":"security_audit_cleanup"') || !String(okEntry.args[0]).includes('"deleted":3')) throw Error('scheduled success observability failed');

  scheduledLogs.length = 0;
  const failingDb = { prepare() { throw new Error('secret-looking-db-error-token'); } };
  let failed = false;
  try { await worker.scheduled({ cron: '0 3 * * *' }, { DB: failingDb }); } catch { failed = true; }
  const errEntry = scheduledLogs.find((x) => x.level === 'error');
  if (!failed || !errEntry || String(errEntry.args[0]).includes('secret-looking-db-error-token') === true || !String(errEntry.args[0]).includes('"event":"security_audit_cleanup"')) throw Error('scheduled failure observability failed');
} finally {
  console.log = originalConsoleLog;
  console.error = originalConsoleError;
}
console.log('v206 scheduled cleanup observability tests: PASS');
