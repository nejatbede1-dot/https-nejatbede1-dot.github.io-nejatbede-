import { existsSync, readFileSync, unlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);
const config = path.join(root, 'worker', 'wrangler.production.toml');
const baseUrl = process.env.PRODUCTION_BASE_URL?.replace(/\/$/, '');
const dryRun = process.env.DRY_RUN === '1' || process.argv.includes('--dry-run');
const node = process.execPath;
const confirmed = process.env.PRODUCTION_DEPLOY_CONFIRM === 'I_UNDERSTAND';
function fail(message) { console.error(`ERROR: ${message}`); process.exit(2); }
if (!existsSync(config)) fail('Missing worker/wrangler.production.toml. Run "npm run prepare:production" first.');
if (!existsSync(path.join(root, 'migrations'))) fail('Missing migrations directory.');
const toml = readFileSync(config, 'utf8');
const idMatch = toml.match(/^database_id\s*=\s*"([^"]+)"/m);
const nameMatch = toml.match(/^database_name\s*=\s*"([^"]+)"/m);
if (!idMatch || !/^[A-Za-z0-9_-]{8,}$/.test(idMatch[1])) fail('Production config has no valid D1 database_id.');
if (!nameMatch || !nameMatch[1]) fail('Production config has no database_name.');
if (!/ENVIRONMENT\s*=\s*"production"/.test(toml)) fail('Production config is not marked ENVIRONMENT=production.');
if (!/ALLOWED_ORIGINS\s*=\s*"[^"]+"/.test(toml)) fail('Production config has no ALLOWED_ORIGINS.');
if (toml.includes('CURSOR_SECRET')) fail('Production config must never contain CURSOR_SECRET.');
if (!dryRun && !confirmed) fail('Refusing production deploy. Set PRODUCTION_DEPLOY_CONFIRM=I_UNDERSTAND explicitly.');

function runLocal(script, extraEnv = {}) {
  const r = spawnSync(node, [path.join(root, 'scripts', script)], { stdio: 'inherit', env: { ...process.env, ...extraEnv } });
  if (r.error) fail(`Could not start local verification ${script}: ${r.error.message}`);
  if (r.status !== 0) fail(`Local verification ${script} failed with exit code ${r.status}.`);
}
const wrangler = process.platform === 'win32' ? 'npx.cmd' : 'npx';
if (!dryRun && !baseUrl) fail('PRODUCTION_BASE_URL is required so post-deploy health cannot be skipped.');
if (dryRun) {
  runLocal('verify-environment.mjs');
  runLocal('verify-secrets.mjs');
  runLocal('verify-migrations.mjs');
  runLocal('verify-release.mjs');
  runLocal('create-release-manifest.mjs');
  runLocal('verify-manifest.mjs');
  runLocal('verify-reproducibility.mjs');
  runLocal('verify-artifact.mjs', { ARTIFACT_CHECK_ALLOW_MANIFEST: '1', ARTIFACT_CHECK_ALLOW_PRODUCTION: '1' });
  console.log('Local production pre-deploy verification: PASS');
}

if (!dryRun) {
  const preflight = spawnSync(wrangler, ['wrangler', 'whoami'], { stdio: 'inherit', env: process.env });
  if (preflight.error) fail(`Could not start Cloudflare authentication preflight: ${preflight.error.message}`);
  if (preflight.status !== 0) fail(`Cloudflare authentication preflight failed with exit code ${preflight.status}.`);
  const migrationList = spawnSync(wrangler, ['wrangler', 'd1', 'migrations', 'list', nameMatch[1], '--remote', '--config', config], { encoding: 'utf8', env: process.env });
  if (migrationList.error) fail(`Could not verify remote D1 migrations: ${migrationList.error.message}`);
  if (migrationList.status !== 0) fail(`Remote D1 migration preflight failed with exit code ${migrationList.status}.`);
  const secretCheck = spawnSync(wrangler, ['wrangler', 'secret', 'list', '--config', config], { encoding: 'utf8', env: process.env });
  if (secretCheck.error) fail(`Could not verify Wrangler secrets: ${secretCheck.error.message}`);
  if (secretCheck.status !== 0) fail(`Could not verify production Wrangler secrets (exit ${secretCheck.status}).`);
  let secrets;
  try { secrets = JSON.parse(secretCheck.stdout || '[]'); } catch { fail('Wrangler secret list returned invalid JSON.'); }
  if (!Array.isArray(secrets) || !secrets.some(x => x?.name === 'CURSOR_SECRET')) fail('Required production secret CURSOR_SECRET is not configured; refusing migration/deploy.');
}
const dbName = nameMatch[1];
const commands = [
  ['npx', ['wrangler', 'd1', 'migrations', 'apply', dbName, '--remote', '--config', config]],
  ['npx', ['wrangler', 'deploy', '--config', config]],
];
console.log(`Production target: ${dbName}`);
console.log(`Dry run: ${dryRun ? 'YES' : 'NO'}`);
console.log('CURSOR_SECRET: must already be configured as a Wrangler secret; it is never written to config.');
if (dryRun) {
  console.log(`Would run: ${commands[0][0]} ${commands[0][1].join(' ')}`);
  console.log(`Would run: ${commands[1][0]} ${commands[1][1].join(' ')}`);
  try { unlinkSync(path.join(root, 'RELEASE-MANIFEST.json')); } catch {}
  try { unlinkSync(config); } catch {}
  console.log('DRY_RUN=1: no Cloudflare command was executed.');
  process.exit(0);
}
for (const [, args] of commands) {
  const r = spawnSync(wrangler, args, { stdio: 'inherit', env: process.env });
  if (r.error) fail(`Could not start ${wrangler}: ${r.error.message}`);
  if (r.status !== 0) fail(`Cloudflare command failed with exit code ${r.status}.`);
}
for (const route of ['/api/health', '/api/health/db', '/api/health/config']) {
  const response = await fetch(`${baseUrl}${route}`, { headers: { Accept: 'application/json' } });
  const body = await response.text();
  console.log(`${route}: HTTP ${response.status} ${body}`);
  if (!response.ok) fail(`Post-deploy health failed for ${route}.`);
  if (route === '/api/health/db') {
    let json; try { json = JSON.parse(body); } catch { fail('Database health returned non-JSON.'); }
    if (json?.ok !== true || json?.database !== 'reachable' || json?.schema !== 'ready') fail('Database health is not reachable/schema-ready.');
  }
  if (route === '/api/health/config') {
    let json; try { json = JSON.parse(body); } catch { fail('Config health returned non-JSON.'); }
    if (json?.ok !== true || json?.environment !== 'production' || json?.checks?.cursor_secret !== true || json?.checks?.allowed_origins !== true) fail('Production config health is not ready.');
  }
}
console.log('Production deployment and health verification: PASS');
