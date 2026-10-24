import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);
const config = path.join(root, 'worker', 'wrangler.production.toml');
function fail(message) { console.error(`ERROR: ${message}`); process.exit(2); }
if (!existsSync(config)) fail('Missing worker/wrangler.production.toml. Run "npm run prepare:production" first.');
const toml = readFileSync(config, 'utf8');
const id = toml.match(/^database_id\s*=\s*"([^"]+)"/m)?.[1];
const name = toml.match(/^database_name\s*=\s*"([^"]+)"/m)?.[1];
if (!id || !/^[A-Za-z0-9_-]{8,}$/.test(id)) fail('Production config has no valid D1 database_id.');
if (!name) fail('Production config has no database_name.');
const wrangler = process.platform === 'win32' ? 'npx.cmd' : 'npx';
function run(args, label) {
  const r = spawnSync(wrangler, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: process.env });
  if (r.error) fail(`${label} could not start: ${r.error.message}`);
  if (r.status !== 0) fail(`${label} failed with exit code ${r.status}. ${String(r.stderr || '').trim()}`);
  return r.stdout || '';
}
run(['wrangler', 'whoami'], 'Cloudflare authentication preflight');
run(['wrangler', 'd1', 'migrations', 'list', name, '--remote', '--config', config], 'Remote D1 migration preflight');
console.log(`Production preflight: PASS (${name})`);
