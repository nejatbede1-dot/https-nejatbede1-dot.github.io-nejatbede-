import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const id = process.env.CLOUDFLARE_D1_DATABASE_ID?.trim();
const name = process.env.CLOUDFLARE_D1_DATABASE_NAME?.trim() || 'nejat-bede';
const origins = String(process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
const account = process.env.CLOUDFLARE_ACCOUNT_ID?.trim();

if (!id || !/^[a-zA-Z0-9_-]{8,}$/.test(id)) {
  console.error('Missing or invalid CLOUDFLARE_D1_DATABASE_ID. No production config was generated.');
  process.exit(2);
}
if (!origins.length) {
  console.error('Missing ALLOWED_ORIGINS. Production config requires at least one exact origin.');
  process.exit(2);
}
const config = `name = "nejat-bede-api"\nmain = "index.js"\ncompatibility_date = "2026-10-01"\n\n[vars]\nENVIRONMENT = "production"\nALLOWED_ORIGINS = "${origins.join(',').replaceAll('"', '')}"\n\n[[d1_databases]]\nbinding = "DB"\ndatabase_name = "${name.replaceAll('"', '')}"\ndatabase_id = "${id}"\nmigrations_dir = "../migrations"\n${account ? `\n# Account ID supplied for production preparation: ${account}\n` : ''}`;

const out = path.join(root, 'worker', 'wrangler.production.toml');
fs.writeFileSync(out, config);
console.log(`Generated ${out}`);
console.log('CURSOR_SECRET is intentionally NOT written to this file; configure it with Wrangler secrets before production traffic.');
