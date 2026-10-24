import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const id = process.env.CLOUDFLARE_D1_DATABASE_ID?.trim();
const name = process.env.CLOUDFLARE_D1_DATABASE_NAME?.trim() || 'nejat-bede';
const account = process.env.CLOUDFLARE_ACCOUNT_ID?.trim();

if (!id || !/^[a-zA-Z0-9_-]{8,}$/.test(id)) {
  console.error('Missing or invalid CLOUDFLARE_D1_DATABASE_ID. No staging config was generated.');
  process.exit(2);
}

const accountLine = account ? `\n# Account ID supplied for staging preparation: ${account}` : '';
const config = `name = "nejat-bede-api"\nmain = "index.js"\ncompatibility_date = "2026-10-01"\n\n[vars]\nENVIRONMENT = "staging"\n\n[[d1_databases]]\nbinding = "DB"\ndatabase_name = "${name.replaceAll('"', '')}"\ndatabase_id = "${id}"\nmigrations_dir = "../migrations"\n${accountLine}`;

const out = path.join(projectRoot, 'worker', 'wrangler.staging.toml');
fs.writeFileSync(out, config);
console.log(`Generated ${out}`);
console.log('Next: npx wrangler d1 migrations apply ' + name + ' --remote --config worker/wrangler.staging.toml');
console.log('Then: npx wrangler deploy --config worker/wrangler.staging.toml');
