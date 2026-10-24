import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const expected = process.env.RELEASE_VERSION?.trim() || 'v211';
const files = [
  'README.md','package.json','test.mjs','test.integration.mjs','scripts/verify-environment.mjs','scripts/verify-secrets.mjs',
  'worker/index.js','worker/wrangler.toml',
  ...fs.readdirSync(path.join(root, 'migrations')).filter(n => /^\d+_[A-Za-z0-9._-]+\.sql$/.test(n)).sort((a,b) => Number(a.split('_')[0])-Number(b.split('_')[0]) || a.localeCompare(b)).map(n => `migrations/${n}`),
  'scripts/prepare-staging.mjs','scripts/deploy-staging.mjs','scripts/prepare-production.mjs','scripts/deploy-production.mjs',
  'scripts/verify-migrations.mjs','scripts/verify-release.mjs','scripts/verify-artifact.mjs',
  'scripts/create-release-manifest.mjs','scripts/verify-manifest.mjs','scripts/verify-reproducibility.mjs'
];
function sha256(rel) {
  const p = path.join(root, rel);
  if (!fs.existsSync(p) || !fs.statSync(p).isFile()) throw new Error(`Missing release file: ${rel}`);
  return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}
function canonical() {
  return JSON.stringify({
    schema: 1,
    version: expected,
    files: Object.fromEntries(files.map(f => [f, sha256(f)]))
  }, null, 2) + '\n';
}
const first = canonical();
const second = canonical();
if (first !== second) {
  console.error('ERROR: Release manifest generation is not deterministic.');
  process.exit(2);
}
const manifest = path.join(root, 'RELEASE-MANIFEST.json');
if (fs.existsSync(manifest) && fs.readFileSync(manifest, 'utf8') !== first) {
  console.error('ERROR: Existing RELEASE-MANIFEST.json does not match deterministic release content.');
  process.exit(2);
}
console.log(`Reproducibility verification: PASS (${expected}; ${files.length} hashed files; deterministic manifest)`);
