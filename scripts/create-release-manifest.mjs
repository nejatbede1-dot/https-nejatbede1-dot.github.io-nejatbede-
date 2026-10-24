import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const expected = process.env.RELEASE_VERSION?.trim() || 'v211';
const output = path.join(root, 'RELEASE-MANIFEST.json');
const files = [
  'README.md','package.json','test.mjs','test.integration.mjs','scripts/verify-environment.mjs','scripts/verify-secrets.mjs',
  'worker/index.js','worker/wrangler.toml',
  'migrations/0001_initial.sql', ...fs.readdirSync(path.join(root, 'migrations')).filter(n => /^\d+_[A-Za-z0-9._-]+\.sql$/.test(n)).sort((a,b) => Number(a.split('_')[0])-Number(b.split('_')[0]) || a.localeCompare(b)).map(n => `migrations/${n}`),
  'scripts/prepare-staging.mjs','scripts/deploy-staging.mjs','scripts/prepare-production.mjs','scripts/deploy-production.mjs',
  'scripts/verify-migrations.mjs','scripts/verify-release.mjs','scripts/verify-artifact.mjs',
  'scripts/create-release-manifest.mjs','scripts/verify-manifest.mjs','scripts/verify-reproducibility.mjs'
];
function sha256(rel) {
  const p=path.join(root,rel);
  if(!fs.existsSync(p) || !fs.statSync(p).isFile()) throw new Error(`Missing release file: ${rel}`);
  return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}
const manifest={schema:1,version:expected,files:Object.fromEntries(files.map(f=>[f,sha256(f)]))};
fs.writeFileSync(output, JSON.stringify(manifest,null,2)+'\n');
console.log(`Release manifest written: ${path.relative(root,output)} (${files.length} files; ${expected})`);
