import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const expected = process.env.RELEASE_VERSION?.trim() || 'v211';
function fail(message) { console.error(`ERROR: ${message}`); process.exit(2); }

const requiredFiles = [
  'README.md', 'package.json', 'test.mjs', 'test.integration.mjs',
  'worker/index.js', 'worker/wrangler.toml',
  'migrations/0001_initial.sql', 'migrations/0002_auth.sql', 'migrations/0003_orders.sql','migrations/0004_order_idempotency.sql','migrations/0005_idempotency_fingerprint.sql', 'migrations/0006_session_lifecycle.sql', 'migrations/0007_session_cap.sql', 'migrations/0008_order_status_lifecycle.sql', 'migrations/0009_numeric_integrity.sql', 'migrations/0010_order_item_lifecycle.sql', 'migrations/0011_order_review_lifecycle.sql', 'migrations/0012_order_status_audit.sql', 'migrations/0013_payment_lifecycle.sql', 'migrations/0014_payment_status_audit.sql', 'migrations/0015_session_cap_db_guard.sql', 'migrations/0016_security_audit.sql',
  'scripts/prepare-staging.mjs', 'scripts/deploy-staging.mjs', 'scripts/prepare-production.mjs', 'scripts/deploy-production.mjs',
  'scripts/verify-migrations.mjs', 'scripts/verify-release.mjs', 'scripts/verify-artifact.mjs', 'scripts/create-release-manifest.mjs', 'scripts/verify-manifest.mjs', 'scripts/verify-reproducibility.mjs'
];
for (const rel of requiredFiles) {
  const p = path.join(root, rel);
  if (!fs.existsSync(p) || (fs.statSync(p).isFile() && fs.statSync(p).size === 0)) fail(`Required artifact missing or empty: ${rel}`);
}
const forbidden = ['worker/wrangler.staging.toml', 'worker/wrangler.production.toml', '.env', '.env.local', '.dev.vars', 'RELEASE-MANIFEST.json'];
const allowStagingConfigForDeploy = process.env.ARTIFACT_CHECK_ALLOW_STAGING === '1';
const allowProductionConfigForDryRun = process.env.ARTIFACT_CHECK_ALLOW_PRODUCTION === '1';
const allowManifestForDeploy = process.env.ARTIFACT_CHECK_ALLOW_MANIFEST === '1';
for (const rel of forbidden) {
  if (rel === 'worker/wrangler.staging.toml' && allowStagingConfigForDeploy) continue;
  if (rel === 'worker/wrangler.production.toml' && allowProductionConfigForDryRun) continue;
  if (rel === 'RELEASE-MANIFEST.json' && allowManifestForDeploy) continue;
  if (fs.existsSync(path.join(root, rel))) fail(`Sensitive/generated file must not be packaged: ${rel}`);
}
const source = fs.readFileSync(path.join(root, 'worker/index.js'), 'utf8');
if (!source.includes(`version: '${expected}'`) && !source.includes(`version: "${expected}"`)) fail(`Worker version mismatch: expected ${expected}.`);
const test = fs.readFileSync(path.join(root, 'test.mjs'), 'utf8');
if (!test.includes(`j.version!=='${expected}'`) && !test.includes(`j.version!=="${expected}"`)) fail(`Contract test version mismatch: expected ${expected}.`);
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
if (pkg.name !== 'nejat-bede-cloudflare' || pkg.private !== true) fail('package.json release metadata is invalid.');
console.log(`Artifact verification: PASS (${expected}; ${requiredFiles.length} required files; sensitive staging files absent)`);
