import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(projectRoot);

const config = path.join(projectRoot, 'worker', 'wrangler.staging.toml');
const migrations = path.join(projectRoot, 'migrations');
const baseUrl = process.env.STAGING_BASE_URL?.replace(/\/$/, '');
const dryRun = process.env.DRY_RUN === '1' || process.env.DEPLOY_DRY_RUN === '1' || process.argv.includes('--dry-run');

function fail(message) {
  console.error(`ERROR: ${message}`);
  process.exit(2);
}

if (!existsSync(config)) {
  fail(`Missing ${config}. Run "npm run prepare:staging" first.`);
}
if (!existsSync(migrations)) {
  fail(`Missing ${migrations}/ directory.`);
}

const toml = readFileSync(config, 'utf8');
const idMatch = toml.match(/^database_id\s*=\s*"([^"]+)"/m);
const nameMatch = toml.match(/^database_name\s*=\s*"([^"]+)"/m);
if (!idMatch || !/^[A-Za-z0-9_-]{8,}$/.test(idMatch[1])) {
  fail('Staging config has no valid D1 database_id. Refusing to deploy.');
}
if (!nameMatch || !nameMatch[1]) {
  fail('Staging config has no database_name. Refusing to deploy.');
}

const dbName = nameMatch[1];
const wrangler = process.platform === 'win32' ? 'npx.cmd' : 'npx';
const secretsArgs = [path.join(projectRoot, 'scripts', 'verify-secrets.mjs')];
const releaseArgs = [path.join(projectRoot, 'scripts', 'verify-release.mjs')];
const verifyArgs = [path.join(projectRoot, 'scripts', 'verify-migrations.mjs')];
const artifactArgs = [path.join(projectRoot, 'scripts', 'verify-artifact.mjs')];
const reproducibilityArgs = [path.join(projectRoot, 'scripts', 'verify-reproducibility.mjs')];
const manifestArgs = [path.join(projectRoot, 'scripts', 'create-release-manifest.mjs')];
const manifestVerifyArgs = [path.join(projectRoot, 'scripts', 'verify-manifest.mjs')];
const migrationArgs = ['wrangler', 'd1', 'migrations', 'apply', dbName, '--remote', '--config', config];
const deployArgs = ['wrangler', 'deploy', '--config', config];

console.log(`Staging target: ${dbName}`);
console.log(`Secret/config verification: node ${secretsArgs.join(' ')}`);
console.log(`Release verification: node ${releaseArgs.join(' ')}`);
console.log(`Migration verification: node ${verifyArgs.join(' ')}`);
console.log(`Artifact verification: node ${artifactArgs.join(' ')}`);
console.log(`Reproducibility verification: node ${reproducibilityArgs.join(' ')}`);
console.log(`Release manifest: node ${manifestArgs.join(' ')}`);
console.log(`Manifest verification: node ${manifestVerifyArgs.join(' ')}`);
console.log(`Migration command: npx ${migrationArgs.join(' ')}`);
console.log(`Deploy command: npx ${deployArgs.join(' ')}`);

const secretsCheck = spawnSync(process.execPath, secretsArgs, { stdio: 'inherit', env: process.env });
if (secretsCheck.error || secretsCheck.status !== 0) fail('Secret/config hygiene verification failed.');

if (dryRun) {
  const manifestCheck = spawnSync(process.execPath, manifestArgs, { stdio: 'inherit', env: process.env });
  if (manifestCheck.error || manifestCheck.status !== 0) fail('Release manifest generation failed.');
  const manifestVerify = spawnSync(process.execPath, manifestVerifyArgs, { stdio: 'inherit', env: process.env });
  if (manifestVerify.error || manifestVerify.status !== 0) fail('Release manifest verification failed.');
  const reproducibilityCheck = spawnSync(process.execPath, reproducibilityArgs, { stdio: 'inherit', env: process.env });
  if (reproducibilityCheck.error || reproducibilityCheck.status !== 0) fail('Release reproducibility verification failed.');
  const releaseCheck = spawnSync(process.execPath, releaseArgs, { stdio: 'inherit', env: process.env });
  if (releaseCheck.error || releaseCheck.status !== 0) fail('Release verification failed.');
  const artifactCheck = spawnSync(process.execPath, artifactArgs, { stdio: 'inherit', env: { ...process.env, ARTIFACT_CHECK_ALLOW_STAGING: '1', ARTIFACT_CHECK_ALLOW_MANIFEST: '1' } });
  if (artifactCheck.error || artifactCheck.status !== 0) fail('Artifact verification failed.');
  const check = spawnSync(process.execPath, verifyArgs, { stdio: 'inherit', env: process.env });
  if (check.error || check.status !== 0) fail('Migration verification failed.');
  console.log('DRY_RUN=1: no Cloudflare command was executed.')
  process.exit(0);
}

function runNode(args) {
  const result = spawnSync(process.execPath, args, { stdio: 'inherit', env: process.env });
  if (result.error) fail(`Could not start Node: ${result.error.message}`);
  if (result.status !== 0) fail(`Command failed with exit code ${result.status}.`);
}

function runWrangler(args) {
  const result = spawnSync(wrangler, args, { stdio: 'inherit', env: process.env });
  if (result.error) fail(`Could not start ${wrangler}: ${result.error.message}`);
  if (result.status !== 0) fail(`Command failed with exit code ${result.status}.`);
}

runNode(manifestArgs);
runNode(manifestVerifyArgs);
runNode(reproducibilityArgs);
runNode(releaseArgs);
runNode(artifactArgs);
runNode(verifyArgs);
runWrangler(migrationArgs);
runWrangler(deployArgs);

if (!baseUrl) {
  fail('STAGING_BASE_URL is required for a real staging deployment so post-deploy health cannot be silently skipped.');
}

for (const path of ['/api/health', '/api/health/db']) {
  const url = `${baseUrl}${path}`;
  console.log(`Verifying ${url}`);
  try {
    const response = await fetch(url, { headers: { Accept: 'application/json' } });
    const body = await response.text();
    console.log(`${path}: HTTP ${response.status} ${body}`);
    if (!response.ok) fail(`Health verification failed for ${path}.`);
    if (path === '/api/health/db') {
      let parsed;
      try { parsed = JSON.parse(body); } catch { fail(`Health verification returned non-JSON for ${path}.`); }
      if (parsed?.ok !== true || parsed?.database !== 'reachable' || parsed?.schema !== 'ready') fail(`Database health check did not report reachable and schema-ready for ${path}.`);
    }
  } catch (error) {
    fail(`Health verification failed for ${path}: ${error.message}`);
  }
}

console.log('Staging deployment and health verification: PASS');
