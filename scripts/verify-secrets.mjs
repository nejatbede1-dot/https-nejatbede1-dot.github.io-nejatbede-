import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const forbiddenNames = /^(?:\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx))$/i;
const ignoredDirs = new Set(['node_modules', '.git', '.wrangler', 'dist', 'coverage']);
const textExt = new Set(['.js','.mjs','.json','.toml','.md','.sql','.html','.txt','.yml','.yaml','.sh']);
const secretPatterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/i,
  /\b(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN|CLOUDFLARE_API_KEY|AWS_SECRET_ACCESS_KEY|DATABASE_PASSWORD|DB_PASSWORD)\s*=\s*[^\s#]+/i,
  /\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|private[_-]?key)\s*[:=]\s*["']?(?!\$\{|<|CHANGE_ME|REPLACE_ME|YOUR_|example|dummy|test)[A-Za-z0-9_./+=:-]{16,}["']?/i,
];
function fail(message) { console.error(`ERROR: ${message}`); process.exit(2); }
function walk(dir, out=[]) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ignoredDirs.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}
for (const file of walk(root)) {
  const rel = path.relative(root, file).replaceAll('\\','/');
  if (forbiddenNames.test(path.basename(file))) fail(`Forbidden secret-like file is present: ${rel}`);
  if (rel === 'RELEASE-MANIFEST.json') continue;
  const ext = path.extname(file).toLowerCase();
  if (!textExt.has(ext)) continue;
  const content = fs.readFileSync(file, 'utf8');
  for (const pattern of secretPatterns) {
    if (pattern.test(content)) fail(`Potential secret detected in ${rel} (pattern ${pattern}).`);
  }
}
console.log('Secret/config hygiene verification: PASS');
