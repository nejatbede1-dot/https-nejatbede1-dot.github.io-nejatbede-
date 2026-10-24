import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(scriptDir, '..');
const requested = process.env.MIGRATIONS_DIR?.trim() || 'migrations';
const dir = path.isAbsolute(requested) ? requested : path.resolve(projectRoot, requested);

function fail(message) {
  console.error(`ERROR: ${message}`);
  process.exit(2);
}

if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) fail(`Migration directory not found: ${dir}`);

const files = fs.readdirSync(dir, { withFileTypes: true })
  .filter(x => x.isFile() && /^\d+_[A-Za-z0-9._-]+\.sql$/.test(x.name))
  .map(x => x.name)
  .sort((a,b) => Number(a.split('_')[0]) - Number(b.split('_')[0]) || a.localeCompare(b));

if (!files.length) fail(`No numbered SQL migrations found in ${dir}.`);

const numbers = files.map(f => Number(f.split('_')[0]));
for (let i = 0; i < numbers.length; i++) {
  const expected = i + 1;
  if (numbers[i] !== expected) fail(`Migration sequence gap/duplicate: expected ${String(expected).padStart(4,'0')}, found ${String(numbers[i]).padStart(4,'0')}.`);
}

for (const file of files) {
  const sql = fs.readFileSync(path.join(dir, file), 'utf8').trim();
  if (!sql) fail(`Migration ${file} is empty.`);
}

console.log(`Migration verification: PASS (${files.length} migrations, ${files.join(', ')})`);
