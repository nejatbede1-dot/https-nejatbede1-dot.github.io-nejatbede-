import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const major = Number(process.versions.node.split('.')[0]);
const requiredMajor = 20;
if (!Number.isInteger(major) || major < requiredMajor) {
  console.error(`ERROR: Node.js ${requiredMajor}+ is required; found ${process.versions.node}.`);
  process.exit(2);
}
if (pkg.engines?.node !== '>=20.0.0') {
  console.error('ERROR: package.json must declare engines.node as >=20.0.0.');
  process.exit(2);
}
if (!pkg.devDependencies?.wrangler?.startsWith('^4.')) {
  console.error('ERROR: Wrangler 4.x is required by the v179 release contract.');
  process.exit(2);
}
console.log(`Environment verification: PASS (Node ${process.versions.node}; Wrangler ${pkg.devDependencies.wrangler})`);
