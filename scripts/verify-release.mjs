import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const expected = process.env.RELEASE_VERSION?.trim() || 'v211';
function fail(message) { console.error(`ERROR: ${message}`); process.exit(2); }
for (const file of [path.join(root,'worker','index.js'), path.join(root,'migrations'), path.join(root,'package.json'), path.join(root,'scripts','create-release-manifest.mjs'), path.join(root,'scripts','verify-manifest.mjs')]) if (!fs.existsSync(file)) fail(`Required release path is missing: ${file}`);
const pkg = JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
if (pkg.version !== '0.0.211') fail(`package.json version must match the current release; found ${pkg.version}.`);
const source = fs.readFileSync(path.join(root,'worker','index.js'),'utf8');
if (![`version:'${expected}'`,`version: '${expected}'`,`version:"${expected}"`,`version: "${expected}"`].some(x=>source.includes(x))) fail(`Worker does not declare expected release version ${expected}.`);
const dir=path.join(root,'migrations'); const files=fs.readdirSync(dir).filter(n=>/^\d+_[A-Za-z0-9._-]+\.sql$/.test(n)).sort((a,b)=>Number(a.split('_')[0])-Number(b.split('_')[0])||a.localeCompare(b));
if(!files.length) fail('No migrations found.');
for(let i=0;i<files.length;i++){const n=Number(files[i].split('_')[0]); if(n!==i+1) fail(`Migration sequence invalid at ${files[i]}.`); if(!fs.readFileSync(path.join(dir,files[i]),'utf8').trim()) fail(`Migration ${files[i]} is empty.`);}
console.log(`Release verification: PASS (${expected}; ${files.length} migrations)`);
