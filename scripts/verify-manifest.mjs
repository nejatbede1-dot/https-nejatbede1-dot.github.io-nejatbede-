import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const expected=process.env.RELEASE_VERSION?.trim()||'v211';
const mf=path.join(root,'RELEASE-MANIFEST.json');
function fail(m){console.error(`ERROR: ${m}`);process.exit(2)}
if(!fs.existsSync(mf)) fail('RELEASE-MANIFEST.json is missing.');
let data; try{data=JSON.parse(fs.readFileSync(mf,'utf8'))}catch{fail('Release manifest is invalid JSON.')}
if(data?.schema!==1||data?.version!==expected||!data?.files||typeof data.files!=='object') fail(`Release manifest metadata mismatch for ${expected}.`);
for(const [rel,hash] of Object.entries(data.files)){
 const p=path.join(root,rel);
 if(!fs.existsSync(p)||!fs.statSync(p).isFile()) fail(`Manifest file missing: ${rel}`);
 const actual=crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
 if(actual!==hash) fail(`SHA-256 mismatch: ${rel}`);
}
console.log(`Release manifest verification: PASS (${expected}; ${Object.keys(data.files).length} files)`);
