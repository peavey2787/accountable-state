// Release evidence for the committed tree: provenance, a CycloneDX SBOM from the lockfile, and
// checksums of the source archive plus any built artifacts named on the command line.
//   node scripts/release-manifest.mjs [--out DIR] [ARTIFACT ...]
// Artifacts are also scanned for private key blocks and embedded local build paths.
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const run = (cmd, args) => execFileSync(cmd, args, { encoding: 'utf8', maxBuffer: 1 << 29 }).trim();
const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');
const PRIVATE_BLOCK = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
const LOCAL_PATH = /(?:[A-Za-z]:\Users\|\/home\/|\/Users\/)[A-Za-z0-9._-]+/;

const argv = process.argv.slice(2);
const outFlag = argv.indexOf('--out');
const outDir = outFlag >= 0 ? argv.splice(outFlag, 2)[1] : 'target/release-evidence';
const artifacts = argv;

if (run('git', ['status', '--porcelain']) !== '') {
  console.error('FAIL: the working tree is not clean; release evidence must describe a commit');
  process.exit(1);
}
const commit = run('git', ['rev-parse', 'HEAD']);
const commitTime = Number(run('git', ['show', '-s', '--format=%ct', 'HEAD']));
fs.mkdirSync(outDir, { recursive: true });

const lock = fs.readFileSync('Cargo.lock');
const checksums = new Map();
for (const block of lock.toString('utf8').split('[[package]]')) {
  const name = /name = "([^"]+)"/.exec(block)?.[1];
  const version = /version = "([^"]+)"/.exec(block)?.[1];
  const sum = /checksum = "([0-9a-f]{64})"/.exec(block)?.[1];
  if (name && version && sum) checksums.set(`${name}@${version}`, sum);
}

const meta = JSON.parse(run('cargo', ['metadata', '--locked', '--format-version', '1']));
const components = meta.packages.map((p) => {
  const sum = checksums.get(`${p.name}@${p.version}`);
  return {
    type: 'library',
    'bom-ref': `pkg:cargo/${p.name}@${p.version}`,
    name: p.name,
    version: p.version,
    purl: `pkg:cargo/${p.name}@${p.version}`,
    ...(p.license ? { licenses: [{ expression: p.license }] } : {}),
    ...(sum ? { hashes: [{ alg: 'SHA-256', content: sum }] } : {}),
  };
});
const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: { timestamp: new Date(commitTime * 1000).toISOString(), component: { type: 'application', name: path.basename(process.cwd()), version: commit } },
  components,
};
fs.writeFileSync(path.join(outDir, 'sbom.cdx.json'), JSON.stringify(sbom, null, 2) + '\n');

const source = execFileSync('git', ['archive', '--format=tar', 'HEAD'], { maxBuffer: 1 << 30 });
const sums = [[`source-${commit}.tar`, sha256(source)], ['Cargo.lock', sha256(lock)]];
const problems = [];
for (const file of artifacts) {
  const bytes = fs.readFileSync(file);
  sums.push([path.basename(file), sha256(bytes)]);
  const text = bytes.toString('latin1');
  if (PRIVATE_BLOCK.test(text)) problems.push(`private key material inside: ${file}`);
  const leak = LOCAL_PATH.exec(text);
  if (leak) problems.push(`local build path embedded in: ${file} (${leak[0]})`);
}
fs.writeFileSync(path.join(outDir, 'SHA256SUMS'), sums.map(([n, h]) => `${h}  ${n}`).join('\n') + '\n');

const provenance = {
  commit,
  commitTime: new Date(commitTime * 1000).toISOString(),
  lockfileSha256: sha256(lock),
  rustc: run('rustc', ['-vV']).split('\n'),
  cargo: run('cargo', ['-V']),
  builder: `${process.platform}-${process.arch}`,
  artifacts: Object.fromEntries(sums),
  scanProblems: problems,
};
fs.writeFileSync(path.join(outDir, 'provenance.json'), JSON.stringify(provenance, null, 2) + '\n');

if (problems.length) {
  console.error(`FAIL: ${problems.length} artifact problem(s):`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(`PASS: release evidence for ${commit.slice(0, 12)} in ${outDir}: ${components.length} SBOM components, ${sums.length} checksums, ${artifacts.length} artifact(s) scanned.`);
