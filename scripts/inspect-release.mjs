// Fails when a release would carry private material or build debris.
//   node scripts/inspect-release.mjs            what git would publish (tracked + untracked, not ignored)
//   node scripts/inspect-release.mjs --dir DIR  every file under DIR, e.g. an extracted archive
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const FORBIDDEN_NAME = /(^|\/)(\.git|target|node_modules|\.arena-local|\.old|\.env[^/]*|id_[a-z0-9]+|[^/]*\.(pem|key|p12|pfx|jks|keystore|identity|pending|secret))$/i;
const FORBIDDEN_DIR = /(^|\/)(\.git|target|node_modules|\.arena-local|\.old|\.gv-demo-[^/]*)(\/|$)/i;
const PRIVATE_BLOCK = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
const MAX_SCAN_BYTES = 8 * 1024 * 1024;

function listPublished() {
  const out = execFileSync('git', ['ls-files', '-z', '-c', '-o', '--exclude-standard'], {
    encoding: 'utf8',
    maxBuffer: 1 << 28,
  });
  return out.split('\0').filter(Boolean).filter((f) => fs.existsSync(f));
}

function walk(dir, base = dir, acc = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(base, full).split(path.sep).join('/');
    if (entry.isDirectory()) {
      if (FORBIDDEN_DIR.test(rel)) acc.push(rel + '/');
      else walk(full, base, acc);
    } else acc.push(rel);
  }
  return acc;
}

const dirFlag = process.argv.indexOf('--dir');
const root = dirFlag > 0 ? process.argv[dirFlag + 1] : process.cwd();
const files = dirFlag > 0 ? walk(root) : listPublished();
const problems = [];

for (const rel of files) {
  if (rel.endsWith('/') || FORBIDDEN_NAME.test(rel) || FORBIDDEN_DIR.test(rel)) {
    problems.push(`forbidden path: ${rel}`);
    continue;
  }
  const full = path.join(root, rel);
  const size = fs.statSync(full).size;
  if (size > MAX_SCAN_BYTES) continue;
  const text = fs.readFileSync(full).toString('latin1');
  if (PRIVATE_BLOCK.test(text)) problems.push(`private key material inside: ${rel}`);
}

if (problems.length) {
  console.error(`FAIL: release inspection found ${problems.length} problem(s):`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(`PASS: release inspection checked ${files.length} file(s); no private material, VCS data or build output.`);
