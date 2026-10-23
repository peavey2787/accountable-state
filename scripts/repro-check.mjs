// Builds the release C ABI library twice from the same commit in separate target directories and
// fails unless the two outputs are byte-identical. Local paths are remapped so the checkout location
// cannot leak into the binary.
//   node scripts/repro-check.mjs
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const root = process.cwd();
const library = process.platform === 'win32' ? 'gv_capi.dll' : process.platform === 'darwin' ? 'libgv_capi.dylib' : 'libgv_capi.so';
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'gv-repro-'));

function build(label) {
  const target = path.join(scratch, label);
  const env = {
    ...process.env,
    CARGO_TARGET_DIR: target,
    RUSTFLAGS: `--remap-path-prefix=${root}=/src --remap-path-prefix=${os.homedir()}=/home`,
    ...(process.platform === 'win32' ? { RUSTFLAGS: `--remap-path-prefix=${root}=/src --remap-path-prefix=${os.homedir()}=/home -C link-arg=/Brepro` } : {}),
  };
  execFileSync('cargo', ['build', '--release', '--locked', '-p', 'gv-capi'], { env, stdio: 'inherit' });
  return crypto.createHash('sha256').update(fs.readFileSync(path.join(target, 'release', library))).digest('hex');
}

const [first, second] = [build('a'), build('b')];
fs.rmSync(scratch, { recursive: true, force: true });
if (first !== second) {
  console.error(`FAIL: the release build is not reproducible\n  ${first}\n  ${second}`);
  process.exit(1);
}
console.log(`PASS: two independent release builds of ${library} are byte-identical (${first})`);
