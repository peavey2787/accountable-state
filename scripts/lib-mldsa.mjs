// Independent ML-DSA-65 (FIPS 204) verification through the system OpenSSL (>= 3.5),
// i.e. a second implementation that shares no code with hydra-crypto.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// SubjectPublicKeyInfo header for id-ml-dsa-65 (2.16.840.1.101.3.4.3.18), 1952-byte key.
const SPKI_HEADER = Buffer.from('308207b2300b0609608648016503040312038207a100', 'hex');

export function opensslHasMlDsa() {
  try {
    const out = execFileSync('openssl', ['list', '-signature-algorithms'], { encoding: 'utf8' });
    return /ML-DSA-65/i.test(out);
  } catch { return false; }
}

export function verifyMlDsa65(vk, message, signature) {
  const dir = mkdtempSync(join(tmpdir(), 'gv-mldsa-'));
  try {
    writeFileSync(join(dir, 'k.der'), Buffer.concat([SPKI_HEADER, vk]));
    writeFileSync(join(dir, 'm'), message);
    writeFileSync(join(dir, 's'), signature);
    execFileSync('openssl', ['pkeyutl', '-verify', '-pubin', '-inkey', join(dir, 'k.der'),
      '-keyform', 'DER', '-rawin', '-in', join(dir, 'm'), '-sigfile', join(dir, 's')], { stdio: 'pipe' });
    return true;
  } catch { return false; }
  finally { rmSync(dir, { recursive: true, force: true }); }
}
