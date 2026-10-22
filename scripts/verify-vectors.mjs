// Independent Node.js golden-vector implementation (not a substitute for Rust tests).
// Run from any directory: node scripts/verify-vectors.mjs
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const selfDir = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(resolve(selfDir, '../tests/interoperability/merkle_sha256_v1.json'),'utf8'));
const le64 = n => { const b=Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const digest = (...parts) => { const h=createHash('sha256'); for(const b of parts)h.update(b);return h.digest(); };
const leaf = x => digest(Buffer.from('gv/leaf/v1\0'), le64(x.length), x);
const node = (a,b) => digest(Buffer.from('gv/node/v1\0'),a,b);
const root = (len,top)=>digest(Buffer.from('gv/root/v1\0'),le64(len),top);
function assertHex(actual, expected, label){
 if(actual.toString('hex')!==expected) throw Error(`FAIL ${label}: ${actual.toString('hex')} != ${expected}`);
}
const alpha=Buffer.from('alpha');
assertHex(root(0,digest(Buffer.from('gv/empty/v1\0'))),vectors.empty_root,'empty root');
assertHex(root(1,leaf(alpha)),vectors.single_alpha_root,'one leaf');
const msgs=vectors.three_records_hex.map(x=>Buffer.from(x,'hex'));
const leaves=msgs.map(leaf);
for(let i=0;i<3;i++)assertHex(leaves[i],vectors.three_leaves[i],`leaf ${i}`);
const siblingRoot=node(node(leaves[0],leaves[1]),node(leaves[2],leaves[2]));
assertHex(root(3,siblingRoot),vectors.three_root,'odd tree root');
const proof=vectors.proof_index_2;
if(proof.index!==2||proof.leaf_count!==3||proof.siblings.length!==2)throw Error('invalid vector proof');
assertHex(leaves[2],proof.siblings[0],'odd leaf sibling');
assertHex(node(leaves[0],leaves[1]),proof.siblings[1],'proof parent sibling');
if(root(3,node(Buffer.from(proof.siblings[1],'hex'),node(leaves[2],Buffer.from(proof.siblings[0],'hex')))).toString('hex')!==vectors.three_root)throw Error('proof verification failed');
if(root(3,node(Buffer.from(proof.siblings[1],'hex'),node(leaf(Buffer.from('tampered')),leaves[2]))).toString('hex')===vectors.three_root)throw Error('false inclusion accepted');
console.log('PASS: independent Node SHA-256/Merkle root and membership vectors, tampered leaf rejected');

// Independent ML-DSA-65 reference: the Rust implementation's exact signed bytes, player id,
// envelope digest and signature, re-derived here and verified by OpenSSL (not hydra-crypto).
import { opensslHasMlDsa, verifyMlDsa65 } from './lib-mldsa.mjs';
if (!opensslHasMlDsa()) {
  console.log('SKIP: system OpenSSL has no ML-DSA-65 (need >= 3.5); signature vectors not checked');
  process.exit(0);
}
const signed = JSON.parse(readFileSync(resolve(selfDir, '../tests/interoperability/signed_mldsa65_v1.json'),'utf8'));
const vk = Buffer.from(signed.verifying_key_hex,'hex');
if (vk.length !== 1952) throw Error('bad ML-DSA-65 verifying key length');
// ParticipantId = SHA-256("gv/player-id/v1\0" || alg(1) || vk)
assertHex(digest(Buffer.from('gv/player-id/v1\0'), Buffer.from([1]), vk), signed.player_id_hex, 'player id');
// Envelope = SHA-512("gv/sig-envelope\0" || [version, alg] || u16 label_len || label || signer || u64 body_len || body)
const body = Buffer.from(signed.body_hex,'hex');
const label = Buffer.from(signed.label);
const u16 = n => { const b=Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const envelope = createHash('sha512').update(Buffer.from('gv/sig-envelope\0')).update(Buffer.from([1,1])).update(u16(label.length))
  .update(label).update(Buffer.from(signed.player_id_hex,'hex')).update(le64(body.length)).update(body).digest();
assertHex(envelope, signed.envelope_digest_hex, 'signature envelope digest');
const signature = Buffer.from(signed.signature_hex,'hex');
if (signature.length !== 3309) throw Error('bad ML-DSA-65 signature length');
if (!verifyMlDsa65(vk, envelope, signature)) throw Error('OpenSSL rejected the Rust ML-DSA-65 signature');
const badDigest = Buffer.from(envelope); badDigest[0] ^= 1;
if (verifyMlDsa65(vk, badDigest, signature)) throw Error('tampered message accepted');
const badSig = Buffer.from(signature); badSig[100] ^= 1;
if (verifyMlDsa65(vk, envelope, badSig)) throw Error('tampered signature accepted');
const otherVk = Buffer.from(vk); otherVk[10] ^= 1;
if (verifyMlDsa65(otherVk, envelope, signature)) throw Error('wrong key accepted');
console.log('PASS: independent OpenSSL ML-DSA-65 verification of the Rust signature, player id, envelope digest; tamper/wrong-key rejected');
