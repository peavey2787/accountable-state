// Independent Node.js reference for GVEC/GVAG/GVKC v1. No Rust or third-party modules.
// Verifies canonical wire layout and the committed ML-DSA-65 signature/hash vectors (OpenSSL as the second signer implementation).
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const sha = b => createHash('sha256').update(b).digest();
const bits = (b,v) => {const x=Buffer.alloc(b); if(b===8)x.writeBigUInt64LE(BigInt(v));else if(b===4)x.writeUInt32LE(v);else if(b===2)x.writeUInt16LE(v);else x[0]=v;return x;};
const vuint = x => {const a=[];do {let b=x%128;x=Math.floor(x/128);if(x)b|=128;a.push(b);}while(x);return Buffer.from(a);};
const concat = (...xs)=>Buffer.concat(xs);
const domain = name => Buffer.from(name+'\0');
import { opensslHasMlDsa, verifyMlDsa65 } from './lib-mldsa.mjs';
const golden = JSON.parse(readFileSync(new URL('../tests/interoperability/packed_controls_v1.json',import.meta.url),'utf8'));
const vk = Buffer.from(golden.verifying_key_hex,'hex');
const player = sha(concat(domain('gv/player-id/v1'),Buffer.from([1]),vk));
assert.equal(player.toString('hex'),golden.player_id_hex);
const SIG_LEN = 3309;
const u16 = n => bits(2,n);
// The exact bytes ML-DSA signs: SHA-512 over the versioned, domain-separated envelope.
const envelope = (label, body) => createHash('sha512').update(domain('gv/sig-envelope')).update(Buffer.from([1,1]))
  .update(u16(label.length)).update(Buffer.from(label)).update(player).update(bits(8,body.length)).update(body).digest();
const verifyRecord = (record, signature, key = vk) => verifyMlDsa65(key, envelope('gv/packed-controls-signed/v1', record), signature);
const encodeRecord=({match=1,prev=2,start=500,ticks=180,width=1,initial=1,changes=[[179,0]]}={})=>{
  const fields=[Buffer.from('GVEC'),bits(1,1),bits(1,width),Buffer.alloc(32,match),player,Buffer.alloc(32,prev),bits(8,start),bits(4,ticks),bits(width,initial),vuint(changes.length)];
  let last=0;
  for(const [offset,state] of changes){assert(offset>last && offset<ticks);fields.push(vuint(offset-last),bits(width,state));last=offset;}
  return concat(...fields);
};
const record=encodeRecord();
const signature=Buffer.from(golden.signature_hex,'hex');
assert.equal(signature.length,SIG_LEN);
assert.equal(record.toString('hex'),golden.record_hex);
const signed=concat(record,signature);
assert.equal(signed.length,record.length+SIG_LEN);
assert.equal(record.subarray(0,4).toString(),'GVEC');
assert.equal(record[5],1);
assert.equal(record.readBigUInt64LE(102),500n); // 4+1+1+32+32+32
assert.equal(record.readUInt32LE(110),180);
assert.equal(record[114],1);
assert.equal(record[115],1);
assert.equal(record[116],179); // delta 179 => 2-byte unsigned LEB128
assert.equal(record[117],1);
assert.equal(record[118],0);
assert.equal(vuint(127).toString('hex'),'7f');
assert.equal(vuint(128).toString('hex'),'8001');
assert.equal(vuint(16384).toString('hex'),'808001');
// An alternate 2-byte encoding of 1 (0x81 0x00) must be rejected by the strict Rust parser.
const nonminimal=Buffer.from([0x81,0x00]);assert.notEqual(nonminimal.toString('hex'),vuint(1).toString('hex'));
const digestOfSigned=sha(concat(domain('gv/packed-controls-hash/v1'),signed));
assert.equal(digestOfSigned.toString('hex'),golden.signed_record_hash);
const aggregate = concat(Buffer.from('GVAG'),bits(1,1),vuint(1),vuint(signed.length),signed);
const aggregateHash=sha(concat(domain('gv/packed-aggregate-hash/v1'),aggregate));
assert.equal(aggregateHash.toString('hex'),golden.aggregate_hash);
assert.equal(aggregate.length,golden.aggregate_length);
function makeChunks(bytes, digest, ceiling, headroom){
  const max=ceiling-49-headroom;assert(max>0);
  const pieces=[];for(let i=0;i<bytes.length;i+=max)pieces.push(bytes.subarray(i,i+max));
  return pieces.map((piece,i)=>concat(Buffer.from('GVKC'),bits(1,1),digest,bits(4,i),bits(4,pieces.length),bits(4,piece.length),piece));
}
const chunks=makeChunks(aggregate,aggregateHash,160,0);
assert(chunks.every(c=>c.length<=160));
assert.deepEqual(concat(...chunks.map(c=>c.subarray(49))),aggregate);
assert(chunks.every((c,i)=>c.readUInt32LE(37)===i && c.readUInt32LE(41)===chunks.length && c.readUInt32LE(45)===c.length-49));
const tampered=Buffer.from(chunks[0]);tampered[55]^=1;
assert.notDeepEqual(sha(concat(domain('gv/packed-aggregate-hash/v1'),concat(tampered.subarray(49),...chunks.slice(1).map(c=>c.subarray(49))))),aggregateHash);
if (opensslHasMlDsa()) {
  assert(verifyRecord(record,signature),'OpenSSL must accept the Rust signature over the record');
  const mutated=Buffer.from(record);mutated[114]^=1;
  assert(!verifyRecord(mutated,signature),'mutated record accepted');
  const badSig=Buffer.from(signature);badSig[7]^=1;
  assert(!verifyRecord(record,badSig),'mutated signature accepted');
  const otherVk=Buffer.from(vk);otherVk[3]^=1;
  assert(!verifyRecord(record,signature,otherVk),'wrong key accepted');
  console.log('PASS: independent Node GVEC event packing, held state, ML-DSA-65 (OpenSSL), SHA-256, aggregate, chunking and mutation rejection');
} else {
  console.log('PASS (signature checks skipped: OpenSSL without ML-DSA): independent Node GVEC packing, SHA-256, aggregate and chunking');
}
