// Independent re-derivation of exact GVEC/GVAG payload sizes with real ML-DSA-65 signatures (3309 B).
// The expected numbers come from tests/interoperability/packing_sizes_v1.json, which the Rust codec
// test `packing_size_vectors` generates from real encoded records; this script recomputes them from
// the wire layout alone and asserts equality. Bytes only: no carrier fee/acceptance model.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const vectors = JSON.parse(readFileSync(
  fileURLToPath(new URL('../tests/interoperability/packing_sizes_v1.json', import.meta.url)), 'utf8'));
assert.equal(vectors.format, 'GV-PACKING-SIZES-V1');
const SIG = vectors.signature_bytes;
assert.equal(SIG, 3309, 'ML-DSA-65 signature length');
const MAX_AGG = vectors.max_aggregate_records;

const vlen = (n) => { let c = 1; while (n >= 128) { c++; n = Math.floor(n / 128); } return c; };

// One signed record: magic4 ver1 width1 match32 player32 prev32 start8 count4 initial(w) varint(n) events sig
function recordBytes(ticks, start, gap, width, state0Event) {
  // events strictly inside (start, start+ticks); an event on the batch boundary folds into initial state
  let changes = 0, body = 0, prev = 0;
  let next = Math.ceil(start / gap) * gap;
  if (next === start && start !== 0) next += gap; // boundary event -> initial state
  if (start === 0) next = gap;
  for (; next < start + ticks; next += gap) { const off = next - start; changes++; body += vlen(off - prev) + width; prev = off; }
  return 4 + 1 + 1 + 96 + 8 + 4 + width + vlen(changes) + body + SIG;
}

function scenario(sc) {
  const ticks = sc.seconds * 60, gap = 60 / sc.events_per_second;
  assert(Number.isInteger(gap) && gap > 0);
  const span = sc.batch_ticks === 0 ? ticks : sc.batch_ticks;
  let records = 0, aggregates = 0, bytes = 0;
  for (let p = 0; p < sc.players; p++) {
    const sizes = [];
    for (let start = 0; start < ticks; start += span) sizes.push(recordBytes(Math.min(span, ticks - start), start, gap, sc.width));
    records += sizes.length;
    for (let i = 0; i < sizes.length; i += MAX_AGG) {
      const chunk = sizes.slice(i, i + MAX_AGG);
      aggregates++;
      bytes += 4 + 1 + vlen(chunk.length) + chunk.reduce((a, s) => a + vlen(s) + s, 0);
    }
  }
  return { records, aggregates, bytes };
}

for (const sc of vectors.scenarios) {
  const got = scenario(sc);
  assert.deepEqual(got, { records: sc.records, aggregates: sc.aggregates, bytes: sc.bytes }, sc.name);
  const kbps = (got.bytes * 8) / sc.seconds / 1000;
  console.log(`${sc.name}: ${got.bytes.toLocaleString('en-US')} B in ${got.records} records / ${got.aggregates} aggregates (${kbps.toFixed(2)} kbit/s averaged)`);
}
console.log('PASS: packing byte accounting matches the Rust codec vectors (bytes only; NOT any carrier acceptance model)');
