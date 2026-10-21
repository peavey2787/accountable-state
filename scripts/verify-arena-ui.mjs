import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const html = fs.readFileSync('examples/edge-p2p/src/arena.html', 'utf8');
const inline = html.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(inline, 'browser Javascript exists');
const script = new vm.Script(inline[1], { filename: 'arena.html' });
for (const feature of ['W ↑', 'Space · Attack', 'Shift · Guard', 'Send cheat move', 'Hide 5 s', 'Finality after play', 'INVALID MOVE DETECTED', '/controls?controls=', '/inject?kind=', '/hide', 'requestAnimationFrame']) {
  assert.ok(html.includes(feature), `missing interactive feature: ${feature}`);
}
assert.ok(!html.includes('id="send"'), 'manual Send input removed');
assert.ok(!html.includes('id="auto"'), 'manual Auto-step removed');
// Gameplay is the Rust 60 Hz simulation. The page must not run its own physics.
assert.ok(!html.includes('previewPosition') && !html.includes('stepFrom'), 'no client-side game prediction remains');

const listeners = new Map(), events = new Map(), calls = [];
const draws = { arcs: 0, text: [], dashed: 0 };
function element(name) {
  const e = { name, style: {}, dataset: {}, textContent: '', children: [], className: '', disabled: false,
    classList: {toggle(){}}, addEventListener(kind, fn) { events.set(`${name}:${kind}`, fn); },
    replaceChildren(...children){this.children = children;}, setPointerCapture() {},
    getContext() { return { fillRect(){}, beginPath(){}, arc(){ draws.arcs++; }, fill(){}, stroke(){}, setLineDash(d){ if (d && d.length) draws.dashed++; }, fillText(t){ draws.text.push(t); },
      set fillStyle(_){}, set font(_){}, set textAlign(_){}, set textBaseline(_){}, set lineWidth(_){}, set strokeStyle(_){}, set globalAlpha(_){} }; },
  };
  if (name === 'arena') { e.width = 680; e.height = 680; }
  return e;
}
const elements = new Map();
const ids = ['arena', 'verdict', 'verdictText', 'violations', 'violationsText', 'phase', 'hz', 'jitter', 'finality', 'lag', 'accepted', 'rejected', 'rollbacks', 'prediction', 'net', 'tick', 'vtick', 'checkpoint', 'connection', 'healthA', 'healthB', 'statA', 'statB', 'youA', 'youB', 'log', 'localmsg', 'cheat', 'illegal', 'hide', 'modeNote'];
for (const id of ids) elements.set(id, element(id));
const buttons = [1, 2, 4, 8, 16, 32].map(bit => { const e = element(`key-${bit}`); e.dataset.bit = String(bit); return e; });
const base = {
  you: 0, phase: 'Playing at 60 Hz', tick: 600, verifiedTick: 560, checkpoint: 'abc',
  fighters: [{ x: -3, y: 0, hp: 100, cooldown: 0, guarding: false, hidden: false }, { x: 3, y: 0, hp: 88, cooldown: 2, guarding: true, hidden: false }],
  verified: [{ x: -3, y: 0, hp: 100, cooldown: 0, guarding: false, hidden: false }, { x: 3, y: 0, hp: 88, cooldown: 2, guarding: true, hidden: false }],
  events: ['CERTIFIED ticks 540..560'], stopped: false, controls: 0, accepted: 2, disputed: 0, rejected: 0,
  verdict: 'valid', pendingTicks: 40, finalityMs: 82, finalityAvgMs: 75.4, tickHz: 60.0, jitterMs: 0.4, simUs: 30,
  rollbacks: 3, maxRollback: 9, prediction: 4, stalled: false, hide: null, hideCooldownTicks: 0,
  rttMs: 1.2, txKbps: 3.1, rxKbps: 2.9,
};
let snapshot = base;
const sandbox = {
  document: { addEventListener() {}, getElementById(id) { if (!elements.has(id)) elements.set(id, element(id)); return elements.get(id); }, querySelectorAll() { return buttons; }, createElement(name) { return element(name); } },
  window: { addEventListener(kind, fn) { listeners.set(kind, fn); } },
  fetch: async (url, options = {}) => { calls.push({ url, options }); return { ok: true, json: async () => snapshot, text: async () => '' }; },
  requestAnimationFrame() {}, setInterval() { return 1; }, clearInterval() {}, setTimeout() { return 1; }, clearTimeout() {},
  performance: { now: () => 0 }, console, Math,
};
script.runInNewContext(sandbox);
const flush = async () => { for (let i = 0; i < 8; i++) await new Promise(resolve => setImmediate(resolve)); };
await flush();
const sent = () => calls.map(x => x.url);
assert.ok(sent().includes('/controls?controls=0'), 'initial neutral input transmitted');
assert.ok(calls.some(x => x.url === '/state'), 'live state is polled');

// Controls are sent as held levels; Rust turns them into one word per tick.
const down = listeners.get('keydown'), up = listeners.get('keyup');
const key = code => ({ code, preventDefault() {}, repeat: false });
down(key('KeyD')); await flush();
assert.ok(sent().includes('/controls?controls=2'), 'movement sent on key press');
down(key('Space')); await flush();
assert.ok(sent().includes('/controls?controls=18'), 'attack combined with movement');
up(key('KeyD')); await flush();
assert.ok(sent().includes('/controls?controls=16'), 'key release updates held controls');
down(key('KeyW')); down(key('KeyD')); await flush();
assert.ok(!sent().some(u => u === '/controls?controls=22' || u === '/controls?controls=6'), 'two directions never produce a contradictory word');
up(key('KeyW')); up(key('KeyD')); up(key('Space')); await flush();
assert.equal(calls.filter(x => x.url.startsWith('/controls')).at(-1).url, '/controls?controls=0');

// Test injections and the new Hide action.
elements.get('cheat').onclick(); await flush();
assert.ok(sent().includes('/inject?kind=cheat'), 'cheat button queues test fraud');
elements.get('illegal').onclick(); await flush();
assert.ok(sent().includes('/inject?kind=invalid'), 'illegal-input button queues an invalid signed word');
elements.get('hide').onclick(); await flush();
assert.equal(calls.filter(x => x.url === '/hide').length, 1, 'Hide button requests a hidden window');
assert.equal(calls.find(x => x.url === '/hide').options.method, 'POST');
down(key('KeyH')); await flush();
assert.equal(calls.filter(x => x.url === '/hide').length, 2, 'H key hides too');

// Telemetry and verification status.
sandbox.receive(base);
assert.equal(elements.get('hz').textContent, '60.0');
assert.equal(elements.get('tick').textContent, 600);
assert.equal(elements.get('vtick').textContent, 560);
assert.equal(elements.get('lag').textContent, 40);
assert.ok(elements.get('finality').textContent.includes('82'));
assert.ok(elements.get('verdict').className.includes('valid'));
assert.ok(elements.get('verdictText').textContent.includes('667 ms'), elements.get('verdictText').textContent);
sandbox.receive({ ...base, pendingTicks: null });
assert.ok(elements.get('verdictText').textContent.includes('all play is certified'), 'idle is not reported as lag');
assert.equal(elements.get('lag').textContent, 0);
sandbox.receive(base);
assert.ok(elements.get('violations').className.includes('valid') && !elements.get('violations').className.includes('invalid'), 'no violations yet');

// Accountability: delay, withholding and disconnects are only ever "suspected", never red.
sandbox.receive({ ...base, rejected: 0, audit: { pending: 2, suspected: 2, unavailable: 1, cleared: 0, provenEquivocation: 0 } });
assert.ok(!elements.get('violations').className.includes('invalid'), 'suspicion alone never turns the violation indicator red');
assert.equal(elements.get('acSuspect').textContent, 2);
assert.ok(elements.get('acNote').textContent.includes('not a cheating verdict'));
sandbox.receive({ ...base, rejected: 0, audit: { cleared: 1, evidenceFiles: 1, evidenceBytes: 4096, persistOk: true } });
assert.equal(elements.get('acCleared').textContent, 1);
assert.ok(!elements.get('violations').className.includes('invalid'), 'exoneration is not a violation');

// The violation indicator is separate, latched, and counts every detection.
sandbox.receive({ ...base, rejected: 1, verdict: 'invalid' });
assert.ok(elements.get('violations').className.includes('invalid'));
assert.ok(elements.get('violationsText').textContent.includes('× 1'));
assert.ok(!elements.get('verdict').className.includes('invalid'), 'verification chip is independent of the violation chip');
sandbox.receive({ ...base, rejected: 1, verdict: 'valid' });
assert.ok(elements.get('violations').className.includes('invalid'), 'stays red after later valid epochs');
sandbox.receive({ ...base, rejected: 3 });
assert.ok(elements.get('violationsText').textContent.includes('× 3'), 'counter increments per detection');
sandbox.receive({ ...base, rejected: 0 });
assert.ok(elements.get('violations').className.includes('invalid'), 'latched even if a snapshot reports fewer');

sandbox.receive({ ...base, rejected: 0, audit: { provenEquivocation: 1 } });
assert.ok(elements.get('violations').className.includes('invalid'), 'cryptographic equivocation proof latches the indicator');
assert.equal(elements.get('acEquiv').textContent, 1);
sandbox.receive({ ...base, rejected: 0 });
assert.ok(elements.get('violations').className.includes('invalid'), 'stays latched');


// Hidden window: observer sees fog and no location; hider sees their own state.
const fogged = { ...base, hide: { hider: 1, start: 540, end: 840, active: true },
  fighters: [base.fighters[0], { ...base.fighters[1], hidden: true }] };
sandbox.receive(fogged);
assert.equal(elements.get('statB').textContent, 'location hidden');
assert.ok(elements.get('hide').disabled, 'cannot hide twice');
assert.ok(elements.get('hide').textContent.includes('Hidden'));
assert.ok(elements.get('modeNote').textContent.includes('opponent is hidden'));
draws.arcs = 0; draws.text.length = 0;
sandbox.frame(16); sandbox.frame(32);
assert.ok(draws.text.includes('?'), 'a fog marker is drawn instead of the opponent');
assert.ok(!draws.text.includes('B'), 'the hidden fighter is not drawn at all');
sandbox.receive({ ...base, you: 1, hide: { hider: 1, start: 540, end: 840, active: true } });
assert.ok(elements.get('modeNote').textContent.includes('You are hidden'));
sandbox.receive({ ...base, hideCooldownTicks: 300 });
assert.ok(elements.get('hide').disabled && elements.get('hide').textContent.includes('5 s'), 'cooldown shown');
sandbox.receive({ ...base, hideCooldownTicks: 0 });
assert.ok(!elements.get('hide').disabled, 'hide available again');

// Rollback ring: a certified position that differs from the live one is outlined.
sandbox.receive({ ...base, verified: [{ ...base.verified[0], x: -4 }, base.verified[1]] });
draws.dashed = 0; sandbox.frame(48);
assert.ok(draws.dashed > 0, 'last certified position is outlined when it differs from live play');

// Stall and failure states.
sandbox.receive({ ...base, stalled: true });
assert.ok(elements.get('verdict').className.includes('warn'));
listeners.get('blur')(); await flush();
assert.equal(calls.filter(x => x.url.startsWith('/controls')).at(-1).url, '/controls?controls=0', 'window blur releases held controls');
sandbox.receive({ ...base, rejected: 0, stopped: true, verdict: 'error', phase: 'Match interrupted: epoch 2, reveal timed out' });
assert.equal(elements.get('rejected').textContent, 0, 'transport errors are not fraud claims');
assert.ok(elements.get('verdictText').textContent.includes('INTERRUPTED'), 'error state stays on the local UI');
console.log('PASS: live GUI parses; control press/hold/release automatically transmits; cheat, invalid-input and hide actions connected; separate latched violation indicator; fog, rollback ring and 60 Hz telemetry render');
