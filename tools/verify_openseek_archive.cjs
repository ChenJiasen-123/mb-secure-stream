'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawnSync} = require('node:child_process');
const app = require('../examples/openseek-archive/archive.cjs');
const crypt = require('../examples/secretstream-file/cli.cjs');
const upstream = require('../examples/openseek-archive/consumer/_build/js/debug/build/reader/reader.js');
const base = path.resolve(__dirname, '../examples/openseek-archive');
const provenance = JSON.parse(fs.readFileSync(path.join(base, 'fixtures/source.json'), 'utf8'));
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const cases = [];
const check = (name, fn) => {fn(); cases.push(name);};
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mbss-openseek-'));
const key = path.join(root, 'synthetic.key');
const input = path.join(root, '会话 空格.jsonl');
const archive = path.join(root, 'session.mbss');
const restored = path.join(root, 'restored.jsonl');
const target = path.join(root, 'rejected.jsonl');
const noStage = () => assert.equal(fs.readdirSync(root).some(name => name.startsWith('.mbss-session-')), false);
let generated, packed, restoredInfo, bigBytes;
try {
  fs.writeFileSync(key, crypto.randomBytes(32), {flag: 'wx', mode: 0o600});
  fs.writeFileSync(input, upstream.make_demo(), {mode: 0o600});
  check('upstream-generated-session-roundtrip', () => {
    generated = app.inspectSession(input);
    assert.equal(generated.events, 5);
    assert.equal(generated.lastSequence, 5);
    packed = app.run('pack', input, archive, key, {offline: true});
    restoredInfo = app.run('restore', archive, restored, key, {expectedId: generated.sessionId});
    assert.equal(packed.outputCommitted, true);
    assert.deepEqual(restoredInfo.session, generated);
    assert.deepEqual(fs.readFileSync(restored), fs.readFileSync(input));
    noStage();
  });
  check('libsodium-independent-decryption', () => {
    const oracle = path.join(root, 'oracle.jsonl');
    const python = process.env.MBSS_PYTHON || 'python';
    const result = spawnSync(python, [path.resolve(__dirname, '../examples/secretstream-file/reference.py'), 'open', archive, oracle, key], {encoding: 'utf8', timeout: 30000});
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(fs.readFileSync(oracle), fs.readFileSync(input));
    assert.deepEqual(app.inspectSession(oracle), generated);
  });
  check('pinned-upstream-legacy-contract', () => {
    const fixture = path.join(base, 'fixtures/session-v1.jsonl');
    assert.equal(sha(fs.readFileSync(fixture)), provenance.sha256);
    const ciphertext = path.join(root, 'legacy.mbss'), output = path.join(root, 'legacy.jsonl');
    app.run('pack', fixture, ciphertext, key, {offline: true, expectedId: 'legacy'});
    const result = app.run('restore', ciphertext, output, key, {expectedId: 'legacy'});
    assert.equal(result.session.events, 18);
    assert.equal(result.session.lastSequence, 18);
    assert.deepEqual(fs.readFileSync(output), fs.readFileSync(fixture));
  });
  check('large-unicode-session-spans-multiple-frames', () => {
    const rows = upstream.make_demo().trimEnd().split('\n').map(JSON.parse);
    rows[0].system_prompt = 'synthetic 😀 中文 '.repeat(80000);
    const source = path.join(root, 'large.jsonl');
    fs.writeFileSync(source, rows.map(row => JSON.stringify(row)).join('\n') + '\n');
    bigBytes = fs.statSync(source).size;
    assert.ok(bigBytes > 1048576);
    const ciphertext = path.join(root, 'large.mbss'), output = path.join(root, 'large-restored.jsonl');
    const result = app.run('pack', source, ciphertext, key, {offline: true});
    assert.ok(result.frames > 2);
    app.run('restore', ciphertext, output, key);
    assert.deepEqual(fs.readFileSync(output), fs.readFileSync(source));
    noStage();
  });
  check('packing-requires-quiescent-source-acknowledgment', () => {
    assert.throws(() => app.run('pack', input, target, key), /requires --offline/);
    assert.equal(fs.existsSync(target), false);
    noStage();
  });
  check('bad-json-header-event-order-and-utf8-rejected', () => {
    const valid = upstream.make_demo();
    const rows = valid.trimEnd().split('\n').map(JSON.parse);
    const duplicate = structuredClone(rows); duplicate[2].sequence = 1;
    const gap = structuredClone(rows); gap[2].sequence = 20;
    const unknown = structuredClone(rows); unknown[1].item.kind = 'unknown-kind';
    const badInputs = [valid + '{', valid.replace('"version":1', '"version":2'), valid.replace('"version":1', '"version":1.5'), duplicate.map(JSON.stringify).join('\n') + '\n', gap.map(JSON.stringify).join('\n') + '\n', unknown.map(JSON.stringify).join('\n') + '\n', Buffer.from([0xff])];
    for (const bytes of badInputs) {
      const bad = path.join(root, 'bad.jsonl'); fs.writeFileSync(bad, bytes);
      assert.throws(() => app.run('pack', bad, target, key, {offline: true}));
      assert.equal(fs.existsSync(target), false);
      noStage();
    }
  });
  check('authenticated-invalid-log-is-not-published', () => {
    const bad = path.join(root, 'invalid-log'); fs.writeFileSync(bad, '{invalid');
    const ciphertext = path.join(root, 'invalid-log.mbss'); crypt.run('seal', bad, ciphertext, key);
    assert.throws(() => app.run('restore', ciphertext, target, key));
    assert.equal(fs.existsSync(target), false);
    noStage();
  });
  check('wrong-key-truncation-tamper-and-trailing-data-rejected', () => {
    const wrong = path.join(root, 'wrong.key'); fs.writeFileSync(wrong, crypto.randomBytes(32));
    assert.throws(() => app.run('restore', archive, target, wrong));
    const bytes = fs.readFileSync(archive), tampered = Buffer.from(bytes); tampered[40] ^= 1;
    for (const damaged of [bytes.subarray(0, -21), tampered, Buffer.concat([bytes, Buffer.from('trailing')])]) {
      const bad = path.join(root, 'damaged.mbss'); fs.writeFileSync(bad, damaged);
      assert.throws(() => app.run('restore', bad, target, key));
      assert.equal(fs.existsSync(target), false); noStage();
    }
  });
  check('unexpected-session-id-and-existing-output-preserved', () => {
    assert.throws(() => app.run('restore', archive, target, key, {expectedId: 'another-session'}), /Unexpected session ID/);
    fs.writeFileSync(target, 'preserve');
    assert.throws(() => app.run('restore', archive, target, key), /already exists/);
    assert.equal(fs.readFileSync(target, 'utf8'), 'preserve'); fs.unlinkSync(target); noStage();
  });
  check('oversized-source-rejected-before-reading-content', () => {
    const sparse = path.join(root, 'oversized'); const fd = fs.openSync(sparse, 'wx');
    fs.ftruncateSync(fd, app.MAX_BYTES + 1); fs.closeSync(fd);
    assert.throws(() => app.run('pack', sparse, target, key, {offline: true}), /size limit/);
    assert.equal(fs.existsSync(target), false); noStage();
  });
  check('source-change-during-snapshot-rejected', () => {
    const source = path.join(root, 'changing.jsonl'); fs.copyFileSync(input, source);
    const read = fs.readSync; let changed = false;
    try {
      fs.readSync = (...args) => {const n = read(...args); if (n && !changed) {changed = true; fs.appendFileSync(source, '\n');} return n;};
      assert.throws(() => app.run('pack', source, target, key, {offline: true}), /changed during snapshot/);
    } finally {fs.readSync = read;}
    assert.equal(fs.existsSync(target), false); noStage();
  });
  check('post-commit-cleanup-failure-is-reported-as-warning', () => {
    const rm = fs.rmSync, output = path.join(root, 'cleanup.mbss');
    try {
      fs.rmSync = (name, options) => {if (path.basename(name).startsWith('.mbss-session-')) throw new Error('injected cleanup failure'); return rm(name, options);};
      const result = app.run('pack', input, output, key, {offline: true});
      assert.equal(result.outputCommitted, true); assert.equal(result.cleanupWarnings.length, 1);
      assert.equal(fs.existsSync(output), true);
    } finally {fs.rmSync = rm;}
    for (const name of fs.readdirSync(root).filter(name => name.startsWith('.mbss-session-'))) fs.rmSync(path.join(root, name), {recursive: true});
  });
  check('actual-command-line-pack-and-restore', () => {
    const program = path.join(base, 'archive.cjs'), output = path.join(root, 'cli.mbss'), plain = path.join(root, 'cli.jsonl');
    for (const args of [['--help'], ['pack', input, output, key, '--offline'], ['restore', output, plain, key, '--expect-id', generated.sessionId]]) {
      const result = spawnSync(process.execPath, [program, ...args], {encoding: 'utf8', timeout: 30000});
      assert.equal(result.status, 0, result.stderr);
    }
    assert.deepEqual(fs.readFileSync(plain), fs.readFileSync(input)); noStage();
  });
  if (process.platform !== 'win32') check('posix-private-output-and-dangling-target-preserved', () => {
    assert.equal(fs.statSync(restored).mode & 0o777, 0o600);
    fs.symlinkSync(path.join(root, 'absent'), target);
    assert.throws(() => app.run('restore', archive, target, key), /already exists/);
    assert.equal(fs.lstatSync(target).isSymbolicLink(), true); fs.unlinkSync(target);
  });
} finally {fs.rmSync(root, {recursive: true, force: true});}
const report = {upstream: 'moonbitlang/openseek@0.6.2', fixture: provenance, generatedSession: generated,
  upstreamParserReconstructionMatches: true, byteExactRecovery: true, libsodiumIndependentDecryption: true,
  multiFramePlaintextBytes: bigBytes, cases, posixChecksExercised: process.platform !== 'win32',
  temporaryDirectoryRemoved: !fs.existsSync(root), node: process.version,
  notes: 'Synthetic and public upstream contract data only. Uses upstream parser/Session APIs, not its native filesystem SessionStore or a live deployed agent.'};
if (process.argv[2]) fs.writeFileSync(process.argv[2], JSON.stringify(report, null, 2) + '\n', {flag: 'wx'});
console.log(JSON.stringify(report));
