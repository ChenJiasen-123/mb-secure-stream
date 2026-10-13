'use strict';
const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const cli = path.resolve(__dirname, '../examples/secretstream-file/cli.cjs');

test('help and argument errors work without any compiled bridge', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mbss-cli-'));
  try {
    const isolated = path.join(root, 'examples/secretstream-file/cli.cjs');
    fs.mkdirSync(path.dirname(isolated), {recursive: true});
    fs.copyFileSync(cli, isolated);
    for (const option of ['--help', '-h']) {
      const result = spawnSync(process.execPath, [isolated, option], {encoding: 'utf8'});
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /Usage:/);
      assert.equal(result.stderr, '');
    }
    for (const args of [[], ['seal'], ['unknown', 'a', 'b', 'c'],
      ['seal', 'a', 'b', 'c', '12junk'], ['seal', 'a', 'b', 'c', '1e3'],
      ['seal', 'a', 'b', 'c', '1', 'extra']]) {
      const result = spawnSync(process.execPath, [isolated, ...args], {encoding: 'utf8'});
      assert.equal(result.status, 1);
      assert.match(result.stderr, /Usage:/);
      assert.equal(result.stdout, '');
    }
    const result = spawnSync(process.execPath, [isolated, 'seal', 'a', 'b', 'c'], {encoding: 'utf8'});
    assert.equal(result.status, 1);
    assert.match(result.stderr, /moon build --target js examples\/secretstream-file\/bridge/);
    assert.doesNotMatch(result.stderr, /Require stack/);
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('zero-progress writes fail and clean temporary output', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mbss-write-'));
  const original = fs.writeSync;
  try {
    const input = path.join(root, 'input');
    const key = path.join(root, 'test.key');
    const output = path.join(root, 'output');
    fs.writeFileSync(input, 'synthetic input');
    fs.writeFileSync(key, Buffer.alloc(32));
    const {run} = require(cli);
    fs.writeSync = () => 0;
    assert.throws(() => run('seal', input, output, key), /File write made no progress/);
    assert.equal(fs.existsSync(output), false);
    assert.equal(fs.readdirSync(root).some(name => name.startsWith('output.part-')), false);
  } finally {
    fs.writeSync = original;
    fs.rmSync(root, {recursive: true, force: true});
  }
});

function publicationFailure(mode, persistent) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mbss-publish-'));
  const unlink = fs.unlinkSync, link = fs.linkSync;
  try {
    const input = path.join(root, 'input'), key = path.join(root, 'key'), output = path.join(root, 'output');
    fs.writeFileSync(input, 'synthetic input');
    fs.writeFileSync(key, Buffer.alloc(32));
    let calls = 0;
    fs.unlinkSync = name => {
      if (name.startsWith(output + '.part-') && (persistent || calls++ === 0)) throw new Error('injected unlink failure');
      return unlink(name);
    };
    const {run} = require(cli);
    if (mode === 'committed') {
      const result = run('seal', input, output, key);
      assert.equal(result.outputCommitted, true);
      assert.equal(result.cleanupWarnings.length, 1);
      assert.match(result.cleanupWarnings[0], /Output committed/);
      assert.equal(fs.existsSync(output), true);
      assert.equal(fs.readdirSync(root).filter(n => n.startsWith('output.part-')).length, 1);
      assert.throws(() => run('seal', input, output, key), /Output already exists/);
      // The committed file remains decryptable even with its extra hard link.
      fs.unlinkSync = unlink;
      run('open', output, path.join(root, 'restored'), key);
      assert.equal(fs.readFileSync(path.join(root, 'restored'), 'utf8'), 'synthetic input');
    } else {
      fs.linkSync = () => {throw new Error('injected publication failure');};
      assert.throws(() => run('seal', input, output, key), error => {
        assert.equal(error.message, 'injected publication failure');
        assert.equal(error.cleanupWarnings.length, 1);
        return true;
      });
      assert.equal(fs.existsSync(output), false);
    }
  } finally {
    fs.unlinkSync = unlink; fs.linkSync = link;
    fs.rmSync(root, {recursive: true, force: true});
  }
}

test('committed output is successful with a cleanup warning after unlink failure', () => publicationFailure('committed', false));
test('persistent post-commit cleanup failure preserves committed output', () => publicationFailure('committed', true));
test('cleanup failure does not mask the original publication failure', () => publicationFailure('failed', true));

test('temporary name collision never deletes a file owned by another operation', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mbss-collision-'));
  const crypto = require('node:crypto'), random = crypto.randomBytes;
  try {
    const input = path.join(root, 'input'), key = path.join(root, 'key'), output = path.join(root, 'output');
    const collision = output + '.part-' + Buffer.alloc(12).toString('hex');
    fs.writeFileSync(input, 'synthetic'); fs.writeFileSync(key, Buffer.alloc(32));
    fs.writeFileSync(collision, 'belongs to another operation');
    crypto.randomBytes = length => length === 12 ? Buffer.alloc(12) : random(length);
    assert.throws(() => require(cli).run('seal', input, output, key), {code: 'EEXIST'});
    assert.equal(fs.readFileSync(collision, 'utf8'), 'belongs to another operation');
    assert.equal(fs.existsSync(output), false);
    assert.throws(() => require(cli).run('seal', path.join(root, 'missing'), output, key), {code: 'ENOENT'});
    assert.equal(fs.readFileSync(collision, 'utf8'), 'belongs to another operation');
  } finally { crypto.randomBytes = random; fs.rmSync(root, {recursive: true, force: true}); }
});

test('key reads are bounded and non-regular file inputs are rejected', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mbss-input-'));
  const readFile = fs.readFileSync;
  try {
    const input = path.join(root, 'input'), key = path.join(root, 'key'), output = path.join(root, 'output');
    fs.writeFileSync(input, 'synthetic');
    const fd = fs.openSync(key, 'w'); fs.ftruncateSync(fd, 64 * 1024 * 1024); fs.closeSync(fd);
    const {run} = require(cli);
    fs.readFileSync = (name, ...args) => {
      if (name === key) throw new Error('unbounded key read');
      return readFile(name, ...args);
    };
    assert.throws(() => run('seal', input, output, key), /exactly 32/);
    assert.equal(fs.existsSync(output), false);
    fs.writeFileSync(key, Buffer.alloc(32));
    assert.throws(() => run('seal', root, output, key), /regular file/);
    assert.throws(() => run('seal', input, output, root), /regular file/);
    assert.equal(fs.readdirSync(root).some(name => name.includes('.part-')), false);
  } finally { fs.readFileSync = readFile; fs.rmSync(root, {recursive: true, force: true}); }
});

test('FIFO input and key are rejected without waiting for a writer', {skip: process.platform === 'win32'}, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mbss-fifo-'));
  try {
    const input = path.join(root, 'input'), key = path.join(root, 'key'), output = path.join(root, 'output'), fifo = path.join(root, 'fifo');
    fs.writeFileSync(input, 'synthetic'); fs.writeFileSync(key, Buffer.alloc(32));
    const made = spawnSync('mkfifo', [fifo], {encoding: 'utf8'});
    assert.equal(made.status, 0, made.stderr);
    for (const [source, keyfile] of [[fifo, key], [input, fifo]]) {
      const result = spawnSync(process.execPath, [cli, 'seal', source, output, keyfile], {encoding: 'utf8', timeout: 5000});
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /regular file/);
      assert.equal(fs.existsSync(output), false);
    }
  } finally { fs.rmSync(root, {recursive: true, force: true}); }
});
