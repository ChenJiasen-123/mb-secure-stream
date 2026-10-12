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
