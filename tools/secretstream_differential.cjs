'use strict';
// Test adapter only. All cryptography runs in the compiled MoonBit bridge.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const mb = require(path.resolve(__dirname, '../_build/js/debug/build/examples/secretstream-file/bridge/bridge.js'));
const bytes = hex => Buffer.from(hex, 'hex');
const hex = value => Buffer.from(value).toString('hex');
const cases = JSON.parse(fs.readFileSync(0, 'utf8'));
// Fail closed if the host CSPRNG throws: no header/writer may be returned.
const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
try {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: {getRandomValues() {throw new Error('injected entropy failure');}},
  });
  assert.throws(() => mb.writer_new(Buffer.alloc(32)));
} finally {
  if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor);
  else delete globalThis.crypto;
}
const output = cases.map(test => {
  const key = bytes(test.key);
  const reader = mb.reader_new(key, bytes(test.header));
  const writer = mb.writer_new(key);
  const frames = [];
  let rejectedInputs = 0;
  let incompleteChecks = 0;
  for (const record of test.records) {
    const aad = bytes(record.aad);
    const frame = bytes(record.frame);
    const damaged = Buffer.from(frame);
    damaged[damaged.length - 1] ^= 1;
    assert.throws(() => mb.reader_pull_record(reader, damaged, aad));
    // Incomplete EOF is an error, and checking it must not consume state.
    assert.throws(() => mb.reader_finish(reader));
    incompleteChecks++;
    for (const rejected of record.rejected) {
      assert.throws(() => mb.reader_pull_record(reader, bytes(rejected.frame), bytes(rejected.aad)), rejected.kind);
      rejectedInputs++;
    }
    // A failed authentication must not change the state needed by the real frame.
    const decoded = mb.reader_pull_record(reader, frame, aad);
    assert.equal(hex(decoded._0), record.message);
    assert.equal(decoded._1, record.tag);
    frames.push(hex(mb.writer_push_record(writer, bytes(record.message), aad, record.tag)));
  }
  mb.reader_finish(reader);
  assert.throws(() => mb.reader_pull_record(reader, bytes(test.records.at(-1).frame), bytes(test.records.at(-1).aad)));
  assert.throws(() => mb.writer_push_record(writer, Buffer.alloc(0), Buffer.alloc(0), 0));
  return {header: hex(mb.writer_header(writer)), frames, rejectedInputs, incompleteChecks};
});
process.stdout.write(JSON.stringify(output));
