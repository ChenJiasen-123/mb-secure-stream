'use strict';
// File I/O adapter only: all cryptography executes in the compiled MoonBit bridge.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const mb = require(path.resolve(__dirname, '../../_build/js/debug/build/examples/secretstream-file/bridge/bridge.js'));
const MAGIC = Buffer.from('MBSS0001');
const MAX = 1024 * 1024;

function exact(fd, length, eofAllowed = false) {
  const bytes = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const n = fs.readSync(fd, bytes, offset, length - offset, null);
    if (!n) {
      if (!offset && eofAllowed) return null;
      throw new Error('Truncated file');
    }
    offset += n;
  }
  return bytes;
}

function writeAll(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) offset += fs.writeSync(fd, bytes, offset, bytes.length - offset);
}

function record(fd, frame) {
  const size = Buffer.alloc(4);
  size.writeUInt32LE(frame.length);
  writeAll(fd, size);
  writeAll(fd, frame);
}

function run(mode, input, output, keyFile, chunk = 65536) {
  if (!['seal', 'open'].includes(mode) || !Number.isInteger(chunk) || chunk < 1 || chunk > MAX)
    throw new Error('Usage: node cli.cjs seal|open INPUT OUTPUT KEYFILE [CHUNK_BYTES:1..1048576]');
  const key = fs.readFileSync(keyFile);
  if (key.length !== 32) throw new Error('Key file must contain exactly 32 binary bytes');
  if (fs.existsSync(output)) throw new Error('Output already exists');
  const temporary = output + '.part-' + crypto.randomBytes(12).toString('hex');
  let source, sink;
  let inputBytes = 0, outputBytes = 0, frames = 0;
  const started = performance.now();
  try {
    source = fs.openSync(input, 'r');
    sink = fs.openSync(temporary, 'wx', 0o600);
    if (mode === 'seal') {
      const writer = mb.writer_new(new Uint8Array(key));
      writeAll(sink, MAGIC);
      writeAll(sink, mb.writer_header(writer));
      outputBytes = 32;
      const buffer = Buffer.alloc(chunk);
      for (;;) {
        const n = fs.readSync(source, buffer, 0, buffer.length, null);
        if (!n) break;
        const frame = mb.writer_push(writer, new Uint8Array(buffer.subarray(0, n)), false);
        record(sink, frame);
        inputBytes += n;
        outputBytes += 4 + frame.length;
        frames++;
      }
      const finalFrame = mb.writer_push(writer, new Uint8Array(), true);
      record(sink, finalFrame);
      outputBytes += 4 + finalFrame.length;
      frames++;
    } else {
      if (!exact(source, 8).equals(MAGIC)) throw new Error('Invalid file header');
      const reader = mb.reader_new(new Uint8Array(key), new Uint8Array(exact(source, 24)));
      inputBytes = 32;
      for (;;) {
        const prefix = exact(source, 4, true);
        if (!prefix) break;
        const length = prefix.readUInt32LE();
        if (length < 17 || length > MAX + 17) throw new Error('Invalid frame size');
        const frame = exact(source, length);
        const message = mb.reader_pull(reader, new Uint8Array(frame));
        writeAll(sink, message);
        inputBytes += 4 + length;
        outputBytes += message.length;
        frames++;
      }
      mb.reader_finish(reader);
    }
    fs.fsyncSync(sink);
    fs.closeSync(sink); sink = undefined;
    fs.closeSync(source); source = undefined;
    // Same-directory hard link publishes a verified file without overwriting.
    fs.linkSync(temporary, output);
    fs.unlinkSync(temporary);
    return {mode, inputBytes, outputBytes, frames, chunkBytes: chunk,
      elapsedSeconds: (performance.now() - started) / 1000,
      peakRssMiB: process.resourceUsage().maxRSS / 1024,
      node: process.version};
  } catch (error) {
    if (sink !== undefined) fs.closeSync(sink);
    if (source !== undefined) fs.closeSync(source);
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
    throw error;
  }
}

if (require.main === module) {
  try {
    const [mode, input, output, keyFile, size] = process.argv.slice(2);
    if (!input || !output || !keyFile) throw new Error('Missing arguments');
    console.log(JSON.stringify(run(mode, input, output, keyFile, size === undefined ? 65536 : Number(size))));
  } catch (error) {
    console.error(error.message || String(error));
    process.exitCode = 1;
  }
}
module.exports = {run};
