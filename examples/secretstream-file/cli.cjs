'use strict';
// File I/O adapter only: all cryptography executes in the compiled MoonBit bridge.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const BRIDGE = path.resolve(__dirname, '../../_build/js/debug/build/examples/secretstream-file/bridge/bridge.js');
const USAGE = 'Usage: node examples/secretstream-file/cli.cjs seal|open INPUT OUTPUT KEYFILE [CHUNK_BYTES:1..1048576]';
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
  while (offset < bytes.length) {
    const written = fs.writeSync(fd, bytes, offset, bytes.length - offset);
    if (written <= 0) throw new Error('File write made no progress');
    offset += written;
  }
}

function record(fd, frame) {
  const size = Buffer.alloc(4);
  size.writeUInt32LE(frame.length);
  writeAll(fd, size);
  writeAll(fd, frame);
}

function run(mode, input, output, keyFile, chunk = 65536) {
  if (!['seal', 'open'].includes(mode) || !Number.isInteger(chunk) || chunk < 1 || chunk > MAX)
    throw new Error(USAGE);
  if (!fs.existsSync(BRIDGE))
    throw new Error('MoonBit JS bridge is not built. From the repository root run: moon build --target js examples/secretstream-file/bridge');
  const mb = require(BRIDGE);
  const key = fs.readFileSync(keyFile);
  if (key.length !== 32) throw new Error('Key file must contain exactly 32 binary bytes');
  if (fs.existsSync(output)) throw new Error('Output already exists');
  const temporary = output + '.part-' + crypto.randomBytes(12).toString('hex');
  let source, sink;
  let inputBytes = 0, outputBytes = 0, frames = 0, maxPlaintextFrameBytes = 0;
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
        maxPlaintextFrameBytes = Math.max(maxPlaintextFrameBytes, n);
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
        maxPlaintextFrameBytes = Math.max(maxPlaintextFrameBytes, message.length);
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
    // Decryption follows input record lengths, not the CLI's chunk argument.
    return {mode, inputBytes, outputBytes, frames, chunkBytes: mode === 'seal' ? chunk : null,
      maxPlaintextFrameBytes,
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
    const args = process.argv.slice(2);
    if (args.length === 1 && ['--help', '-h'].includes(args[0])) {
      console.log(USAGE + '\nCHUNK_BYTES controls encryption only; decryption follows input records.\nBuild first: moon build --target js examples/secretstream-file/bridge');
    } else {
      if (args.length < 4 || args.length > 5) throw new Error(USAGE);
      const [mode, input, output, keyFile, size] = args;
      if (size !== undefined && !/^[0-9]+$/.test(size)) throw new Error(USAGE);
      console.log(JSON.stringify(run(mode, input, output, keyFile, size === undefined ? 65536 : Number(size))));
    }
  } catch (error) {
    console.error(error.message || String(error));
    process.exitCode = 1;
  }
}
module.exports = {run};
