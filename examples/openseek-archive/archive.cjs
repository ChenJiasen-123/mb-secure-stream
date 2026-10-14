'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {run: cryptFile} = require('../secretstream-file/cli.cjs');
const READER = path.resolve(__dirname, 'consumer/_build/js/debug/build/reader/reader.js');
const MAX_BYTES = 32 * 1024 * 1024;
const USAGE = 'Usage: node examples/openseek-archive/archive.cjs pack|restore INPUT OUTPUT KEYFILE [--offline] [--expect-id SESSION_ID]';

function exists(filename) {
  try { fs.lstatSync(filename); return true; }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}

function copySnapshot(source, target, limit) {
  const input = fs.openSync(source, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0));
  let output;
  try {
    const before = fs.fstatSync(input, {bigint: true});
    if (!before.isFile()) throw new Error('Session input must be a regular file');
    if (before.size > BigInt(limit)) throw new Error('Session exceeds the archive example size limit');
    output = fs.openSync(target, 'wx', 0o600);
    const buffer = Buffer.alloc(65536);
    let total = 0;
    for (;;) {
      const count = fs.readSync(input, buffer, 0, buffer.length, null);
      if (!count) break;
      total += count;
      if (total > limit) throw new Error('Session grew beyond the archive example size limit');
      let offset = 0;
      while (offset < count) {
        const written = fs.writeSync(output, buffer, offset, count - offset);
        if (written <= 0) throw new Error('Snapshot write made no progress');
        offset += written;
      }
    }
    const after = fs.fstatSync(input, {bigint: true});
    if (BigInt(total) !== before.size || after.size !== before.size || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs)
      throw new Error('Session changed during snapshot; stop its writer before archiving');
  } finally {
    if (output !== undefined) fs.closeSync(output);
    fs.closeSync(input);
  }
}

function inspectSession(filename, expectedId) {
  const data = fs.readFileSync(filename);
  if (data.length > MAX_BYTES) throw new Error('Session exceeds the archive example size limit');
  const text = new TextDecoder('utf-8', {fatal: true}).decode(data);
  const first = text.split('\n').find(line => line.trim());
  let header;
  try { header = JSON.parse(first); } catch { throw new Error('Invalid session header'); }
  if (!header || header.version !== 1 || typeof header.id !== 'string' || !header.id || typeof header.system_prompt !== 'string')
    throw new Error('Only a complete version-1 session header is supported');
  const result = JSON.parse(require(READER).inspect(text));
  if (!result.valid) throw new Error('OpenSeek rejected session: ' + result.reason);
  if (expectedId !== undefined && result.sessionId !== expectedId) throw new Error('Unexpected session ID');
  return result;
}

function run(mode, source, output, key, {offline = false, expectedId} = {}) {
  if (!['pack', 'restore'].includes(mode) || (mode === 'pack' && !offline) ||
      (expectedId !== undefined && (typeof expectedId !== 'string' || !expectedId))) throw new Error(USAGE + '\nPacking requires --offline: the source writer must be stopped.');
  if (!fs.existsSync(READER)) throw new Error('Build the OpenSeek consumer first: cd examples/openseek-archive/consumer && moon build reader --target js');
  output = path.resolve(output);
  if (exists(output)) throw new Error('Output already exists');
  const stage = fs.mkdtempSync(path.join(path.dirname(output), '.mbss-session-'));
  const input = path.join(stage, 'input');
  const ready = path.join(stage, mode === 'pack' ? 'session.mbss' : 'session.jsonl');
  let session, crypt;
  try {
    copySnapshot(source, input, mode === 'pack' ? MAX_BYTES : MAX_BYTES + 1024 * 1024);
    if (mode === 'pack') {
      session = inspectSession(input, expectedId);
      crypt = cryptFile('seal', input, ready, key);
    } else {
      crypt = cryptFile('open', input, ready, key);
      session = inspectSession(ready, expectedId);
    }
    // All input authentication and upstream parsing happen before this commit point.
    fs.linkSync(ready, output);
  } catch (error) {
    try { fs.rmSync(stage, {recursive: true, force: true}); }
    catch (cleanup) { error.cleanupWarnings = [`Retained private staging directory ${stage}: ${cleanup.message}`]; }
    throw error;
  }
  const cleanupWarnings = [];
  try { fs.rmSync(stage, {recursive: true, force: true}); }
  catch (cleanup) { cleanupWarnings.push(`Output committed; remove private staging directory ${stage}: ${cleanup.message}`); }
  return {mode, outputCommitted: true, cleanupWarnings, session,
    upstream: 'moonbitlang/openseek@0.6.2 public parser and Session reconstruction',
    crypto: 'MoonBit secretstream', frames: crypt.frames};
}

if (require.main === module) {
  try {
    const args = process.argv.slice(2);
    if (args.length === 1 && args[0] === '--help') console.log(USAGE + '\nPlaintext session limit: 32 MiB; restore writes a new standalone JSONL file.');
    else {
      if (args.length < 4) throw new Error(USAGE);
      const [mode, source, output, key, ...flags] = args;
      const options = {};
      for (let i = 0; i < flags.length; i++) {
        if (flags[i] === '--offline' && !options.offline) options.offline = true;
        else if (flags[i] === '--expect-id' && options.expectedId === undefined && flags[i + 1] && !flags[i + 1].startsWith('--')) options.expectedId = flags[++i];
        else throw new Error(USAGE);
      }
      console.log(JSON.stringify(run(mode, source, output, key, options)));
    }
  } catch (error) {
    console.error(error.message || String(error));
    for (const warning of error.cleanupWarnings || []) console.error(warning);
    process.exitCode = 1;
  }
}
module.exports = {run, inspectSession, MAX_BYTES};
