'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {spawn} = require('node:child_process');
const archive = require('./archive.cjs');
const USAGE = 'Usage: node examples/openseek-archive/lifecycle.cjs run|restore STORE_ROOT SESSION_ID ARCHIVE KEYFILE [-- OPENSEEK_RUN_ARGUMENTS...]';

function sessionFile(root, id) {
  // Restrict to portable IDs; do not allow paths supplied by the archive header.
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(id)) throw new Error('Expected a portable session ID (letters, digits, underscore or hyphen; max 128 characters)');
  return path.join(path.resolve(root), 'sessions', id, `openseek_session-${id}.jsonl`);
}

async function runAndArchive(root, id, ciphertext, key, args, {env = process.env, stdio = 'inherit'} = {}) {
  const source = sessionFile(root, id);
  // The wrapper owns session selection; forwarded arguments cannot change it.
  if (!Array.isArray(args) || !args.length || args.some(arg =>
    /^(--session|--session-root|--no-session|--inspect|--input-format|--kind)(=|$)/.test(arg)))
    throw new Error(USAGE + '\nPass text-mode run arguments; session selection is managed by this wrapper.');
  // Fail before running a potentially expensive model request.
  try { fs.lstatSync(ciphertext); throw new Error('Archive output already exists'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  await new Promise((resolve, reject) => {
    const child = spawn(env.MBSS_MOONX || 'moonx', ['moonbitlang/openseek@0.6.2',
      '--session-root', path.resolve(root), '--session', id, 'run', ...args],
      {env, stdio, windowsHide: true});
    child.on('error', reject);
    child.on('close', code => code === 0 ? resolve() : reject(new Error(`OpenSeek exited ${code}; no archive was published`)));
  });
  // OpenSeek has exited and released its store lock. The caller must exclusively
  // own this session; another process must not resume it during this snapshot.
  return archive.run('pack', source, ciphertext, key, {offline: true, expectedId: id});
}

function restoreStore(root, id, ciphertext, key) {
  const output = sessionFile(root, id);
  root = path.resolve(root);
  // A new root prevents replacing sessions in a live store. Parent must exist.
  fs.mkdirSync(root, {mode: 0o700});
  try {
    fs.mkdirSync(path.dirname(output), {recursive: true, mode: 0o700});
    return archive.run('restore', ciphertext, output, key, {expectedId: id});
  } catch (error) {
    try { fs.rmSync(root, {recursive: true, force: true}); }
    catch (cleanup) { error.cleanupWarnings = [...(error.cleanupWarnings || []), `Retained restore root ${root}: ${cleanup.message}`]; }
    throw error;
  }
}

if (require.main === module) {
  (async () => {
    const [mode, root, id, ciphertext, key, ...rest] = process.argv.slice(2);
    if (mode === '--help') { console.log(USAGE); return; }
    if (!key || !['run', 'restore'].includes(mode)) throw new Error(USAGE);
    let result;
    if (mode === 'restore') {
      if (rest.length) throw new Error(USAGE);
      result = restoreStore(root, id, ciphertext, key);
    } else {
      if (rest.shift() !== '--') throw new Error(USAGE);
      result = await runAndArchive(root, id, ciphertext, key, rest);
    }
    console.log(JSON.stringify(result));
  })().catch(error => {
    console.error(error.message || String(error));
    for (const warning of error.cleanupWarnings || []) console.error(warning);
    process.exitCode = 1;
  });
}
module.exports = {runAndArchive, restoreStore, sessionFile};
