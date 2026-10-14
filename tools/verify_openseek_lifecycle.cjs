'use strict';
// Real published OpenSeek CLI and SessionStore; only the remote model is replaced
// by a deterministic loopback SSE provider. No model credentials are read.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {randomBytes, createHash} = require('node:crypto');
const archive = require('../examples/openseek-archive/archive.cjs');
const lifecycle = require('../examples/openseek-archive/lifecycle.cjs');

function cleanEnvironment() {
  return Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !/^(DEEPSEEK|KIMI|GLM|OPENSEEK_)/i.test(key)));
}

function cli(args, cwd) {
  return new Promise((resolve, reject) => {
    // Explicitly remove inherited provider configuration and MCP/skills inputs.
    const env = cleanEnvironment();
    const child = spawn(process.env.MBSS_MOONX || 'moonx', ['moonbitlang/openseek@0.6.2', ...args],
      {cwd, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']});
    let stdout = '', stderr = '';
    const timer = setTimeout(() => child.kill(), 90000);
    child.stdout.on('data', data => { stdout += data; });
    child.stderr.on('data', data => { stderr += data; });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`OpenSeek exited ${code}: ${stderr}`));
      else resolve({stdout, stderr});
    });
  });
}

async function main() {
  if (!process.argv[2]) throw new Error('Usage: node tools/verify_openseek_lifecycle.cjs NEW_REPORT.json');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mbss-openseek-live-'));
  const firstPrompt = 'Remember synthetic archive marker ORCHID-731.';
  const secondPrompt = 'Continue the restored session and report its marker.';
  const firstAnswer = 'Synthetic marker recorded: ORCHID-731.';
  const secondAnswer = 'Restored context contains ORCHID-731.';
  const requests = [];
  let serverFailure;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        assert.equal(req.url, '/chat/completions');
        const request = JSON.parse(body);
        assert.equal(request.stream, true);
        requests.push(request);
        const serialized = JSON.stringify(request.messages);
        assert.ok(serialized.includes(firstPrompt));
        const second = serialized.includes(secondPrompt);
        if (second) assert.ok(serialized.includes(firstAnswer), 'restored assistant history missing from actual model request');
        const payload = {choices: [{delta: {tool_calls: [{index: 0,
          id: `finish-${requests.length}`, type: 'function', function: {name: 'finish',
            arguments: JSON.stringify({answer: second ? secondAnswer : firstAnswer})}}]}}],
          usage: {prompt_tokens: 100, completion_tokens: 20, total_tokens: 120}};
        res.writeHead(200, {'Content-Type': 'text/event-stream'});
        res.end(`data: ${JSON.stringify(payload)}\n\ndata: [DONE]\n\n`);
      } catch (error) {
        serverFailure = error;
        res.writeHead(500); res.end('Synthetic test provider rejected request');
      }
    });
  });
  let report;
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const workspace = path.join(root, 'workspace'); fs.mkdirSync(workspace);
    const skills = path.join(root, 'empty-skills'); fs.mkdirSync(skills);
    const prompt = path.join(root, 'system.txt'); fs.writeFileSync(prompt, 'Synthetic lifecycle test. Use finish to answer.');
    const key = path.join(root, 'key'); fs.writeFileSync(key, randomBytes(32), {mode: 0o600});
    const original = path.join(root, 'original');
    const restored = path.join(root, 'restored');
    const id = 'mbss-lifecycle';
    const result1 = path.join(root, 'first-result.json');
    const result2 = path.join(root, 'second-result.json');
    const base = ['--api-key', 'synthetic-local-key', '--api-url', `http://127.0.0.1:${server.address().port}/chat/completions`,
      '--retry-attempts', '1', '--max-steps', '3', '--session', id];
    const runArgs = (store, result, task) => [...base, '--session-root', store, 'run', '--dir', workspace,
      '--global-skills-dir', skills, '--system-prompt-file', prompt, '--result-file', result, task];
    const ciphertext = path.join(root, 'session.mbss');
    const wrapperArgs = runArgs(original, result1, firstPrompt).slice(base.length + 3);
    await lifecycle.runAndArchive(original, id, ciphertext, key,
      [...base.slice(0, -2), ...wrapperArgs], {env: cleanEnvironment(), stdio: 'ignore'});
    assert.ifError(serverFailure);
    const first = JSON.parse(fs.readFileSync(result1, 'utf8'));
    assert.equal(first.status, 'completed');
    const sessionRelative = path.join('sessions', id, `openseek_session-${id}.jsonl`);
    const source = path.join(original, sessionRelative);
    const before = fs.readFileSync(source);
    const summary1 = archive.inspectSession(source, id);
    assert.ok(fs.existsSync(ciphertext), 'automatic archive missing after real CLI exit');
    // Remove only this verifier's own source store: continuation must use recovery.
    fs.rmSync(original, {recursive: true});
    const destination = path.join(restored, sessionRelative);
    lifecycle.restoreStore(restored, id, ciphertext, key);
    assert.throws(() => lifecycle.restoreStore(restored, id, ciphertext, key), /exist/i);
    const wrongRoot = path.join(root, 'wrong-id');
    assert.throws(() => lifecycle.restoreStore(wrongRoot, 'unexpected-id', ciphertext, key), /Unexpected session ID/);
    assert.equal(fs.existsSync(wrongRoot), false);
    assert.deepEqual(fs.readFileSync(destination), before);
    const shown = await cli(['--session-root', restored, 'sessions', 'show', id, '--dir', workspace], workspace);
    assert.ok(shown.stdout.includes(firstAnswer));
    await cli(runArgs(restored, result2, secondPrompt), workspace);
    assert.ifError(serverFailure);
    const second = JSON.parse(fs.readFileSync(result2, 'utf8'));
    assert.equal(second.status, 'completed');
    assert.equal(requests.length, 2);
    assert.ok(JSON.stringify(second).includes(secondAnswer));
    const after = fs.readFileSync(destination);
    assert.deepEqual(after.subarray(0, before.length), before, 'resume must preserve original durable bytes');
    const summary2 = archive.inspectSession(destination, id);
    assert.ok(summary2.events > summary1.events);
    report = {upstream: 'moonbitlang/openseek@0.6.2 published CLI via moonx',
      provider: 'deterministic loopback SSE; no real model call',
      firstStatus: first.status, resumedStatus: second.status,
      firstSession: summary1, resumedSession: summary2,
      automaticArchiveAfterCLIExit: true, existingStoreProtected: true, failedRestoreRootRemoved: true,
      originalStoreRemovedBeforeRestore: !fs.existsSync(original), byteExactRecovery: true,
      upstreamSessionStoreShowPassed: true, restoredHistoryInActualModelRequest: true,
      originalEventsPreservedOnResume: true, modelRequests: requests.length,
      archivedPlaintextSha256: createHash('sha256').update(before).digest('hex')};
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(root, {recursive: true, force: true});
  }
  report.temporaryDirectoryRemoved = !fs.existsSync(root);
  fs.writeFileSync(process.argv[2], JSON.stringify(report, null, 2) + '\n', {flag: 'wx'});
  console.log(JSON.stringify(report, null, 2));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
