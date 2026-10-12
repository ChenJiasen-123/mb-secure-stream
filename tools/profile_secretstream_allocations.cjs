'use strict';
// Inspector sampling includes collected objects; values are estimates, not RSS.
const inspector = require('node:inspector');
const fs = require('node:fs');
const path = require('node:path');
const session = new inspector.Session();
const post = (method, params = {}) => new Promise((resolve, reject) =>
  session.post(method, params, (error, result) => error ? reject(error) : resolve(result)));

async function main() {
  const [mode, input, output, key, report, chunk = '65536'] = process.argv.slice(2);
  if (!report || !['seal', 'open'].includes(mode))
    throw new Error('Usage: node tools/profile_secretstream_allocations.cjs seal|open INPUT OUTPUT KEYFILE REPORT [CHUNK]');
  session.connect();
  try {
    await post('HeapProfiler.startSampling', {samplingInterval: 32768,
      includeObjectsCollectedByMajorGC: true, includeObjectsCollectedByMinorGC: true});
    const metrics = require(path.resolve(__dirname, '../examples/secretstream-file/cli.cjs'))
      .run(mode, input, output, key, Number(chunk));
    const {profile} = await post('HeapProfiler.stopSampling');
    const totals = new Map();
    function visit(node) {
      const name = node.callFrame.functionName || '(anonymous)';
      totals.set(name, (totals.get(name) || 0) + node.selfSize);
      for (const child of node.children || []) visit(child);
    }
    visit(profile.head);
    const functions = [...totals].filter(([, size]) => size > 0)
      .sort((a, b) => b[1] - a[1]).map(([functionName, sampledBytes]) => ({functionName, sampledBytes}));
    fs.writeFileSync(report, JSON.stringify({node: process.version, samplingInterval: 32768,
      includesCollectedObjects: true, metrics, sampledBytes: functions.reduce((n, row) => n + row.sampledBytes, 0),
      functions, notes: 'Sampled JS heap allocations including startup; not exact allocation counts, retained heap or total process RSS.'}, null, 2) + '\n', {flag: 'wx'});
    console.log('PASS: allocation sample written');
  } finally {
    session.disconnect();
  }
}
main().catch(error => {console.error(error.message); process.exitCode = 1;});
