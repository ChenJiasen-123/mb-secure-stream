'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {webcrypto} = require('node:crypto');

const moduleFile = path.resolve(__dirname, '../_build/wasm-gc/debug/build/examples/secretstream-wasm/secretstream-wasm.wasm');
const moduleBytes = fs.readFileSync(moduleFile);
const compiled = new WebAssembly.Module(moduleBytes);
function instantiate(entropy) {
  let output = '';
  const instance = new WebAssembly.Instance(compiled, {
    crypto: {
      newUint8Array: length => new Uint8Array(length),
      getRandomValues: entropy,
      readByte: (buffer, index) => buffer[index],
    },
    spectest: {print_char: character => {output += String.fromCharCode(character);}},
  });
  return {run: () => instance.exports._start(), output: () => output};
}
const requests = [];
const normal = instantiate(buffer => {requests.push(buffer.length); return webcrypto.getRandomValues(buffer);});
normal.run();
assert.equal(normal.output().trim(), 'PASS: wasm-gc secretstream host integration');
assert.deepEqual(requests.slice(0, 7), [65535, 65536, 65536, 1, 65536, 65536, 1]);
assert.equal(Math.max(...requests), 65536);

const failure = new Error('injected host CSPRNG failure');
const broken = instantiate(() => {throw failure;});
assert.throws(broken.run, error => error === failure);
assert.equal(broken.output(), '');
assert.throws(() => new WebAssembly.Instance(compiled, {
  crypto: {}, spectest: {print_char() {}},
}), WebAssembly.LinkError);

const report = {
  backend: 'wasm-gc', node: process.version,
  entropyBoundaryRequests: [65535, 65536, 65537, 131073], maxHostRequestBytes: Math.max(...requests),
  randomHeaderRoundtrip: true, pushRekeyFinal: true,
  entropyFailureTrapsWithoutCompletion: true, missingImportsRejected: true,
  notes: 'Custom Node Web Crypto host; not a WASI or browser compatibility claim. Protocol differential evidence is separate.',
};
if (process.argv[2]) fs.writeFileSync(process.argv[2], JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report));
