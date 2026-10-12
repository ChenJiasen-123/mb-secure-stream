# WasmGC host integration

This synthetic example checks the public random-header factory under a Node
Web Crypto host, repeated REKEY/PUSH/FINAL handling, and failure when the host
CSPRNG throws or its imports are missing. It is not a file encryption CLI,
WASI application, browser test or independent protocol oracle.

From the repository root (Node 24 and tested MoonBit 0.10.14):

```sh
moon build --target wasm-gc examples/secretstream-wasm
node tools/verify_secretstream_wasm.cjs wasm-host.json
```

The host must supply `crypto.newUint8Array`, `crypto.getRandomValues` and
`crypto.readByte`. `getRandomValues` must use a trusted CSPRNG and fill the
whole array, or throw. Host exceptions propagate as call failures before a
writer is returned; they are not converted to MoonBit Result errors. The
example uses a fixed synthetic key, which must never protect private data.

The runner also provides `spectest.print_char` for demonstration output.
This tested WasmGC host integration does not establish support for the
linear-memory `wasm` backend or other hosts.
