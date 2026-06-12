# mb-getrandom

Secure random number generation for MoonBit, providing access to OS-level entropy sources.

## Features

- Cross-platform support (native, JavaScript, WASM)
- Cryptographically secure random byte generation
- Uses OS CSPRNG (seeded by hardware entropy) on all platforms

## Installation

```bash
moon add ChenJiasen-123/moon_jwt/crypto/mb-getrandom
```

## Usage

```moonbit
fn main {
  match @lib.getrandom(32) {
    Ok(random_bytes) => println("Generated 32 random bytes")
    Err(e) => println("Error: \{e}")
  }
}
```

## Platform Support

| Target | Backend | Source of Entropy |
|--------|---------|-------------------|
| Native | C FFI | `/dev/urandom` (Unix), `BCryptGenRandom` (Windows) |
| JS | `extern "js"` | `crypto.getRandomValues()` / Node.js `crypto.randomBytes()` |
| WASM / WASM-GC | Host imports | Web Crypto API via host-provided `crypto` module |

## WASM-GC Host Setup

When using the WASM-GC backend, the JavaScript host must provide a `crypto` import module when instantiating the WASM module:

```javascript
const importObject = {
  crypto: {
    newUint8Array: (len) => new Uint8Array(len),
    getRandomValues: (buf) => { globalThis.crypto.getRandomValues(buf); },
    readByte: (buf, idx) => buf[idx],
  },
  // ... other MoonBit runtime imports
};

const module = new WebAssembly.Module(wasmBytes, {
  builtins: ["js-string"],
  importedStringConstants: "_",
});
const instance = new WebAssembly.Instance(module, importObject);
```

## Testing

Bare `moon test` defaults to the wasm-gc target, which will fail because `moonrun` does not support custom host imports. Use the following commands instead:

```bash
# Run tests on native and JS targets
moon test --target native
moon test --target js

# Run tests on wasm-gc using the custom test harness
moon test --target wasm-gc --build-only
node test/run_wasm_gc_test.mjs

# Or run all targets at once
bash test.sh
```

## License

Apache-2.0
