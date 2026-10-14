# Secretstream authenticated encryption

This is a MoonBit implementation of libsodium's
`crypto_secretstream_xchacha20poly1305` construction, not a new cryptographic
protocol.

Upstream: https://github.com/jedisct1/libsodium
Reference commit: `89e500718da7e1fc90e168bd88e18d1060f54db3`.
Reference file: `src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c`.
The original ISC license and copyright are retained in NOTICE.
Existing ChaCha20 and Poly1305 primitives come from the parent repository's
documented upstream adaptations.

The reader consumes an externally supplied 24-byte header and key. On the JS
backend, `init_push(Bytes)` now returns a separate writer with a fresh header
from the existing OS/Web Crypto CSPRNG provider. Entropy failure is an error.
The deterministic sender is internal and exists only to compare test vectors.
Never reuse a key/header pair. The same factory uses the existing OS entropy
shim on Native; Linux Native protocol and random-header tests pass in CI.
WasmGC uses mb-getrandom's host crypto imports and is tested under the
[Node Web Crypto host example](../../examples/secretstream-wasm/README.md).
Host instantiation and crypto import calls are supplied by the runtime.

The wrapper accepts standard tags 0–3, treats FINAL as terminal, and requires
`finish()` at transport EOF. Authentication of each frame alone cannot prove
the whole stream is complete. A failed authentication does not advance state.
Applications must enforce their own framing and must not treat partial output
as a complete file before FINAL. Frame and AAD sizes follow the API parameters.

Fixtures in `fixtures/libsodium.json` were generated with independent PyNaCl
1.6.2 bundled libsodium. Tests compare every sender byte and every receiver
plaintext/tag across empty, boundary-sized, AAD, REKEY and FINAL frames.
Negative tests cover corruption, wrong AAD/key, replay, reordering,
truncation, finalization and malformed/oversized inputs.

Run `moon test crypto/mb-secretstream/src` from the repository root.
To regenerate independent fixtures, install `tools/requirements-dev.txt` in
an isolated Python environment and run `python tools/generate_secretstream_vectors.py`.
Regeneration chooses a fresh random header and updates both the JSON fixture
and generated tests. Keep the checked-in pair together for repeatable tests.

Bytes APIs and a bounded file I/O integration are available; see
[the file adapter](../../examples/secretstream-file/README.md). Mooncakes 0.2.0
is an experimental release; main contains the unpublished 0.3.0 development
source. Linux Native and the documented Node Web Crypto WasmGC host are tested.

Randomized differential checks use the public random-header JS sender and
independent PyNaCl/libsodium, comparing exact ciphertext, plaintext and tags:

```sh
moon build --target js examples/secretstream-file/bridge
python tools/verify_secretstream_differential.py differential.json --streams 32
```

They cover boundary and random lengths, AAD, repeated REKEY, PUSH, FINAL,
authentication failure without state advancement and injected host entropy
failure. A payload seed is recorded; OS-generated headers intentionally remain
random.

The same harness mutates each received stream with random bit flips,
truncation, short frames, trailing bytes, wrong AAD, replay and reordered
frames. Independent libsodium must reject each candidate without changing
its state; MoonBit must reject all candidates and then recover the correct
plaintext/tag from the original frame. Calling `finish()` before each valid
frame must reject incomplete input without preventing later recovery.
At the default 32 streams this checks 5,536 malformed inputs and 800 early
completion checks. Change `--seed` for additional cases; this bounded mutation

Counter-wrap regression vectors in fixtures/counter-wrap.json use independent
PyNaCl/libsodium ciphertext and next-state values. The test positions the internal
32-bit counter at 0xfffffffe, checks automatic rekey, then explicit REKEY and
FINAL, including rejection without state advancement for a damaged frame.
Regenerate with python tools/generate_secretstream_counter_vectors.py, followed
by moon fmt crypto/mb-secretstream. State positioning is test-only; the public
API does not expose nonce or key mutation.
