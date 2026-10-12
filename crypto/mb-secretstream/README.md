# Secretstream compatibility prototype

This is an experimental MoonBit port of libsodium's
`crypto_secretstream_xchacha20poly1305` construction, not a new cryptographic
protocol. It is not audited and must not be presented as production ready.

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
Never reuse a key/header pair. The same factory is enabled for Native using the
existing OS entropy shim. Native verification is included in Linux CI, but has
not yet been run successfully: this Windows checkout has only MinGW, whereas
MoonBit requires an MSVC-compatible Windows toolchain. Do not claim verified
Native support until the CI/platform tests pass. Wasm sender integration is pending.

The wrapper accepts standard tags 0–3, treats FINAL as terminal, and requires
`finish()` at transport EOF. Authentication of each frame alone cannot prove
the whole stream is complete. A failed authentication does not advance state.
Applications must enforce their own framing and must not treat partial output
as a complete file before FINAL. Frames/AAD are bounded by prototype limits.

Fixtures in `fixtures/libsodium.json` were generated with independent PyNaCl
1.6.2 bundled libsodium. Tests compare every sender byte and every receiver
plaintext/tag across empty, boundary-sized, AAD, REKEY and FINAL frames.
Negative tests cover corruption, wrong AAD/key, replay, reordering,
truncation, finalization and malformed/oversized inputs.

Run `moon test -p crypto/mb-secretstream/src` from the repository root.
To regenerate independent fixtures, install `tools/requirements-dev.txt` in
an isolated Python environment and run `python tools/generate_secretstream_vectors.py`.
Regeneration chooses a fresh random header and updates both the JSON fixture
and generated tests. Keep the checked-in pair together for repeatable tests.

Bytes APIs and a bounded file I/O integration are now available; see
`examples/secretstream-file`. Before any release: more independent vectors and
fuzzing, verified Native/Wasm sender support, security review and documented key lifecycle.

Randomized differential checks use the public random-header JS sender and
independent PyNaCl/libsodium, comparing exact ciphertext, plaintext and tags:

```sh
moon build --target js examples/secretstream-file/bridge
python tools/verify_secretstream_differential.py differential.json --streams 32
```

They cover boundary and random lengths, AAD, repeated REKEY, PUSH, FINAL,
authentication failure without state advancement and injected host entropy
failure. A payload seed is recorded; OS-generated headers intentionally remain
random. These checks are evidence of tested behavior, not an audit.
