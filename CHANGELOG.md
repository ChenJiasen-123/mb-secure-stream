# Changelog

## Unreleased (main and pending fixes; not on Mooncakes)

- File adapters only remove temporary paths they successfully created; bound key reads, reject non-regular inputs without blocking on FIFOs, and create private Python reference outputs.

- Strict review fixes (#10–#19): reject negative bandwidth consumption, enforce optional issuer/audience policy, strictly parse claims, admit one half-open probe, use weighted request round robin, bound/expire replay caches, saturate backoff, chunk Web Crypto entropy, report post-commit cleanup warnings, and synchronize main/source documentation.
- Compatibility: legacy auth filter remains issuer/audience-unconstrained; backoff normalizes invalid configuration. Queue service changes from strict priority to 8:4:2:1 request shares; malformed optional gateway claims now fail closed.


- Add automatic counter-wrap rekey vectors and malformed-stream differential checks.
- Fix CLI startup/help and MoonBit 0.10.15 bridge formatting.
- Add typed tags/errors and public reader/writer interfaces, keeping compatibility APIs.
- Add synthetic cross-language backup recovery walkthrough, architecture diagrams,
  independent published consumer tutorial, trial and presentation guides.
- Reduce Poly1305 block-packing allocations; include independent integer vectors and
  raw repeated measurements. Peak process RSS is not claimed to improve.
- Keep homepage free of API code and move integration details to dedicated docs.

API/optimization baseline is merged into main; strict-review fixes remain in their PR until merged. See docs/contributions.md for the contribution record.

## 0.2.0

- Add experimental libsodium-compatible XChaCha20-Poly1305 secretstream with
  Bytes APIs, separate random-header writer, AAD, PUSH, REKEY and FINAL handling.
- Reject failed authentication without advancing state; require `finish()` at
  transport EOF and reject frames after FINAL.
- Add Node bounded file I/O example and independent PyNaCl/libsodium oracle.
  MBSS0001 is this project's example envelope, not a libsodium file format.
- Add fixed vectors, randomized protocol differential tests, damaged-container
  checks, entropy failure checks and WasmGC Node Web Crypto host example.
- Verify JS, Linux Native and the specified WasmGC Node host in CI.
  Windows Native, linear-memory Wasm and other hosts remain unverified.
- Reduce temporary allocations in frame encoding; large chunks still incur
  substantial process RSS. No performance or constant-time guarantee is made.
- Clear gateway identity/error state on revalidation and add regression tests.
- Resolve toolchain warnings without disabling the strict CI checks.
- Retain mb-crypto Apache-2.0 provenance and libsodium ISC attribution.

This is unaudited experimental software. Key storage, password derivation,
recovery, guaranteed memory erasure and production security review are outside
the delivered functionality. Historical JWT benchmarks are separate from the
new protocol work. See the module READMEs for API and reproducible commands.
