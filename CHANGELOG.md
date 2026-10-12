# Changelog

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
