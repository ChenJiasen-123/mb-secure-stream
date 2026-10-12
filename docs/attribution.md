# 来源与许可证

主体为 Apache-2.0；secretstream 参考 libsodium，保留其 ISC 许可与版权，见 [NOTICE](../crypto/mb-secretstream/NOTICE)。

### Modules Adapted from moonbit-crypto/mb-crypto

The following table lists each cryptographic module, its upstream source, the license (Apache-2.0), and the scope of modifications made in this repository:

| # | Module | Upstream Source | License | Reference / Modification Scope |
|---|--------|-----------------|---------|-------------------------------|
| 1 | `crypto/mb-hash` | [moonbit-crypto/mb-crypto/mb-hash](https://github.com/moonbit-crypto/mb-crypto/tree/main/mb-hash) | Apache-2.0 | SHA-256 and SHA-512 implementation adapted verbatim; added `Sha256::digest_string` and `Sha512::digest_string` convenience methods |
| 2 | `crypto/mb-hmac` | [moonbit-crypto/mb-crypto/mb-hmac](https://github.com/moonbit-crypto/mb-crypto/tree/main/mb-hmac) | Apache-2.0 | HMAC-SHA256 and HMAC-SHA512 adapted verbatim; no semantic changes |
| 3 | `crypto/mb-chacha` | [moonbit-crypto/mb-crypto/mb-chacha](https://github.com/moonbit-crypto/mb-crypto/tree/main/mb-chacha) | Apache-2.0 | ChaCha20/XChaCha20 stream ciphers adapted verbatim; added `encrypt_bytes`/`decrypt_bytes` convenience wrappers |
| 4 | `crypto/mb-poly1305` | [moonbit-crypto/mb-crypto/mb-poly1305](https://github.com/moonbit-crypto/mb-crypto/tree/main/mb-poly1305) | Apache-2.0 | Poly1305 one-time MAC adapted verbatim; added `poly1305_mac_bytes` / `poly1305_verify_bytes` Bytes API; local block-buffer reuse and UInt packing before UInt64 limb arithmetic |
| 5 | `crypto/mb-aead` | [moonbit-crypto/mb-crypto/mb-aead](https://github.com/moonbit-crypto/mb-crypto/tree/main/mb-aead) | Apache-2.0 | ChaCha20-Poly1305 AEAD adapted verbatim; added `aead_encrypt_bytes` / `aead_decrypt_bytes` Bytes API convenience wrappers |
| 6 | `crypto/mb-p256` | [moonbit-crypto/mb-crypto/mb-p256](https://github.com/moonbit-crypto/mb-crypto/tree/main/mb-p256) | Apache-2.0 | ECDSA P-256 adapted verbatim; added `ecdsa_sign_message`/`ecdsa_verify_message` wrappers for JWT integration |
| 7 | `crypto/mb-hkdf` | [moonbit-crypto/mb-crypto/mb-hkdf](https://github.com/moonbit-crypto/mb-crypto/tree/main/mb-hkdf) | Apache-2.0 | HKDF adapted verbatim; added `_bytes` convenience wrappers |
| 8 | `crypto/mb-getrandom` | [moonbit-crypto/mb-crypto/mb-getrandom](https://github.com/moonbit-crypto/mb-crypto/tree/main/mb-getrandom) | Apache-2.0 | OS CSPRNG adapted verbatim; no semantic changes |
| 9 | `crypto/mb-jwt` | Built on top of `mb-hash`, `mb-hmac`, `mb-p256`, `mb-base64url` from [moonbit-crypto/mb-crypto](https://github.com/moonbit-crypto/mb-crypto/tree/main/mb-jwt) | Apache-2.0 | JWT sign/verify (HS256, ES256) — original implementation in this repository using upstream crypto primitives; adds signature comparison, `alg:none` rejection, claims validation |
| 10 | `gateway` | This repository (original) | Apache-2.0 | JWT security filter middleware, flow control (rate limiter, circuit breaker, fair queue, bandwidth shaper, connection pool, backoff, replay protection), stream metrics |

> **Note**: The upstream repository [moonbit-crypto/mb-crypto](https://github.com/moonbit-crypto/mb-crypto) is itself licensed under Apache-2.0. Modifications in this repository are limited to adding convenience wrappers and integration shims; no cryptographic algorithms were changed.


来源范围应以具体模块 README 和源码注释为准。历史改造和本期 secretstream 实现分开说明。
