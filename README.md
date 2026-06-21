# mb-secure-stream

Industrial-grade JWT gateway and cryptography library for MoonBit.

## Features

- **Constant-time verification** — Prevents timing attacks on signature comparison
- **Algorithm enforcement** — Rejects `alg:none` to prevent signature bypass (CVE-2016-5431)
- **Zero-copy token splitting** — Efficient token parsing without intermediate allocations
- **HS256 & ES256** — HMAC-SHA256 and ECDSA P-256 + SHA-256 support
- **Production-ready** — RFC 7519 compliant with comprehensive test coverage

## Modules

| Module | Description |
|--------|-------------|
| `crypto/mb-jwt` | JWT sign/verify (HS256, ES256) with constant-time verification |
| `crypto/mb-hmac` | HMAC-SHA256 |
| `crypto/mb-hash` | SHA-2 family |
| `crypto/mb-chacha` | ChaCha20 stream cipher |
| `crypto/mb-aead` | Poly1305 AEAD |
| `crypto/mb-p256` | ECDSA P-256 |
| `crypto/mb-hkdf` | HKDF key derivation |
| `crypto/mb-getrandom` | Secure random bytes |
| `gateway` | JWT security filter middleware |

## Quick Start

```bash
# Run JWT tests
cd crypto/mb-jwt && moon test

# Run gateway tests
cd ../../gateway && moon test
```

## Examples

### Cloudflare Worker

A production-ready TypeScript JWT gateway deployed as a Cloudflare Worker. Uses the Web Crypto API (no Wasm dependency) and includes:

- JWT signature verification (HS256)
- CORS handling with configurable allowed origins
- Upstream proxy with `X-User-ID` and `X-User-Role` header forwarding
- Security response headers (HSTS)

See `examples/cloudflare-worker/README.md` for deployment instructions.

## License

Apache 2.0
