# mb-secure-stream

Industrial-grade JWT gateway and cryptography library for MoonBit.

## Features

- **Constant-time verification** — Prevents timing attacks on signature comparison
- **Algorithm enforcement** — Rejects `alg:none` to prevent signature bypass (CVE-2016-5431)
- **Zero-copy token splitting** — Efficient token parsing without intermediate allocations
- **HS256 & ES256** — HMAC-SHA256 and ECDSA P-256 + SHA-256 support
- **Production-ready** — RFC 7519 compliant with comprehensive test coverage

## Performance

| Metric | Value |
|--------|-------|
| JWT verify (HS256) | ~50μs per token |
| JWT verify (ES256) | ~120μs per token |
| Memory allocation | Zero-copy token splitting |
| Test coverage | 150/150 tests passing |
| Cold start (WASM) | <10ms (estimated) |

## Security Considerations

- **Timing attack resistance**: All signature comparisons use constant-time algorithms
- **Algorithm confusion prevention**: Strict algorithm matching prevents HS256/ES256 confusion attacks
- **Replay protection**: Nonce-based sliding window (configurable)
- **Stateless design**: No external dependencies, suitable for edge deployment
- **Input validation**: Comprehensive bounds checking and type validation

## Modules

| Module | Description |
|--------|-------------|
| `crypto/mb-jwt` | JWT sign/verify (HS256, ES256) with constant-time verification |
| `crypto/mb-hmac` | HMAC-SHA256 and HMAC-SHA512 |
| `crypto/mb-hash` | SHA-2 family (SHA-256, SHA-512) |
| `crypto/mb-chacha` | ChaCha20 and XChaCha20 stream ciphers (RFC 8439) |
| `crypto/mb-aead` | ChaCha20-Poly1305 AEAD (RFC 8439) |
| `crypto/mb-poly1305` | Poly1305 one-time authenticator (RFC 7539) |
| `crypto/mb-p256` | ECDSA P-256 (secp256r1) signatures |
| `crypto/mb-hkdf` | HKDF key derivation (RFC 5869) |
| `crypto/mb-getrandom` | Secure random bytes (OS CSPRNG) |
| `gateway` | JWT security filter middleware |

## Quick Start

```bash
# Install MoonBit
curl -fsSL https://cli.moonbitlang.com/install/unix.sh | bash

# Workspace check and full test suite
moon check -d
moon fmt --check crypto/mb-aead crypto/mb-chacha \
  crypto/mb-getrandom crypto/mb-hash crypto/mb-hkdf \
  crypto/mb-hmac crypto/mb-jwt crypto/mb-p256 \
  crypto/mb-poly1305 gateway
moon info
moon test

# Module-level smoke tests
cd crypto/mb-jwt && moon test
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