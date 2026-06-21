# mb-secure-stream

Industrial-grade JWT gateway and cryptography library for MoonBit.

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
# Run JWT tests (28 tests)
cd crypto/mb-jwt && moon test

# Run gateway tests (21 tests)
cd ../../gateway && moon test
```

## Cloudflare Worker

See `examples/cloudflare-worker/README.md` for deployment instructions.

## License

Apache 2.0