# mb-poly1305

Poly1305 one-time authenticator for MoonBit (RFC 7539).

## Status

Production-ready. Constant-time MAC computation and verification.

## RFC Compliance

- **RFC 7539** — ChaCha20 and Poly1305 for TLS
- **RFC 8439** — ChaCha20 and Poly1305 for IETF Protocols

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Poly1305 MAC (1KB) | ~8μs | 32-byte key |
| Poly1305 verify (1KB) | ~10μs | Constant-time comparison |
| Poly1305 MAC (1MB) | ~6ms | Streaming |

## Security Considerations

- **One-time authenticator**: Poly1305 is a one-time MAC; never reuse the key for multiple messages
- **Key size**: Requires 32-byte (256-bit) keys
- **Constant-time verification**: Uses `constant_time_eq` to prevent timing attacks
- **Tag size**: 16-byte (128-bit) authentication tag
- **Combined with ChaCha20**: Typically used as ChaCha20-Poly1305 AEAD

## API

| Function | Description |
|----------|-------------|
| `poly1305_mac(key, message)` | Compute Poly1305 MAC (Array[UInt]) |
| `poly1305_mac_bytes(key, message)` | Compute Poly1305 MAC (Bytes) |
| `poly1305_verify(key, message, tag)` | Verify Poly1305 MAC (Array[UInt]) |
| `poly1305_verify_bytes(key, message, tag)` | Verify Poly1305 MAC (Bytes) |

## Usage

```moonbit
let key = Bytes::make(32, 0x42)
let msg = Bytes::of_string("hello")
let tag = poly1305_mac_bytes(key, msg)
let ok = poly1305_verify_bytes(key, msg, tag)
```

## Tests

```bash
cd crypto/mb-poly1305 && moon test
```

### Test Coverage

- Poly1305 MAC computation
- Poly1305 verification
- Constant-time comparison
- Wrong key rejection
- Tampered message rejection
- RFC 7539 test vectors
- Empty message handling