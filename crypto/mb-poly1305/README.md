# mb-poly1305

Poly1305 one-time authenticator for MoonBit (RFC 7539).

## Status

Production-ready. Constant-time MAC computation and verification.

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