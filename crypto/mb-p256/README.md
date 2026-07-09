# mb-p256

ECDSA P-256 (secp256r1) public-key signatures for MoonBit.

## Status

Production-ready. RFC 7518 compliant.

## API

| Function | Description |
|----------|-------------|
| `p256_generate_keypair()` | Generate a new P-256 keypair |
| `p256_sign(private_key, message)` | Sign message (Array[UInt]) |
| `p256_sign_bytes(private_key, message)` | Sign message (Bytes) |
| `p256_verify(public_key, message, signature)` | Verify signature (Array[UInt]) |
| `p256_verify_bytes(public_key, message, signature)` | Verify signature (Bytes) |

## Usage

```moonbit
let (public_key, private_key) = p256_generate_keypair()
let message = string_to_uints("hello")
let sig = p256_sign(private_key, message)
let ok = p256_verify(public_key, message, sig)
```

## Tests

```bash
cd crypto/mb-p256 && moon test