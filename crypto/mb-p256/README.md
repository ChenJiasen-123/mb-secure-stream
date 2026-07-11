# mb-p256

ECDSA P-256 (secp256r1) public-key signatures for MoonBit.

## Status

Production-ready. RFC 7518 compliant.

## RFC Compliance

- **RFC 7518** — JSON Web Algorithms (JWA) — ES256
- **FIPS 186-4** — Digital Signature Standard (DSS)
- **SEC 1** — Elliptic Curve Cryptography

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Key generation | ~500μs | P-256 keypair |
| Sign | ~200μs | ECDSA P-256 + SHA-256 |
| Verify | ~120μs | ASN.1 parsing + curve verification |
| Public key derivation | ~150μs | From private key |

## Security Considerations

- **Curve security**: P-256 provides ~128-bit security level
- **Deterministic signatures**: Uses RFC 6979 deterministic k to prevent nonce-reuse attacks
- **Constant-time**: Scalar multiplication uses constant-time algorithms
- **Point validation**: Public keys are validated before use
- **Signature validation**: Strict ASN.1 DER parsing prevents malformed signature attacks

## API

| Function | Description |
|----------|-------------|
| `p256_generate_keypair()` | Generate a new P-256 keypair |
| `p256_sign(private_key, message)` | Sign message (Array[UInt]) |
| `p256_sign_bytes(private_key, message)` | Sign message (Bytes) |
| `p256_verify(public_key, message, signature)` | Verify signature (Array[UInt]) |
| `p256_verify_bytes(public_key, message, signature)` | Verify signature (Bytes) |
| `derive_public_key(private_key)` | Derive public key from private key |

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
```

### Test Coverage

- Key generation
- Sign/verify roundtrip
- Public key derivation
- Wrong public key rejection
- Tampered message rejection
- Wrong signature rejection
- RFC 6979 deterministic k
- NIST test vectors