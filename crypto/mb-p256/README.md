# mb-p256

ECDSA P-256 (secp256r1) public-key signatures for MoonBit.

## Status

Experimental implementation. Tests cover selected behavior and vectors; they do not establish production readiness or side-channel resistance.

## Reference standards

- **RFC 7518** — JSON Web Algorithms (JWA) — ES256
- **FIPS 186-4** — Digital Signature Standard (DSS)
- **SEC 1** — Elliptic Curve Cryptography

## Performance

No reproducible per-operation benchmark is published for this module. See the repository measurement reports for the specific configurations measured.

## Security Considerations

- **Curve security**: P-256 provides ~128-bit security level
- **Deterministic signatures**: Uses RFC 6979 deterministic k to prevent nonce-reuse attacks
- **Point validation**: Public keys are validated before use
- **Signature validation**: Strict ASN.1 DER parsing prevents malformed signature attacks

## API

- `derive_public_key(private_key)` derives a public key.
- `ecdsa_keygen(private_key)` and `ecdsa_keygen_bytes(private_key)` derive a key pair from caller-supplied private key material; they do not generate random keys.
- `ecdsa_sign_message(private_key, message)` and `ecdsa_verify_message(public_key, message, signature)` operate on messages.
- `ecdsa_sign` / `ecdsa_verify` operate on hashes; consult `src/pkg.generated.mbti` for exact types and Bytes variants.
- `ecdh` / `ecdh_bytes` provide shared-secret derivation.

Handle Result errors and source private keys from a secure random generator. Do not treat these primitives as an audited protocol implementation.

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