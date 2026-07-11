# mb-jwt

JWT (JSON Web Tokens) for MoonBit — HS256 and ES256 signing/verification.

## Status

Production-ready. RFC 7519 with constant-time verification and zero-copy token splitting.

## RFC Compliance

- **RFC 7519** — JSON Web Tokens (JWT)
- **RFC 7515** — JSON Web Signature (JWS)
- **RFC 7516** — JSON Web Encryption (JWE) (partial)
- **RFC 7518** — JSON Web Algorithms (JWA)

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| HS256 sign | ~30μs | HMAC-SHA256 |
| HS256 verify | ~50μs | Constant-time comparison |
| ES256 sign | ~200μs | ECDSA P-256 + SHA-256 |
| ES256 verify | ~120μs | ASN.1 parsing + curve verification |
| Token splitting | ~5μs | Zero-copy `Bytes::from_array` |
| Memory allocation | Minimal | No intermediate string copies |

## Security Considerations

- **Timing attack resistance**: All signature comparisons use constant-time algorithms (`constant_time_eq`)
- **Algorithm confusion prevention**: Strict algorithm matching prevents HS256/ES256 confusion attacks
- **alg:none rejection**: Blocks CVE-2016-5431 and variants (case-insensitive, whitespace-tolerant)
- **Signature strip detection**: Rejects tokens with missing or empty signatures
- **Input validation**: Comprehensive bounds checking for all cryptographic operations
- **Stateless design**: No external dependencies, suitable for edge deployment

## API

| Function | Description |
|----------|-------------|
| `sign(payload, key)` | Create signed JWT (HS256 or ES256) |
| `verify(token, key)` | Constant-time verify + decode |
| `decode(token)` | Decode without verification |
| `decode_header(token)` | Decode header without verification |
| `validate_claims(payload, current_time, expected_iss, expected_aud)` | Validate exp, nbf, iss, aud |
| `base64url_encode(data)` | Base64URL encode |
| `base64url_decode(encoded)` | Base64URL decode |

## Algorithms

- **HS256** — HMAC-SHA256 (symmetric)
- **ES256** — ECDSA P-256 + SHA-256 (asymmetric)

## Usage

```moonbit
let key = @mb_jwt.JwtKey::HS256("your-secret")
let payload = "{\"sub\":\"user\",\"exp\":2000000000}"

let token = match @mb_jwt.sign(payload, key) {
  Ok(t) => t
  Err(_) => abort("sign failed")
}

match @mb_jwt.verify(token, key) {
  Ok(p) => println("Valid: " + p)
  Err(e) => println("Invalid: \{e}")
}
```

## Tests

```bash
cd crypto/mb-jwt && moon test
```

### Test Coverage

- JWT sign/verify roundtrip (HS256, ES256)
- Invalid signature detection
- Malformed token handling
- alg:none attack rejection (CVE-2016-5431)
- Algorithm confusion prevention
- Signature strip attack detection
- Truncated token rejection
- Payload tampering detection
- Header injection prevention
- Weak secret resistance
- Cross-token signature reuse prevention
- Expired token rejection
- Not-before (nbf) enforcement
- Issuer validation
- Audience validation
- Empty key handling
- Base64url padding confusion
- ES256 all-zero signature rejection
- ES256 truncated signature rejection