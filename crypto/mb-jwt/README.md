# mb-jwt

JWT (JSON Web Tokens) for MoonBit — HS256 and ES256 signing/verification.

## Status

Experimental implementation. Tests cover selected behavior and vectors; they do not establish production readiness or side-channel resistance.

## Reference standards

- **RFC 7519** — JSON Web Tokens (JWT)
- **RFC 7515** — JSON Web Signature (JWS)
- **RFC 7518** — JSON Web Algorithms (JWA)

## Performance

No reproducible per-operation benchmark is published for this module. See the repository measurement reports for the specific configurations measured.

## Security Considerations

`verify` checks the signature and returns the payload; applications must separately validate claims and authorization policy. `decode` and `decode_header` do not authenticate their outputs. Use a strong randomly generated HS256 secret; the short strings below are demonstration placeholders.

- **Algorithm confusion prevention**: Strict algorithm matching prevents HS256/ES256 confusion attacks
- **alg:none rejection**: Blocks CVE-2016-5431 and variants (case-insensitive, whitespace-tolerant)
- **Signature strip detection**: Rejects tokens with missing or empty signatures

## API

| Function | Description |
|----------|-------------|
| `sign(payload, key)` | Create signed JWT (HS256 or ES256) |
| `verify(token, key)` | Verify signature and decode; validate claims separately |
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
  Ok(p) => println("Signature verified; claims still need validation: " + p)
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
- Empty or invalid key handling (not a guarantee against weak secrets)
- Cross-token signature reuse prevention
- Expired token rejection
- Not-before (nbf) enforcement
- Issuer validation
- Audience validation
- Empty key handling
- Base64url padding confusion
- ES256 all-zero signature rejection
- ES256 truncated signature rejection