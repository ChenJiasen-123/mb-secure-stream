# mb-jwt

JWT (JSON Web Tokens) for MoonBit — HS256 and ES256 signing/verification.

## Status

Production-ready. RFC 7519 with constant-time verification and zero-copy token splitting.

## Quick Start

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

## API

| Function | Description |
|----------|-------------|
| `sign(payload, key)` | Create signed JWT (HS256 or ES256) |
| `verify(token, key)` | Constant-time verify + decode |
| `decode(token)` | Decode without verification |
| `validate_claims(payload, time, iss, aud)` | Validate exp, nbf, iss, aud |
| `base64url_encode(data)` | Base64URL encode |
| `base64url_decode(encoded)` | Base64URL decode |

## Algorithms

- **HS256** — HMAC-SHA256 (symmetric)
- **ES256** — ECDSA P-256 + SHA-256 (asymmetric)

## Tests

```bash
cd crypto/mb-jwt && moon test