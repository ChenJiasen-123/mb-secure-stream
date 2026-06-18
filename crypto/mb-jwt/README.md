# mb-jwt

JWT (JSON Web Tokens) implementation for MoonBit with **HS256** (HMAC-SHA256) and **ES256** (ECDSA P-256 + SHA-256) signing.

## Status

**Production-ready** — Implements RFC 7519 with constant-time signature verification, zero-copy token splitting, and algorithm-pinned dispatch.

## Installation

Add to your `moon.mod.json`:

```json
{
  "deps": {
    "mb_jwt": { "path": "../crypto/mb-jwt" }
  }
}
```

## Usage

### Sign a token (HS256)

```moonbit
let key = @mb_jwt.JwtKey::HS256("your-secret-key")
let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\"}"

let token = match @mb_jwt.sign(payload, key) {
  Ok(t) => t
  Err(_) => abort("sign failed")
}
// Returns: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOi...
```

### Sign a token (ES256 — asymmetric)

```moonbit
let private_key : Array[UInt] = // 32-byte P-256 private key
let key = @mb_jwt.JwtKey::ES256(private_key)
let payload = "{\"sub\":\"user\",\"iat\":1516239022}"

let token = match @mb_jwt.sign(payload, key) {
  Ok(t) => t
  Err(_) => abort("sign failed")
}
```

### Verify a token

```moonbit
let key = @mb_jwt.JwtKey::HS256("your-secret-key")
match @mb_jwt.verify(token, key) {
  Ok(payload) => println("Valid! Payload: " + payload)
  Err(e) => println("Invalid: \{e}")
}
```

### Validate standard claims

```moonbit
let payload = @mb_jwt.new_jwt_payload(
  Some("issuer"),     // iss
  Some("user-123"),   // sub
  None,               // aud
  Some(2000000000L),  // exp
  Some(1000000000L),  // nbf
  None,               // iat
  None,               // jti
)
match @mb_jwt.validate_claims(payload, 1500000000L, None, None) {
  Ok(_) => println("Claims valid")
  Err(@mb_jwt.TokenExpired(_, _)) => println("Token expired")
  Err(@mb_jwt.TokenNotYetValid(_, _)) => println("Token not yet valid")
  Err(_) => println("Other claim error")
}
```

### Decode without verification

```moonbit
// WARNING: Never trust unverified tokens
match @mb_jwt.decode(token) {
  Ok(payload) => println(payload)
  Err(e) => println("Malformed token")
}
```

## API

| Function | Description |
|----------|-------------|
| `sign(payload, key) -> Result[String, JWTError]` | Create a signed JWT (HS256 or ES256) |
| `verify(token, key) -> Result[String, JWTError]` | Constant-time verify + decode |
| `decode(token) -> Result[String, JWTError]` | Decode payload without verification |
| `decode_header(token) -> Result[String, JWTError]` | Decode the JWT header |
| `validate_claims(payload, current_time, iss, aud) -> Result[Unit, JWTError]` | Validate standard JWT claims (exp, nbf, iss, aud) |
| `new_jwt_payload(iss, sub, aud, exp, nbf, iat, jti) -> JWTPayload` | Construct a typed JWTPayload |
| `new_jwt_header(alg, typ) -> JWTHeader` | Construct a typed JWTHeader |
| `base64url_encode(data) -> String` | Base64URL encode (RFC 4648) |
| `base64url_decode(encoded) -> Array[UInt]` | Base64URL decode |
| `base64url_decode_range(source, start, end) -> Array[UInt]` | **Zero-copy** range decode |
| `base64url_decode_range_to_string(source, start, end) -> String` | **Zero-copy** range decode to string |

### Key Types

| Type | Description |
|------|-------------|
| `JwtKey::HS256(String)` | Symmetric HMAC-SHA256 secret |
| `JwtKey::ES256(Array[UInt])` | Asymmetric ECDSA P-256 private/public key (32 bytes) |

### Error Types (`JWTError`)

| Variant | Meaning |
|---------|---------|
| `InvalidFormat` | Token does not have `header.payload.signature` structure |
| `InvalidSignature` | Signature verification failed (tampered token) |
| `AlgorithmMismatch(String)` | Header `alg` does not match expected algorithm |
| `CryptoError(String)` | Underlying crypto library failure |
| `TokenExpired(Int64, Int64)` | Token has expired (current_time, exp) |
| `TokenNotYetValid(Int64, Int64)` | Token is not yet valid (current_time, nbf) |
| `InvalidIssuer(String)` | Issuer does not match expected value |
| `InvalidAudience(String)` | Audience does not match expected value |

## Supported Algorithms

- **HS256** — HMAC with SHA-256 (symmetric, default)
- **ES256** — ECDSA P-256 + SHA-256 (asymmetric)

## Security Features

- **Constant-time signature comparison** — bitwise XOR accumulation with no early returns (prevents timing attacks)
- **alg:none rejection** — CVE-2016-5431 mitigation
- **Algorithm pinning** — `verify()` dispatches to the correct algorithm based on `JwtKey` variant, preventing algorithm confusion attacks
- **Zero-copy token splitting** — no heap allocations on the hot path
- **Range-based base64url decoding** — operates directly on the original token string without intermediate substrings

## Dependencies

- `mb-hmac` — HMAC-SHA256 implementation
- `mb-p256` — ECDSA P-256 implementation