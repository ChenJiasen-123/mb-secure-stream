# mb-jwt

JWT (JSON Web Tokens) implementation for MoonBit with HS256 signing.

## Status

**In Development** - Implements HS256 algorithm (HMAC-SHA256).

## Installation

Add to your `moon.mod.json`:

```json
{
  "deps": {
    "moon-crypto/mb-jwt": "0.1.0"
  }
}
```

## Usage

### Sign a token

```moonbit
let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\"}"
let secret = "your-secret-key"

let token = @jwt.sign(payload, secret)
// Returns: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOi...
```

### Verify a token

```moonbit
match @jwt.verify(token, secret) {
  Ok(payload) => println("Valid! Payload: " + payload)
  Err(e) => println("Invalid: " + e)
}
```

### Decode without verification

```moonbit
// WARNING: Never trust unverified tokens
match @jwt.decode(token) {
  Ok(payload) => println(payload)
  Err(e) => println("Malformed token")
}
```

## API

| Function | Description |
|----------|-------------|
| `sign(payload: String, secret: String) -> String` | Create a signed JWT |
| `verify(token: String, secret: String) -> Result[String, String]` | Verify and decode a JWT |
| `decode(token: String) -> Result[String, String]` | Decode without verification |
| `decode_header(token: String) -> Result[String, String]` | Decode the JWT header |

## Supported Algorithms

- **HS256** - HMAC with SHA-256 (default, currently only supported)

## Security Notes

- Uses constant-time comparison for signature verification
- Always verify tokens before trusting their contents
- Use strong, random secrets (at least 256 bits)

## Dependencies

- `mb-hmac` - HMAC-SHA256 implementation
