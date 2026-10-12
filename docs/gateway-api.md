# 历史 JWT 与网关接口说明

以下由旧首页迁移，示意代码不是独立可运行程序。实际导出签名以各包的 pkg.generated.mbti 为准；完整使用说明见 [JWT](../crypto/mb-jwt/README.md) 和 [网关](../gateway/README.md)。本期 secretstream 接口见 [独立指南](secretstream-api.md)。

## API Reference

### JWT API

#### Core Functions

| Function | Input | Output | Description |
|----------|-------|--------|-------------|
| `sign(payload, key)` | `payload: String` (JSON), `key: JwtKey` | `Result[String, JWTError]` | Create signed JWT token |
| `verify(token, key)` | `token: String`, `key: JwtKey` | `Result[String, JWTError]` | Verify JWT and return payload JSON |
| `decode(token)` | `token: String` | `Result[String, JWTError]` | Decode without verification |
| `decode_header(token)` | `token: String` | `Result[String, JWTError]` | Decode header without verification |
| `validate_claims(payload, current_time, expected_iss, expected_aud)` | `payload: JWTPayload`, `current_time: Int64`, `expected_iss: String?`, `expected_aud: String?` | `Result[Unit, JWTError]` | Validate exp, nbf, iss, aud |

#### Key Types

```moonbit
enum JwtKey {
  HS256(String)           // HMAC-SHA256 secret key
  ES256(Array[UInt])      // ECDSA P-256 private key (32 bytes)
}
```

#### Data Structures

```moonbit
struct JWTPayload {
  iss: Option[String]  // Issuer
  sub: Option[String]  // Subject (user ID)
  aud: Option[String]  // Audience
  exp: Option[Int64]   // Expiration time (Unix timestamp)
  nbf: Option[Int64]   // Not before (Unix timestamp)
  iat: Option[Int64]   // Issued at (Unix timestamp)
  jti: Option[String]  // JWT ID
}
```

#### Usage Example

```moonbit
// Sign
let key = JwtKey::HS256("my-secret")
let payload = "{\"sub\":\"user123\",\"exp\":2000000000,\"role\":\"admin\"}"
let token = sign(payload, key)?  // Returns: "header.payload.signature"

// Verify
match verify(token, key) {
  Ok(payload_json) => {
    // Success: payload_json is the decoded JSON string
    println("Valid token: \{payload_json}")
  }
  Err(InvalidSignature) => println("Invalid signature")
  Err(TokenExpired(_, _)) => println("Token expired")
  Err(e) => println("Error: \{e}")
}
```

### Gateway API

#### Core Functions

| Function | Input | Output | Description |
|----------|-------|--------|-------------|
| `new_stream_context(token)` | `token: String` | `StreamContext` | Create security context |
| `execute_security_filter(ctx, key, time)` | `ctx: StreamContext`, `key: JwtKey`, `time: Int64` | `Unit` | Validate JWT and populate context |

#### Data Structures

```moonbit
struct StreamContext {
  token: String           // Input: JWT token
  mut is_allowed: Bool    // Output: true if valid
  mut error_message: String // Output: error reason if invalid
  mut user_sub: String    // Output: JWT "sub" claim (user ID)
  mut user_role: String   // Output: JWT "role" claim ("admin", "guest", etc.)
}
```

#### Usage Example

```moonbit
// Create context with JWT token
let ctx = new_stream_context("eyJhbGciOiJIUzI1NiJ9...")

// Execute security filter
let jwt_key = JwtKey::HS256("my-secret")
let current_time = 1700000000
execute_security_filter(ctx, jwt_key, current_time)

// Check result
if ctx.is_allowed {
  // Success: access granted
  println("Access allowed, sub: \{ctx.user_sub}, role: \{ctx.user_role}")
  // Forward request with user context
  forward_request(ctx.user_sub, ctx.user_role)
} else {
  // Failure: access denied
  println("Access denied: \{ctx.error_message}")
  // Return 401/403 error
}
```

#### Error Messages

| Error Type | error_message | HTTP Status |
|------------|---------------|-------------|
| Invalid signature | "Crypto Blocked: Invalid signature" | 401 |
| Malformed token | "Crypto Blocked: Malformed token format" | 401 |
| Algorithm mismatch | "Crypto Blocked: Algorithm mismatch" | 401 |
| Token expired | "Gateway Blocked: Token has expired" | 401 |
| Not yet valid | "Gateway Blocked: Token is not yet valid (nbf)" | 401 |
| Invalid issuer | "Gateway Blocked: Invalid issuer" | 403 |
| Invalid audience | "Gateway Blocked: Invalid audience" | 403 |

