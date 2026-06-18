# Gateway — JWT Security Filter Middleware

A **security filter middleware** for MoonBit web services that validates JWT tokens and produces a `StreamContext` with authorization decisions.

## Overview

The gateway module provides a **three-step pipeline** for every inbound request:

```
Request Token
     │
     ▼
┌─────────────────────────────────┐
│  Step 1: verify(token, JwtKey)  │  ← crypto-level: detects tampering,
│  Returns: payload JSON or error │    malformed format, algorithm mismatch
└────────────┬────────────────────┘
             │ success
             ▼
┌─────────────────────────────────────┐
│  Step 2: parse_gateway_claims(json) │  ← extracts sub, exp, nbf, iss, role
│  Returns: GatewayClaims or error    │
└────────────┬────────────────────────┘
             │ success
             ▼
┌─────────────────────────────────────┐
│  Step 3: validate_claims(payload,   │  ← business-rule: exp, nbf, iss, aud
│           current_time, ...)        │
└────────────┬────────────────────────┘
             │ result
             ▼
      StreamContext {
        is_allowed: true/false,
        user_role: "admin"|"guest"|...,
        error_message: "..."
      }
```

### Error Differentiation

| Error | Source | Action |
|-------|--------|--------|
| `InvalidSignature` | Step 1 | **IP-fencing** — tampered token, likely attack |
| `InvalidFormat` | Step 1 | **Return 400** — malformed request |
| `TokenExpired` | Step 3 | **Seamless refresh** — return 401 with refresh hint |
| `TokenNotYetValid` | Step 3 | **Clock sync warning** — token used before nbf |

## API

| Function | Description |
|----------|-------------|
| `new_stream_context(token) -> StreamContext` | Create a security context from a raw JWT |
| `execute_security_filter(ctx, key, current_time)` | Run the full security pipeline (verify → parse → validate) |
| `parse_gateway_claims(json) -> Result[GatewayClaims, String]` | Parse gateway-specific claims from a JSON string |

### Key Types

```moonbit
pub struct StreamContext {
  token : String                           // Raw JWT string
  mut is_allowed : Bool                    // true if request should proceed
  mut error_message : String               // Human-readable rejection reason
  mut user_role : String                   // "admin" | "guest" | custom
}

pub struct GatewayClaims {
  sub : String                             // Subject (required)
  exp : Int64                              // Expiration timestamp (required)
  nbf : Option[Int64]                      // Not-before timestamp (optional)
  iss : Option[String]                     // Issuer (optional)
  role : Option[String]                    // Role (optional, defaults to "guest")
}
```

## Usage

```moonbit
// Create an HS256 key and sign a token
let key = @mb_jwt.JwtKey::HS256("my-cluster-secret")
let payload = "{\"sub\":\"user_abc\",\"exp\":2000000000,\"role\":\"admin\"}"
let token = match @mb_jwt.sign(payload, key) {
  Ok(t) => t
  Err(_) => abort("sign failed")
}

// Validate through the filter
let ctx = new_stream_context(token)
execute_security_filter(ctx, key, 1000000000L)

if ctx.is_allowed {
  // Authorized — route to handler
  println("role: \{ctx.user_role}")
} else {
  // Rejected — inspect ctx.error_message for action
  println("denied: \{ctx.error_message}")
}
```

### Using ES256 (Asymmetric Keys)

The filter accepts **any `JwtKey` variant**, so switching to a public-key infrastructure is a one-line change:

```moonbit
let public_key = // 32-byte P-256 public key
execute_security_filter(ctx, @mb_jwt.JwtKey::ES256(public_key), current_time)
```

## Dependencies

- `mb_jwt` — JWT sign/verify (HS256, ES256)
- `mb-p256` — ECDSA P-256 (for ES256 tests)