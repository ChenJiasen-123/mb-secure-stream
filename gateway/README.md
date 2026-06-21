# Gateway — JWT Security Filter Middleware

Validates JWT tokens and produces a `StreamContext` with authorization decisions.

## Pipeline

```
Token → verify() → parse_gateway_claims() → validate_claims() → StreamContext
```

| Step | Function | Purpose |
|------|----------|---------|
| 1 | `verify(token, key)` | Constant-time HMAC/ECDSA signature check |
| 2 | `parse_gateway_claims(json)` | Extract sub, exp, nbf, iss, role |
| 3 | `validate_claims(payload, time)` | Check exp, nbf, iss, aud |

## API

| Function | Description |
|----------|-------------|
| `new_stream_context(token)` | Create security context |
| `execute_security_filter(ctx, key, time)` | Run full pipeline |
| `parse_gateway_claims(json)` | Parse gateway claims |

## Usage

```moonbit
let key = @mb_jwt.JwtKey::HS256("secret")
let ctx = new_stream_context(token)
execute_security_filter(ctx, key, current_time)
if ctx.is_allowed {
  println("role: " + ctx.user_role)
}
```

## Tests

```bash
cd gateway && moon test
```
