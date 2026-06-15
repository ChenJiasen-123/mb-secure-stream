# mb-secure-stream

**Industrial-Grade Streaming JWT Gateway & Cryptography Engine for MoonBit / WebAssembly**

A high-performance, security-hardened streaming cryptography library written purely in [MoonBit](https://www.moonbitlang.com), designed for **WebAssembly (WASM-GC)** and **cloud-native edge computing** environments.

> Built on top of [mb-crypto](https://github.com/moonbit-crypto/mb-crypto) core primitives, extending them with a zero-copy JWT gateway pipeline, constant-time cryptographic verification, and a stateful Chunked AEAD streaming protocol.

---

## Architecture

### Request Flow: Token → Gateway → Context

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Inbound Request (HTTP/WS/gRPC)                       │
└───────────────────────────┬─────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  1. Token Extraction                                                        │
│     Raw JWT extracted from Authorization header or protocol metadata        │
│     e.g. "eyJhbGciOiJIUzI1NiIs...3gFcS0"                                    │
└───────────────────────────┬─────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  2. Zero-Copy Token Splitting  (O(1) heap — no substring allocations)       │
│                                                                             │
│     Token: ┌───────header────────┬───────payload──────┬────signature─────┐  │
│            0─────────────────dot1──────────────dot2─────────────────len     │
│                                                                             │
│     Returns: TokenParts { header_start, header_end, payload_start,          │
│                           payload_end, signature_start, signature_end }     │
│     No String[3] allocated.  Only two Int indices scanned from original.    │
└───────────────────────────┬─────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  3. Constant-Time Signature Verification                                    │
│                                                                              │
│     ┌─── header ───┐  ┌─── payload ──┐                                      │
│     │ base64url    │  │ base64url    │                                      │
│     │ decode_range │  │ decode_range │                                      │
│     └──────┬───────┘  └──────┬───────┘                                      │
│            │                 │                                              │
│            └─────┬───────────┘                                              │
│                  ▼                                                          │
│     Signing Input: "header_enc.payload_enc"                                 │
│                  │                                                          │
│                  ▼                                                          │
│     HMAC-SHA256(secret) ──► expected_sig                                    │
│                  │                                                          │
│                  ▼                                                          │
│     constant_time_eq(expected_sig, actual_sig)  ◄─── decoded from range     │
│         │                                           │                       │
│         │ (bitwise XOR across all bytes,            │                       │
│         │  no early return on mismatch)             │                       │
│         ▼                                           │                       │
│     ╔══════════════════════╗                        │                       │
│     ║  Timing Attack       ║  XOR accumulator       │                       │
│     ║  Impossible: every   ║  includes length       │                       │
│     ║  comparison takes    ║  difference too        │                       │
│     ║  identical wall time ║                        │                       │
│     ╚══════════════════════╝                        │                       │
└───────────────────────────┬─────────────────────────┘───────────────────────┘
                            │
                    ┌───────┴───────┐
                    ▼               ▼
                 VALID          INVALID
                    │               │
                    │               ▼
                    │          Reject 401
                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  4. Gateway Claims Parsing & Expiry Check                                   │
│                                                                             │
│     JSON ├── sub: "user_abc123"                                             │
│          ├── exp: 1783928400  ◄─── if current_time >= exp → BLOCKED         │
│          ├── iss: "auth.example.com"                                        │
│          └── role: "admin" / "guest" (default)                              │
│                                                                             │
│     ┌──────────────────────────────────┐                                    │
│    │  StreamContext {                  │                                    │
│     │    is_allowed: true,             │                                    │
│     │    user_role: "admin",           │                                    │
│     │    error_message: ""             │                                    │
│     │  }                               │                                    │
│     └──────────────────────────────────┘                                    │
└───────────────────────────┬─────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  5. Context Injection into Downstream Pipeline                              │
│                                                                             │
│     StreamContext ──► Business Logic / Encrypted Stream Tunnel              │
│                        │                                                    │
│                        ├── is_allowed == true  →  Process request           │
│                        └── user_role == "admin" →  Elevated privileges      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Module Dependency Tree

```
mb-secure-stream/
├── crypto/
│   ├── mb-jwt/                  # JWT sign/verify + zero-copy decoder
│   │   ├── src/
│   │   │   ├── jwt.mbt          # HS256 / ES256 sign, verify, decode
│   │   │   ├── base64url.mbt    # Base64URL encode/decode + range decoding
│   │   │   ├── types.mbt        # JWTPayload, JWTHeader, ValidationError
│   │   │   └── jwt_test.mbt     # 28 tests
│   │   └── moon.mod.json
│   ├── mb-hmac/                 # HMAC-SHA256
│   ├── mb-hash/                 # SHA-2 family
│   ├── mb-chacha/               # ChaCha20 stream cipher
│   ├── mb-aead/                 # Poly1305 AEAD
│   ├── mb-p256/                 # ECDSA P-256
│   ├── mb-hkdf/                 # HKDF key derivation
│   └── mb-getrandom/            # Secure random bytes
└── gateway/                     # Token validation middleware
    ├── src/
    │   ├── middleware.mbt        # StreamContext + execute_security_filter
    │   ├── payload.mbt          # GatewayClaims + parse_gateway_claims
    │   └── gateway_test.mbt     # 21 tests
    ├── moon.pkg.json
    └── moon.mod.json
```

---

## Security & Performance Features

### 🛡️ Constant-Time Signature Verification

| Attack Vector | Defense |
|---|---|
| **Timing Side-Channel** | Signature comparison uses pure bitwise XOR accumulation — **no early returns**, no `if a[i] != b[i]` branches. Every comparison runs through all bytes, producing identical wall-clock time regardless of where (or if) a mismatch occurs. |
| **Length Leakage** | Even when the two signatures have *different lengths*, the comparison still iterates to the minimum length and folds the length difference into the XOR accumulator via `diff = diff | (len_a ^ len_b)`. |

```
Before (VULNERABLE):          After (SECURE):
  if a.len() != b.len()         let min = min(a.len(), b.len())
    return false    ← leak!     diff = 0
  for i in 0..<a.len()          for i in 0..<min
    if a[i] != b[i]               diff |= a[i] ^ b[i]
      return false ← leak!      diff |= a.len() ^ b.len()
  return true                    return diff == 0
```

### ⚡ Zero-Copy Token Splitting (GC-Free Hot Path)

Traditional JWT implementations split the token string into three substrings (`header`, `payload`, `signature`) using `String.split(".")`. This creates **3 String allocations per verification** — catastrophic under high-throughput gateway load.

**Our approach:** A `split_token_indices()` function that scans the original token for the two dot `.` positions and returns a lightweight `TokenParts` struct containing only integer index ranges:

```moonbit
priv struct TokenParts {
  header_start : Int
  header_end : Int
  payload_start : Int
  payload_end : Int
  signature_start : Int
  signature_end : Int
}
```

Combined with `base64url_decode_range(source, start, end)`, base64url decoding operates **directly on the original token string** without ever extracting substrings. The result: **zero heap allocations** on the token-parsing hot path.

| Metric | Traditional Split | Zero-Copy (this lib) |
|--------|:-:|:-:|
| Heap allocations per verify | 3+ `String` objects | **0** |
| GC pressure | High under load | **None** |
| Memory bandwidth | Copies bytes 3× | **1× scan only** |

### 🔐 Additional Hardening

- **alg:none Rejection** — Headers containing `"alg":"none"` are explicitly blocked (CVE-2016-5431 mitigation)
- **Algorithm Pinning** — Each verify path enforces the expected algorithm (HS256 / ES256), preventing algorithm confusion attacks
- **Range-Based Decoding** — All base64url operations can decode directly from string slices using `(source, start, end)` — no intermediate copies
- **Expiry Boundary** — `current_time >= claims.exp` correctly treats the expiration timestamp as an exclusive upper bound

---

## Quick Start

### 1. Clone and Run Tests

```bash
git clone https://github.com/ChenJiasen-123/mb-secure-stream.git
cd mb-secure-stream

# Run all JWT crypto tests (28 tests)
cd crypto/mb-jwt && moon test

# Run all gateway middleware tests (21 tests)
cd ../../gateway && moon test
```

### 2. Integrate Gateway Middleware into Your Service

The following is a complete, copy-pasteable example that signs a JWT, passes it through the security filter, and verifies the result:

```moonbit
// === Step 1: Sign a token with user claims ===
let secret = "my-cluster-secret"
let current_time = 1000000000L  // e.g. Unix timestamp
let future_exp = 2000000000L

let payload = "{\"sub\":\"user_abc123\",\"exp\":\{future_exp},\"iss\":\"auth.example.com\",\"role\":\"admin\"}"
let token = @mb_jwt.sign(payload, secret)

// === Step 2: Create gateway context and run security filter ===
let ctx = new_stream_context(token)
execute_security_filter(ctx, secret, current_time)

// === Step 3: Check result ===
if ctx.is_allowed {
  println("✅ Access granted for role: \{ctx.user_role}")
  // Proceed with business logic...
} else {
  println("❌ Access denied: \{ctx.error_message}")
  // Return 401 Unauthorized
}
```

### 3. Expected Output

```
✅ Access granted for role: admin
```

### 4. Running the Full Test Suite

```bash
# From project root
cd crypto/mb-jwt && moon test
# Total tests: 28, passed: 28, failed: 0.

cd ../../gateway && moon test
# Total tests: 21, passed: 21, failed: 0.
```

**49 tests total — all passing.**

---

## Cryptographic Protocol (Stream Encryption)

When the JWT gateway authorizes a session, data flows through the **Chunked AEAD** streaming engine:

### Envelope Binary Structure

```text
┌────────────────────────┬────────────────────────┬────────────────────────┬────────────────────────┐
│        Nonce (N)       │   Length Indicator     │   Ciphertext (C)       │   Poly1305 Tag (T)     │
│        12 Bytes        │        4 Bytes         │     Variable (L)       │        16 Bytes        │
└────────────────────────┴────────────────────────┴────────────────────────┴────────────────────────┘
```

Each chunk $i$ is sealed with:

$$\mathbf{Nonce}_i = \text{sec-random}(12)$$
$$\mathbf{AAD}_i = \text{Serialize}(i \parallel \text{IsLastFlag})$$
$$C_i = \mathbf{ChaCha20}_K(N_i, P_i)$$
$$T_i = \mathbf{Poly1305}_K(N_i, \mathbf{AAD}_i \parallel \text{Length} \parallel C_i)$$

- **Truncation protection**: The `IsLastFlag` (0x00 = more, 0x01 = final) prevents premature stream termination.
- **Replay protection**: The sequence counter $i$ in AAD binds each chunk to its position, preventing reordering attacks.
- **Bounded memory**: $\mathcal{O}(1)$ — fixed 4 KB sliding-window buffers regardless of total payload size.

---

## API Reference

### `mb-jwt` (crypto/mb-jwt)

| Function | Description |
|----------|-------------|
| `sign(payload, secret) -> String` | Create a signed JWT (HS256) |
| `verify(token, secret) -> Result[String, String]` | Constant-time verify + decode |
| `decode(token) -> Result[String, String]` | Decode payload without verification |
| `decode_header(token) -> Result[String, String]` | Decode the JWT header |
| `sign_es256(payload, private_key) -> Result[String, String]` | Sign with ES256 (ECDSA P-256) |
| `verify_es256(token, public_key) -> Result[String, String]` | Verify ES256 token |
| `validate_claims(payload, current_time, iss, aud)` | Validate standard JWT claims |
| `base64url_encode(data) -> String` | Base64URL encode (RFC 4648) |
| `base64url_decode(encoded) -> Array[UInt]` | Base64URL decode |
| `base64url_decode_range(source, start, end) -> Array[UInt]` | **Zero-copy** range decode |
| `base64url_decode_range_to_string(source, start, end) -> String` | **Zero-copy** range decode to string |

### `gateway` (gateway/src)

| Function | Description |
|----------|-------------|
| `new_stream_context(token) -> StreamContext` | Create a security context |
| `execute_security_filter(ctx, secret, current_time)` | Run the full security pipeline |
| `parse_gateway_claims(json) -> Result[GatewayClaims, String]` | Parse gateway-specific claims |

---

## License

Licensed under the **Apache License, Version 2.0**.
