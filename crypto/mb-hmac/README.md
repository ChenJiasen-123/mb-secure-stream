# mb-hmac

HMAC (Hash-Based Message Authentication Code) for MoonBit — SHA-256 and SHA-512 variants.

## Status

Production-ready. Constant-time comparison for secure MAC verification.

## RFC Compliance

- **RFC 2104** — HMAC: Keyed-Hashing for Message Authentication
- **RFC 4231** — Identifiers and Test Vectors for HMAC-SHA-224/256/384/512

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| HMAC-SHA256 | ~20μs | 32-byte key, 64-byte message |
| HMAC-SHA512 | ~35μs | 64-byte key, 128-byte message |
| Verification | ~20μs | Constant-time comparison |

## Security Considerations

- **Constant-time verification**: All MAC comparisons use `constant_time_eq` to prevent timing attacks
- **Key length validation**: Rejects keys longer than block size (64 bytes for SHA-256, 128 bytes for SHA-512)
- **Block-size padding**: Automatic key padding per RFC 2104
- **No key leakage**: Keys are never exposed in output or error messages

## API

| Function | Description |
|----------|-------------|
| `hmac_sha256(message, key)` | Compute HMAC-SHA256 (Array[UInt] input) |
| `hmac_sha256_bytes(message, key)` | Compute HMAC-SHA256 (Bytes input) |
| `hmac_sha256_string(message, key)` | Compute HMAC-SHA256 (String input) |
| `verify_hmac_sha256(message, key, mac)` | Constant-time HMAC-SHA256 verification |
| `verify_hmac_sha256_bytes(message, key, mac)` | Constant-time verification (Bytes input) |
| `hmac_sha512(message, key)` | Compute HMAC-SHA512 (Array[UInt] input) |
| `hmac_sha512_bytes(message, key)` | Compute HMAC-SHA512 (Bytes input) |
| `hmac_sha512_string(message, key)` | Compute HMAC-SHA512 (String input) |
| `verify_hmac_sha512(message, key, mac)` | Constant-time HMAC-SHA512 verification |
| `verify_hmac_sha512_bytes(message, key, mac)` | Constant-time verification (Bytes input) |

## Usage

```moonbit
let key = string_to_uints("secret-key")
let msg = string_to_uints("hello world")

let mac = hmac_sha256(msg, key)
let ok = verify_hmac_sha256(msg, key, mac)
```

## Tests

```bash
cd crypto/mb-hmac && moon test
```

### Test Coverage

- HMAC-SHA256 computation
- HMAC-SHA512 computation
- Constant-time verification
- Key length validation
- Empty message handling
- Empty key handling
- RFC 4231 test vectors