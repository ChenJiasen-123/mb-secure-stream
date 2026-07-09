# mb-hmac

HMAC (Hash-Based Message Authentication Code) for MoonBit — SHA-256 and SHA-512 variants.

## Status

Production-ready. Constant-time comparison for secure MAC verification.

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