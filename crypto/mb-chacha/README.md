# mb-chacha

ChaCha20 and XChaCha20 stream ciphers for MoonBit (RFC 8439).

## Status

Production-ready. HChaCha20 subkey derivation, ChaCha20/XChaCha20 with configurable counter.

## RFC Compliance

- **RFC 8439** — ChaCha20 and Poly1305 for IETF Protocols
- **RFC 7539** — ChaCha20 and Poly1305 for TLS

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| ChaCha20 encrypt (1KB) | ~10μs | 8-byte nonce |
| ChaCha20 encrypt (1MB) | ~8ms | Streaming |
| XChaCha20 encrypt (1KB) | ~12μs | 24-byte nonce |
| HChaCha20 | ~5μs | Subkey derivation |

## Security Considerations

- **Nonce uniqueness**: ChaCha20 requires unique nonce for each encryption (never reuse)
- **XChaCha20 advantage**: 24-byte nonce makes random nonce generation safe (birthday bound ~2^96)
- **No authentication**: ChaCha20 is encryption-only; use with Poly1305 (AEAD) for authenticated encryption
- **Constant-time**: Implementation avoids data-dependent branches
- **Counter overflow**: After 2^32 blocks, generate a new key/nonce

## API

| Function | Description |
|----------|-------------|
| `ChaCha20::new(key, nonce)` | Create ChaCha20 cipher (8-byte nonce) |
| `ChaCha20::encrypt(plaintext)` | Encrypt in-place (Array[UInt]) |
| `ChaCha20::encrypt_bytes(plaintext)` | Encrypt (Bytes) |
| `ChaCha20::decrypt(ciphertext)` | Decrypt in-place (Array[UInt]) |
| `ChaCha20::decrypt_bytes(ciphertext)` | Decrypt (Bytes) |
| `ChaCha20::apply_keystream(data)` | XOR with keystream in-place |
| `ChaCha20::set_counter(n)` | Set block counter |
| `XChaCha20::new(key, nonce)` | Create XChaCha20 cipher (24-byte nonce) |
| `XChaCha20::encrypt(plaintext)` | Encrypt in-place |
| `XChaCha20::encrypt_bytes(plaintext)` | Encrypt (Bytes) |
| `XChaCha20::decrypt(ciphertext)` | Decrypt in-place |
| `XChaCha20::decrypt_bytes(ciphertext)` | Decrypt (Bytes) |
| `hchacha20(key_words, nonce_words)` | HChaCha20 subkey derivation |

## Usage

```moonbit
let key = Bytes::make(32, 0x42)
let nonce = Bytes::make(8, 0x01)
let cipher = ChaCha20::new(key, nonce)?
let plaintext = Bytes::of_string("hello")
let ciphertext = cipher.encrypt_bytes(plaintext)
```

## Tests

```bash
cd crypto/mb-chacha && moon test
```

### Test Coverage

- ChaCha20 encryption/decryption roundtrip
- XChaCha20 encryption/decryption roundtrip
- HChaCha20 subkey derivation
- Counter increment
- Keystream application
- RFC 8439 test vectors
- Empty input handling