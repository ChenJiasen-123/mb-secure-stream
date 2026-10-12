# mb-chacha

ChaCha20 and XChaCha20 stream ciphers for MoonBit (RFC 8439).

## Status

Experimental implementation. Tests cover selected behavior and vectors; they do not establish production readiness or side-channel resistance.

## Reference standards

- **RFC 8439** — ChaCha20 and Poly1305 for IETF Protocols
- **RFC 7539** — ChaCha20 and Poly1305 for TLS

## Performance

No reproducible per-operation benchmark is published for this module. See the repository measurement reports for the specific configurations measured.

## Security Considerations

- **Nonce uniqueness**: ChaCha20 requires unique nonce for each encryption (never reuse)
- **XChaCha20 advantage**: 24-byte nonce makes random nonce generation safe (birthday bound ~2^96)
- **No authentication**: ChaCha20 is encryption-only; use with Poly1305 (AEAD) for authenticated encryption
- **Counter overflow**: After 2^32 blocks, generate a new key/nonce

## API

| Function | Description |
|----------|-------------|
| `ChaCha20::new(key, nonce)` | Create ChaCha20 cipher (12-byte nonce) |
| `ChaCha20::encrypt(plaintext)` | Encrypt into a new Array[UInt] |
| `ChaCha20::encrypt_bytes(plaintext)` | Encrypt (Bytes) |
| `ChaCha20::decrypt(ciphertext)` | Decrypt into a new Array[UInt] |
| `ChaCha20::decrypt_bytes(ciphertext)` | Decrypt (Bytes) |
| `ChaCha20::apply_keystream(data)` | Return a new array XORed with the keystream |
| `ChaCha20::set_counter(n)` | Set block counter |
| `XChaCha20::new(key, nonce)` | Create XChaCha20 cipher (24-byte nonce) |
| `XChaCha20::encrypt(plaintext)` | Encrypt into a new array |
| `XChaCha20::encrypt_bytes(plaintext)` | Encrypt (Bytes) |
| `XChaCha20::decrypt(ciphertext)` | Decrypt into a new array |
| `XChaCha20::decrypt_bytes(ciphertext)` | Decrypt (Bytes) |
| `hchacha20(key_words, nonce_words)` | HChaCha20 subkey derivation |

## Usage

Constructors return a Result. Supply a 32-byte key and a 12-byte ChaCha20 nonce (24 bytes for XChaCha20), handle errors, and never reuse a key/nonce pair. Prefer the authenticated secretstream API for file encryption.

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