# mb-chacha

ChaCha20 and XChaCha20 stream ciphers for MoonBit (RFC 8439).

## Status

Production-ready. HChaCha20 subkey derivation, ChaCha20/XChaCha20 with configurable counter.

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