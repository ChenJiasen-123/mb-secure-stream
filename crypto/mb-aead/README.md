# mb-aead

ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) for MoonBit (RFC 8439).

## Status

Production-ready. Encrypt-and-authenticate with a single call.

## API

| Function | Description |
|----------|-------------|
| `aead_encrypt(key, nonce, plaintext, aad)` | AEAD encrypt (Array[UInt]) |
| `aead_decrypt(key, nonce, ciphertext, aad)` | AEAD decrypt + verify (Array[UInt]) |
| `aead_encrypt_bytes(key, nonce, plaintext, aad)` | AEAD encrypt (Bytes API) |
| `aead_decrypt_bytes(key, nonce, ciphertext, aad)` | AEAD decrypt + verify (Bytes API) |

## Usage

```moonbit
let key = Bytes::make(32, 0x42)
let nonce = Bytes::make(12, 0x01)
let plaintext = Bytes::of_string("hello")
let aad = Bytes::of_string("aad")

let ciphertext = aead_encrypt_bytes(key, nonce, plaintext, aad)
let decrypted = aead_decrypt_bytes(key, nonce, ciphertext, aad)
```

## Tests

```bash
cd crypto/mb-aead && moon test