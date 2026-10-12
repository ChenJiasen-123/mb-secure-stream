# mb-aead

ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) for MoonBit (RFC 8439).

## Status

Experimental implementation. Tests cover selected behavior and vectors; they do not establish production readiness or side-channel resistance.

## Reference standards

- **RFC 8439** — ChaCha20 and Poly1305 for IETF Protocols
- **RFC 7539** — ChaCha20 and Poly1305 for TLS

## Performance

No reproducible per-operation benchmark is published for this module. See the repository measurement reports for the specific configurations measured.

## Security Considerations

- **Authenticated encryption**: Provides confidentiality + integrity + authenticity
- **Tag verification**: Always verify the Poly1305 tag before using decrypted data
- **Nonce uniqueness**: Never reuse a nonce with the same key (catastrophic failure)
- **AAD binding**: Associated data is authenticated but not encrypted
- **Key size**: Requires 32-byte (256-bit) keys

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
```

### Test Coverage

- AEAD encrypt/decrypt roundtrip
- Tag verification
- AAD binding
- Wrong key rejection
- Wrong nonce rejection
- Tampered ciphertext rejection
- RFC 8439 test vectors
- Empty plaintext handling