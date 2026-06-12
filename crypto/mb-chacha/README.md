# mb-chacha

ChaCha20 stream cipher implementation for MoonBit.

## Features

- ChaCha20 stream cipher (RFC 8439)
- XChaCha20 extended nonce variant
- Constant-time implementation
- Test vectors from RFC 8439

## Usage

```moonbit
use moonbitlang/mb-chacha

fn main {
  let key = Bytes::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  let nonce = Bytes::from_hex("000000000000004a00000000")
  
  let cipher = ChaCha20::new(key, nonce)?
  cipher.apply_keystream(plaintext)
}
```

## Security Notes

- ChaCha20 is a stream cipher and should not be used without authentication
- Consider using ChaCha20-Poly1305 (from mb-aead) for authenticated encryption
- Never reuse a nonce with the same key

## License

Apache-2.0