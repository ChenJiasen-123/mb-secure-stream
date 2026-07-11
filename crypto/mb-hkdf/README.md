# mb-hkdf

HKDF (HMAC-based Extract-and-Expand Key Derivation Function) for MoonBit — RFC 5869.

## Status

Production-ready. SHA-256 and SHA-512 variants.

## RFC Compliance

- **RFC 5869** — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| HKDF-SHA256 extract | ~25μs | Salt + IKM |
| HKDF-SHA256 expand | ~30μs | PRK + info |
| HKDF-SHA256 combined | ~50μs | One-shot |
| HKDF-SHA512 combined | ~70μs | One-shot |

## Security Considerations

- **Salt recommendation**: Use a random salt for extract phase (can be empty but not recommended)
- **Info binding**: Use `info` parameter to bind derived key to context
- **Key length**: Output key length ≤ 255 × hash_len (e.g., 8160 bytes for SHA-256)
- **One-way**: HKDF is a one-way function; cannot recover IKM from output key
- **No key leakage**: IKM and PRK are never exposed in output

## API

| Function | Description |
|----------|-------------|
| `hkdf_extract_sha256(salt, ikm)` | HKDF-Extract with HMAC-SHA256 |
| `hkdf_expand_sha256(prk, info, length)` | HKDF-Expand with HMAC-SHA256 |
| `hkdf_sha256(salt, ikm, info, length)` | Combined HKDF-SHA256 |
| `hkdf_extract_sha512(salt, ikm)` | HKDF-Extract with HMAC-SHA512 |
| `hkdf_expand_sha512(prk, info, length)` | HKDF-Expand with HMAC-SHA512 |
| `hkdf_sha512(salt, ikm, info, length)` | Combined HKDF-SHA512 |
| `hkdf_extract_sha256_bytes(salt, ikm)` | HKDF-Extract (Bytes API) |
| `hkdf_expand_sha256_bytes(prk, info, length)` | HKDF-Expand (Bytes API) |
| `hkdf_sha256_bytes(salt, ikm, info, length)` | Combined HKDF (Bytes API) |
| `hkdf_extract_sha512_bytes(salt, ikm)` | HKDF-Extract SHA-512 (Bytes API) |
| `hkdf_expand_sha512_bytes(prk, info, length)` | HKDF-Expand SHA-512 (Bytes API) |
| `hkdf_sha512_bytes(salt, ikm, info, length)` | Combined HKDF SHA-512 (Bytes API) |

## Usage

```moonbit
let salt = Bytes::of_string("salt")
let ikm = Bytes::of_string("input key material")
let info = Bytes::of_string("info")

let key = hkdf_sha256_bytes(salt, ikm, info, 32)
```

## Tests

```bash
cd crypto/mb-hkdf && moon test
```

### Test Coverage

- HKDF-SHA256 extract/expand
- HKDF-SHA512 extract/expand
- RFC 5869 test vectors
- Empty salt handling
- Empty info handling
- Various output lengths
- Bytes API consistency