# mb-poly1305

Poly1305 one-time authenticator for MoonBit (RFC 7539).

## Status

Experimental, unaudited implementation. Compiled constant-time behavior and production safety are not established.

## RFC Compliance

- **RFC 7539** — ChaCha20 and Poly1305 for TLS
- **RFC 8439** — ChaCha20 and Poly1305 for IETF Protocols

## Performance

No validated portable performance guarantee. See [allocation optimization evidence](../../docs/allocation-optimization.md) for a bounded synthetic JS measurement and its limits.

## Security Considerations

- **One-time authenticator**: Poly1305 is a one-time MAC; never reuse the key for multiple messages
- **Key size**: Requires 32-byte (256-bit) keys
- **Verification**: Equal-length tags use an accumulator comparison; compiled timing-attack resistance is not established
- **Tag size**: 16-byte (128-bit) authentication tag
- **Combined with ChaCha20**: Typically used as ChaCha20-Poly1305 AEAD

## API

| Function | Description |
|----------|-------------|
| `poly1305_mac(key, message)` | Compute Poly1305 MAC (Array[UInt]) |
| `poly1305_mac_bytes(key, message)` | Compute Poly1305 MAC (Bytes) |
| `poly1305_verify(key, message, tag)` | Verify Poly1305 MAC (Array[UInt]) |
| `poly1305_verify_bytes(key, message, tag)` | Verify Poly1305 MAC (Bytes) |

## Usage

This is a low-level one-time MAC primitive. For authenticated streams use the
[secretstream interface](../../docs/secretstream-api.md), which manages the
protocol state and per-message authentication keys. Exact primitive signatures
are in `src/pkg.generated.mbti`; callers must never reuse a Poly1305 key.

## Tests

```bash
moon test crypto/mb-poly1305/src
```

### Test Coverage

- Poly1305 MAC computation
- Poly1305 verification
- Signature comparison correctness (runtime constant-time behavior unverified)
- Wrong key rejection
- Tampered message rejection
- RFC 7539 test vectors
- Empty message handling