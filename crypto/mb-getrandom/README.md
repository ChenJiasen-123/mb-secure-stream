# mb-getrandom

Secure random bytes for MoonBit — platform-native CSPRNG.

## Reference standards

- **RFC 4086** — Randomness Requirements for Security

## API

`getrandom(length : Int) -> Result[Bytes, String]` allocates and returns random bytes. Non-positive lengths return an error. There is no public buffer-fill overload or `getrandom_bytes` function.

JS uses host crypto facilities and native uses the platform shim. Wasm requires the documented crypto host imports: a host exception can trap instead of returning an error. Availability and blocking behavior depend on the host.

## Tests

```bash
moon test crypto/mb-getrandom/src/lib --target js
```

### Test Coverage

- Random byte generation
- Statistical randomness (basic)
- Error handling
- Various lengths
Web Crypto backends split positive requests into calls of at most 65536 bytes. JS returns an error on host failure; Wasm host failure can still trap.
