# mb-getrandom

Secure random bytes for MoonBit — platform-native CSPRNG.

## Status

Experimental implementation. Tests cover selected behavior and vectors; they do not establish production readiness or side-channel resistance.

## Reference standards

- **RFC 4086** — Randomness Requirements for Security

## Performance

No reproducible per-operation benchmark is published for this module. See the repository measurement reports for the specific configurations measured.

## Security Considerations

- **Cryptographically secure**: Uses OS-level CSPRNG (/dev/urandom, getrandom(), CryptGenRandom)
- **No userland PRNG**: Avoids weak userland random number generators
- **Fail-safe**: Returns error if OS random source unavailable

## API

`getrandom(length : Int) -> Result[Bytes, String]` allocates and returns random bytes. Non-positive lengths return an error. There is no public buffer-fill overload or `getrandom_bytes` function.

JS uses host crypto facilities and native uses the platform shim. Wasm requires the documented crypto host imports: a host exception can trap instead of returning an error. Availability and blocking behavior depend on the host.

## Tests

```bash
cd crypto/mb-getrandom && moon test
```

### Test Coverage

- Random byte generation
- Statistical randomness (basic)
- Error handling
- Various lengths
Web Crypto backends split positive requests into calls of at most 65536 bytes. JS returns an error on host failure; Wasm host failure can still trap. Splitting removes the deterministic per-call quota failure, not arbitrary host failures.
