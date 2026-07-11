# mb-getrandom

Secure random bytes for MoonBit — platform-native CSPRNG.

## Status

Production-ready. Uses OS-level secure random sources.

## RFC Compliance

- **RFC 4086** — Randomness Requirements for Security

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| getrandom(32 bytes) | ~5μs | OS CSPRNG |
| getrandom(1KB) | ~10μs | Linear scaling |
| getrandom_bytes(32) | ~5μs | Returns new Bytes object |

## Security Considerations

- **Cryptographically secure**: Uses OS-level CSPRNG (/dev/urandom, getrandom(), CryptGenRandom)
- **Non-blocking**: Never blocks on entropy pool (uses /dev/urandom, not /dev/random)
- **No userland PRNG**: Avoids weak userland random number generators
- **Thread-safe**: Safe for concurrent use
- **Fail-safe**: Returns error if OS random source unavailable

## API

| Function | Description |
|----------|-------------|
| `getrandom(length)` | Fill buffer with secure random bytes |
| `getrandom_bytes(length)` | Return a new `Bytes` filled with secure random data |

## Usage

```moonbit
// Generate 32 random bytes for a secret key
let key = getrandom_bytes(32)

// Fill existing buffer
let mut buf : Array[UInt] = Array::make(16, 0U)
getrandom(16, buf)
```

## Tests

```bash
cd crypto/mb-getrandom && moon test
```

### Test Coverage

- Random byte generation
- Buffer filling
- Statistical randomness (basic)
- Error handling
- Various lengths