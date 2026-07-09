# mb-getrandom

Secure random bytes for MoonBit — platform-native CSPRNG.

## Status

Production-ready. Uses OS-level secure random sources.

## API

| Function | Description |
|----------|-------------|
| `getrandom(length)` | Fill buffer with secure random bytes |
| `getrandom_bytes(length)` | Return a new `Bytes` filled with secure random data |

## Usage

```moonbit
let random_bytes = getrandom_bytes(32)
```

## Tests

```bash
cd crypto/mb-getrandom && moon test