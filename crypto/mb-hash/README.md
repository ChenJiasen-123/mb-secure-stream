# mb-hash: SHA-2 Package

`mb-hash` is a simple and efficient implementation of the SHA-2 family of cryptographic hash functions for MoonBit projects inspired by Rust Crypto.

## Features

- Supports SHA-256
- Planned support for SHA-224, SHA-384, and SHA-512 and SHA3
- Zero dependencies

## Installation

Add `mb-hash` to your MoonBit project using the package manager:

```bash
moon add ChenJiasen-123/moon_jwt/crypto/mb-hash
```

Or add it to your `moon.pkg.json`:

```json
{
  "deps": {
    "ChenJiasen-123/moon_jwt/crypto/mb-hash": "*"
  }
}
```

Then in your moon.pkg.json, import the package:

```json
{
  "import": [
    "ChenJiasen-123/moon_jwt/crypto/mb-hash/sha2"
  ]
}
```

## Usage

```moonbit
let hash256 = @sha2.sha256("hello world")
println(hash256)
```

## License

MIT
