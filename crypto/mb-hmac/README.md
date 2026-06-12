# MB Crypto Mac Library

A cryptographic MAC (Message Authentication Code) library for secure message authentication.

## Features

- Secure message authentication
- Multiple MAC algorithm support
- Easy-to-use API
- Cross-platform compatibility

## Installation

```bash
# Add installation instructions here
```

## Usage

```moonbit
// Generate MAC
let mac = @hmac.generateMAC(message, key);

// Verify MAC
let isValid = @hmac.verifyMAC(message, key, mac);
```

## API Reference

### `generateMAC(message, key)`
Generates a MAC for the given message using the provided key.

### `verifyMAC(message, key, mac)`
Verifies a MAC against the message and key.

## License

MIT License

## Contributing

Pull requests are welcome. For major changes, please open an issue first.