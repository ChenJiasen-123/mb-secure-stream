# mb-secure-stream

An industrial-grade, high-performance streaming cryptography library written purely in MoonBit, tailored for WebAssembly (WASM-GC) and cloud-native edge computing environments.

---

## Overview

`mb-secure-stream` serves as the high-level orchestration layer of your cryptographic workspace. It integrates underlying low-level modules (`mb-hash`, `mb-chacha`, `mb-aead`, and `mb-getrandom`) into a unified, secure pipe. 

> **Project Evolution & Enhancement**: 
> This library is built as an advanced, production-ready enhancement on top of the existing cryptographic foundation found at [mb-crypto](https://github.com/moonbit-crypto/mb-crypto). It extends those core primitives by introducing stateful stream sequencing and robust chunked sealing defenses.

By employing a **stateful sliding-window streaming state machine** and an augmented **Chunked AEAD protocol**, it enables the processing of arbitrary data sizes under constant memory overhead $\mathcal{O}(1)$, completely eliminating memory-bloat vulnerabilities and preventing stream truncation or chunk-reordering attacks during large network I/O or file transfers.

---

## Cryptographic Protocol & Byte Layout

To mitigate truncation, replay, and long-stream classification attacks, the engine splits continuous data streams into fixed-size chunks of size $L = 4096 \text{ bytes}$. Each chunk is sealed independently inside a unique **Crypto Envelope** bound chronologically to the stream session via an internal sequence counter.

### Envelope Binary Structure

Every transmitted block adheres strictly to the following byte allocation schema:

```text
┌────────────────────────┬────────────────────────┬────────────────────────┬────────────────────────┐
│        Nonce (N)       │   Length Indicator     │   Ciphertext (C)       │   Poly1305 Tag (T)     │
│        12 Bytes        │        4 Bytes         │     Variable (L)       │        16 Bytes        │
└────────────────────────┴────────────────────────┴────────────────────────┴────────────────────────┘
```

The cryptographic transformations for each sequential chunk $i$ are formally defined as:

$$\mathbf{Nonce}_i = \text{mb-getrandom}(12 \text{ bytes})$$

$$\mathbf{AAD}_i = \text{Serialize}(i \mathbin{\Vert} \text{IsLastFlag})$$

$$C_i = \mathbf{E}_{K}(N_i, P_i)$$

$$T_i = \mathbf{\text{Poly1305}}_{K}(N_i, \mathbf{AAD}_i \mathbin{\Vert} \text{Length} \mathbin{\Vert} C_i)$$

Where:
* $P_i$ represents the plaintext payload chunk.
* $\mathbf{E}_{K}$ denotes the ChaCha20 stream cipher transformation using key $K$.
* $\Vert$ denotes binary concatenation.
* $\text{IsLastFlag}$ is a single terminal byte ($0x00$ for intermediate chunks, $0x01$ for the final chunk).

>  **Security Assurance**: Any unauthorized dropping of trailing envelopes, swapping of chunk order, or structural modifications to $C_i$ or $N_i$ alters the computed $\mathbf{AAD}_i$, triggering an immediate validation failure via $T_i$, resulting in an atomic stream termination.

---

## Key Features

* **Stateful Chunked AEAD Security Model**: Extends the core design principles of RFC 5116. Data streaming is strictly compartmentalized and sequenced, guaranteeing that an isolated corruption event does not invalidate the entire stream history while providing innate immunity to truncation attacks.
* **Bounded $\mathcal{O}(1)$ Memory Footprint**: Instead of loading whole files or large buffers into memory, the sliding-window architecture processes incoming bytes via small, deterministic buffers. Memory allocation remains flat regardless of whether the payload is $1 \text{ KB}$ or $10 \text{ GB}$.
* **Zero-Trust Identity Handshake**: Integrates seamlessly with `mb-jwt`. Prior to initiating the streaming state machine, symmetric node authentication is enforced, linking identity validation directly to the encrypted channel establishment.

---

## Project Dependency Tree

This project sits at the apex of your cryptographic subsystem. The layout of the workspace components is structured as follows:

```text
crypto/
├── mb-aead/           # Poly1305 MAC and authenticated encryption mechanics
├── mb-chacha/         # ChaCha20 stream encryption core
├── mb-getrandom/      # Cryptographically secure pseudorandom number generator (CSPRNG)
├── mb-hash/           # SHA256 / SHA512 hashing primitives
│   └── src/
│       └── sha2/      # Structural SHA2 core implementations
├── mb-hkdf/           # HMAC-based Extract-and-Expand Key Derivation Function
├── mb-hmac/           # Keyed-Hashing for Message Authentication primitives
├── mb-jwt/            # Pre-stream node authentication token mechanism
└── mb-secure-stream/  # ──► Main streaming engine package
    ├── moon.pkg.json  # Declares local imports of the sub-modules
    └── src/
        ├── protocol.mbt  # Binary packet serialization/deserialization
        ├── encrypt.mbt   # Chunked encryption sliding-window machine
        ├── decrypt.mbt   # Chunked decryption sliding-window machine
        └── stream_test.mbt
```

---

## Dependency Configuration
Configure your crypto/mb-secure-stream/moon.pkg.json to link the components:

```text
JSON
{
  "name": "mb-secure-stream",
  "version": "0.1.0",
  "description": "An industrial-grade streaming cryptography library for MoonBit using Chunked AEAD.",
  "license": "Apache-2.0",
  "import": [
    "crypto/mb-hash",
    "crypto/mb-chacha",
    "crypto/mb-aead",
    "crypto/mb-getrandom"
  ]
}
```

---

## 💡 Quick Start Architecture Example
### 1. Pre-Stream Identity Verification (mb-jwt)
Code snippet
```text
// Server-side boundary interception
match @mb-jwt.verify_and_validate(incoming_token, "cluster-shared-secret", 1750000000L, None, None) {
  Ok(payload) => {
    let node_id = payload.sub.default("unknown_node")
    println("Node \{node_id} successfully authenticated. Initiating mb-secure-stream tunnel.")
  }
  Err(err) => {
    println("Handshake rejected. Authentication failed: \{err}")
    // Terminate connection
  }
}
```
### 2. Stream Serialization (mb-secure-stream)
Code snippet
```text
// Encapsulating raw data into a structured crypto-envelope
let envelope : CryptoEnvelope = {
  nonce: current_nonce,
  length: 4096U,
  ciphertext: encrypted_buffer,
  tag: authentication_tag
}

// Convert state to flat binary byte array ready for network Socket I/O pump
let binary_wire_stream : Array[UInt] = @mb-secure-stream.serialize_envelope(envelope)
```

---

## 📜 License
Licensed under the Apache License, Version 2.0.