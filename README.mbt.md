# mb-secure-stream

An industrial-grade, high-performance streaming cryptography library written purely in MoonBit, tailored for WebAssembly (WASM-GC) and cloud-native edge computing.

---

## 🚀 Overview

`mb-secure-stream` serves as the high-level orchestration layer of your cryptographic workspace. It integrates underlying low-level modules (`mb-hash`, `mb-chacha`, `mb-aead`, and `mb-getrandom`) into a unified, secure pipe. 

By employing a **sliding-window streaming state machine** and a **Chunked AEAD protocol**, it enables the processing of arbitrary data sizes under constant memory overhead $O(1)$, completely eliminating memory-bloat vulnerabilities during large network I/O or file transfers.

---

## 📐 Cryptographic Protocol & Byte Layout

To mitigate truncation and long-stream classification attacks, the engine splits continuous data streams into fixed-size chunks of size $L = 4096 \text{ bytes}$. Each chunk is sealed independently inside a unique **Crypto Envelope**.

### 💾 Envelope Binary Structure

Every transmitted block adheres strictly to the following byte allocation schema:

┌────────────────────────┬────────────────────────┬────────────────────────┬────────────────────────┐
│     Nonce ($N$)        │   Length Indicator     │   Ciphertext ($C$)     │   Poly1305 Tag ($T$)   │
│        12 Bytes        │        4 Bytes         │     Variable ($L$)     │        16 Bytes        │
└────────────────────────┴────────────────────────┴────────────────────────┴────────────────────────┘
The cryptographic transformations for each chunk $i$ are formally defined as:

$$\mathbf{Nonce}_i = \text{mb-getrandom}(12 \text{ bytes})$$

$$C_i = \mathbf{E}_{K}(N_i, P_i)$$

$$T_i = \mathbf{\text{Poly1305}}_{K}(N_i, \text{Length} \mathbin{\Vert} C_i)$$

Where:
* $P_i$ represents the plaintext payload chunk.
* $\mathbf{E}_{K}$ denotes the ChaCha20 stream cipher transformation using key $K$.
* $\Vert$ denotes binary concatenation.
* Any unauthorized alteration to $C_i$ or $N_i$ triggers an immediate validation failure via $T_i$, resulting in an atomic stream termination.

---

## ✨ Key Features

* **Chunked AEAD Security Model**: Adheres to the core design principles of RFC 5116. Data streaming is compartmentalized, guaranteeing that an isolated corruption event does not invalidate the entire stream history, while providing innate immunity to truncation and replay attacks.
* **Bounded $O(1)$ Memory Footprint**: Instead of loading whole files into memory, the sliding-window architecture processes incoming bytes via small, deterministic buffers. Memory allocation remains flat regardless of whether the payload is $1 \text{ KB}$ or $10 \text{ GB}$.
* **Zero-Trust Identity Handshake**: Integrates seamlessly with `mb-jwt`. Prior to initiating the streaming state machine, asymmetric or symmetric node authentication is enforced, linking identity validation directly to the encrypted channel establishment.

---

## 📂 Project Dependency Tree

This project sits at the apex of your cryptographic subsystem. The layout of the workspace components is structured as follows:

crypto/
├── mb-hash/           # SHA256 / SHA512 hashing primitives
├── mb-chacha/         # ChaCha20 stream encryption core
├── mb-aead/           # Poly1305 MAC and authenticated encryption mechanics
├── mb-getrandom/      # Cryptographically secure pseudorandom number generator (CSPRNG)
├── mb-jwt/            # Pre-stream node authentication token mechanism
│
└── mb-secure-stream/  # ──► Main streaming engine package
├── moon.pkg.json  # Declares local imports of the sub-modules
└── src/
├── protocol.mbt  # Binary packet serialization/deserialization
├── encrypt.mbt   # Chunked encryption sliding-window machine
├── decrypt.mbt   # Chunked decryption sliding-window machine
└── stream_test.mbt


### 📦 Dependency Configuration

Configure your `crypto/mb-secure-stream/moon.pkg.json` to link the components:

```json
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
💡 Quick Start Architecture Example
1. Pre-Stream Identity Verification (mb-jwt)
Code snippet
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
2. Stream Serialization (mb-secure-stream)
Code snippet
// Encapsulating raw data into a structured crypto-envelope
let envelope : CryptoEnvelope = {
  nonce: current_nonce,
  length: 4096U,
  ciphertext: encrypted_buffer,
  tag: authentication_tag
}

// Convert state to flat binary byte array ready for network Socket I/O pump
let binary_wire_stream : Array[UInt] = @mb-secure-stream.serialize_envelope(envelope)

