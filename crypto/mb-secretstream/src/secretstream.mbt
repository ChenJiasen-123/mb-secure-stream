// Compatibility prototype based on libsodium secretstream_xchacha20poly1305.c.
// See ../NOTICE for upstream provenance and ISC license.

///|
pub struct SecretStream {
  priv mut key : Array[UInt]
  priv nonce : Array[UInt]
  priv mut finished : Bool
}

///|
fn slice(data : Array[UInt], start : Int, len : Int) -> Array[UInt] {
  Array::makei(len, i => data[start + i])
}

///|
fn valid_bytes(data : Array[UInt]) -> Bool {
  for b in data {
    if b > 255U {
      return false
    }
  }
  true
}

///|
fn load32(data : Array[UInt], offset : Int) -> UInt {
  data[offset] |
  (data[offset + 1] << 8) |
  (data[offset + 2] << 16) |
  (data[offset + 3] << 24)
}

///|
/// Initialize a reader from a 32-byte key and the sender's 24-byte header.
/// Prototype only: not independently audited or ready for production use.
pub fn init_pull(
  key : Array[UInt],
  header : Array[UInt],
) -> Result[SecretStream, String] {
  if key.length() != 32 ||
    header.length() != 24 ||
    !valid_bytes(key) ||
    !valid_bytes(header) {
    return Err("Invalid key or header")
  }
  let words = FixedArray::makei(8, i => load32(key, i * 4))
  let input = FixedArray::makei(4, i => load32(header, i * 4))
  let derived = @chacha.hchacha20(words, input)
  let subkey = Array::makei(32, i => (derived[i / 4] >> (i % 4 * 8)) & 255U)
  let nonce = Array::make(12, 0U)
  nonce[0] = 1U
  for i in 0..<8 {
    nonce[4 + i] = header[16 + i]
  }
  Ok({ key: subkey, nonce, finished: false, })
}

///|
fn crypt(
  state : SecretStream,
  data : Array[UInt],
  counter : UInt,
) -> Array[UInt] {
  @chacha.ChaCha20::new_from_uints_with_counter(state.key, state.nonce, counter)
  .unwrap()
  .apply_keystream(data)
}

///|
fn store64(out : Array[UInt], offset : Int, value : Int) -> Unit {
  let v = value.to_uint64()
  for i in 0..<8 {
    out[offset + i] = ((v >> (8 * i)) & 255UL).to_uint()
  }
}

///|
fn mac(
  state : SecretStream,
  aad : Array[UInt],
  block : Array[UInt],
  ciphertext : Array[UInt],
) -> Array[UInt] {
  // libsodium's historical padding is mlen % 16, not (-mlen) % 16.
  let block_offset = aad.length() + (16 - aad.length() % 16) % 16
  let ciphertext_offset = block_offset + 64
  let lengths_offset = ciphertext_offset +
    ciphertext.length() +
    ciphertext.length() % 16
  let input = Array::make(lengths_offset + 16, 0U)
  for i in 0..<aad.length() {
    input[i] = aad[i]
  }
  for i in 0..<64 {
    input[block_offset + i] = block[i]
  }
  for i in 0..<ciphertext.length() {
    input[ciphertext_offset + i] = ciphertext[i]
  }
  store64(input, lengths_offset, aad.length())
  store64(input, lengths_offset + 8, 64 + ciphertext.length())
  @poly.poly1305_mac(crypt(state, Array::make(32, 0U), 0U), input)
}

///|
fn advance(
  state : SecretStream,
  authenticator : Array[UInt],
  tag : UInt,
) -> Unit {
  for i in 0..<8 {
    state.nonce[4 + i] = state.nonce[4 + i] ^ authenticator[i]
  }
  let mut carry = 1U
  for i in 0..<4 {
    let n = state.nonce[i] + carry
    state.nonce[i] = n & 255U
    carry = n >> 8
  }
  if (tag & 2U) != 0U || carry != 0U {
    let material = state.key.copy()
    for i in 4..<12 {
      material.push(state.nonce[i])
    }
    let next = crypt(state, material, 0U)
    state.key = slice(next, 0, 32)
    for i in 0..<8 {
      state.nonce[4 + i] = next[32 + i]
    }
    for i in 0..<4 {
      state.nonce[i] = 0U
    }
    state.nonce[0] = 1U
  }
  // The wrapper treats FINAL as terminal; raw libsodium leaves this to callers.
  if tag == 3U {
    state.finished = true
  }
}

///|
fn check_input(
  state : SecretStream,
  data : Array[UInt],
  aad : Array[UInt],
) -> Result[Unit, StreamError] {
  if state.finished {
    return Err(Finalized)
  }
  if data.length() > 1048593 ||
    aad.length() > 1048576 ||
    !valid_bytes(data) ||
    !valid_bytes(aad) {
    return Err(InvalidInput)
  }
  Ok(())
}

///|
// Deterministic sender for compatibility tests only. Production sender must
// generate a fresh random header; never reuse (key, header).
fn push(
  state : SecretStream,
  message : Array[UInt],
  aad : Array[UInt],
  tag : UInt,
) -> Result[Array[UInt], StreamError] {
  match check_input(state, message, aad) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  if message.length() > 1048576 {
    return Err(FrameTooLarge)
  }
  if tag > 3U {
    return Err(UnsupportedTag)
  }
  let tagblock = Array::make(64, 0U)
  tagblock[0] = tag
  let encrypted_tagblock = crypt(state, tagblock, 1U)
  let ciphertext = crypt(state, message, 2U)
  let authenticator = mac(state, aad, encrypted_tagblock, ciphertext)
  let out = Array::make(ciphertext.length() + 17, 0U)
  out[0] = encrypted_tagblock[0]
  for i in 0..<ciphertext.length() {
    out[1 + i] = ciphertext[i]
  }
  for i in 0..<16 {
    out[1 + ciphertext.length() + i] = authenticator[i]
  }
  advance(state, authenticator, tag)
  Ok(out)
}

///|
fn pull_checked(
  state : SecretStream,
  frame : Array[UInt],
  aad : Array[UInt],
) -> Result[(Array[UInt], UInt), StreamError] {
  match check_input(state, frame, aad) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  if frame.length() < 17 {
    return Err(TruncatedFrame)
  }
  let block = crypt(state, Array::make(64, 0U), 1U)
  let tag = frame[0] ^ block[0]
  block[0] = frame[0]
  let ciphertext = slice(frame, 1, frame.length() - 17)
  let authenticator = mac(state, aad, block, ciphertext)
  let mut mismatch = 0U
  for i in 0..<16 {
    mismatch = mismatch | (authenticator[i] ^ frame[frame.length() - 16 + i])
  }
  if mismatch != 0U {
    return Err(AuthenticationFailed)
  }
  if tag > 3U {
    return Err(UnsupportedTag)
  }
  let message = crypt(state, ciphertext, 2U)
  advance(state, authenticator, tag)
  Ok((message, tag))
}

///|
/// Call at transport EOF to distinguish a complete stream from truncation.
pub fn SecretStream::finish(state : SecretStream) -> Result[Unit, String] {
  if state.finished {
    Ok(())
  } else {
    Err("Missing FINAL frame")
  }
}

///|
pub fn SecretStream::pull(state : SecretStream, frame : Array[UInt], aad : Array[UInt]) -> Result[(Array[UInt], UInt), String] {
  match pull_checked(state, frame, aad) {
    Ok(value) => Ok(value)
    Err(error) => Err(legacy_error(error))
  }
}
