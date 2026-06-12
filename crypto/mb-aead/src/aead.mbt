// ChaCha20-Poly1305 AEAD (RFC 8439 Section 2.8)

fn bytes_to_uint_array(bytes : Bytes) -> Array[UInt] {
  let arr : Array[UInt] = []
  for i in 0..<bytes.length() {
    arr.push(bytes[i].to_int().reinterpret_as_uint())
  }
  arr
}

fn uints_to_bytes(values : Array[UInt]) -> Bytes {
  let buf : Array[Byte] = []
  for value in values {
    buf.push((value & 0xFFU).to_byte())
  }
  Bytes::from_array(buf)
}

/// Encode a 64-bit value as 8 bytes in little-endian order.
fn le64(value : UInt64) -> Array[UInt] {
  let out : Array[UInt] = []
  out.push((value & 0xFFUL).to_uint())
  out.push(((value >> 8) & 0xFFUL).to_uint())
  out.push(((value >> 16) & 0xFFUL).to_uint())
  out.push(((value >> 24) & 0xFFUL).to_uint())
  out.push(((value >> 32) & 0xFFUL).to_uint())
  out.push(((value >> 40) & 0xFFUL).to_uint())
  out.push(((value >> 48) & 0xFFUL).to_uint())
  out.push(((value >> 56) & 0xFFUL).to_uint())
  out
}

/// Pad length to 16-byte boundary with zeros.
fn pad16_zeros(data_len : Int) -> Array[UInt] {
  let remainder = data_len % 16
  if remainder == 0 {
    return []
  }
  let pad_len = 16 - remainder
  let out : Array[UInt] = []
  let mut i = 0
  while i < pad_len {
    out.push(0U)
    i = i + 1
  }
  out
}

/// Build the Poly1305 mac_data per RFC 8439 Section 2.8:
/// AAD || pad(AAD) || ciphertext || pad(ciphertext) || le64(aad_len) || le64(ct_len)
fn build_mac_data(
  aad : Array[UInt],
  ciphertext : Array[UInt],
) -> Array[UInt] {
  let mac_data : Array[UInt] = []
  // AAD
  for v in aad {
    mac_data.push(v)
  }
  // pad AAD to 16-byte boundary
  for v in pad16_zeros(aad.length()) {
    mac_data.push(v)
  }
  // ciphertext
  for v in ciphertext {
    mac_data.push(v)
  }
  // pad ciphertext to 16-byte boundary
  for v in pad16_zeros(ciphertext.length()) {
    mac_data.push(v)
  }
  // le64(aad_len)
  for v in le64(aad.length().reinterpret_as_uint().to_uint64()) {
    mac_data.push(v)
  }
  // le64(ct_len)
  for v in le64(ciphertext.length().reinterpret_as_uint().to_uint64()) {
    mac_data.push(v)
  }
  mac_data
}

/// Constant-time comparison of two byte arrays.
fn constant_time_eq(a : Array[UInt], b : Array[UInt]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0U
  for i in 0..<a.length() {
    diff = diff | (a[i] ^ b[i])
  }
  diff == 0U
}

/// Encrypt and authenticate using ChaCha20-Poly1305 AEAD.
///
/// Returns (ciphertext, 16-byte tag) on success.
pub fn aead_encrypt(
  key : Array[UInt],
  nonce : Array[UInt],
  aad : Array[UInt],
  plaintext : Array[UInt],
) -> Result[(Array[UInt], Array[UInt]), String] {
  if key.length() != 32 {
    return Err("AEAD key must be 32 bytes")
  }
  if nonce.length() != 12 {
    return Err("AEAD nonce must be 12 bytes")
  }
  // Step 1: Create ChaCha20 at counter=0, generate block for Poly1305 key
  match @chacha.ChaCha20::new_from_uints_with_counter(key, nonce, 0U) {
    Err(e) => return Err(e)
    Ok(cipher) => {
      let block0 = cipher.generate_block() // counter becomes 1
      let poly_key : Array[UInt] = []
      for i in 0..<32 {
        poly_key.push(block0[i])
      }
      // Step 2: Encrypt plaintext (counter starts at 1 since generate_block incremented it)
      let ciphertext = cipher.apply_keystream(plaintext)
      // Step 3: Build mac_data and compute tag
      let mac_data = build_mac_data(aad, ciphertext)
      let tag = @poly1305.poly1305_mac(poly_key, mac_data)
      Ok((ciphertext, tag))
    }
  }
}

/// Decrypt and verify using ChaCha20-Poly1305 AEAD.
///
/// Returns plaintext on success, error if authentication fails.
pub fn aead_decrypt(
  key : Array[UInt],
  nonce : Array[UInt],
  aad : Array[UInt],
  ciphertext : Array[UInt],
  tag : Array[UInt],
) -> Result[Array[UInt], String] {
  if key.length() != 32 {
    return Err("AEAD key must be 32 bytes")
  }
  if nonce.length() != 12 {
    return Err("AEAD nonce must be 12 bytes")
  }
  if tag.length() != 16 {
    return Err("AEAD tag must be 16 bytes")
  }
  // Step 1: Derive Poly1305 key
  match @chacha.ChaCha20::new_from_uints_with_counter(key, nonce, 0U) {
    Err(e) => return Err(e)
    Ok(cipher) => {
      let block0 = cipher.generate_block()
      let poly_key : Array[UInt] = []
      for i in 0..<32 {
        poly_key.push(block0[i])
      }
      // Step 2: Verify tag BEFORE decrypting (authenticate-then-decrypt)
      let mac_data = build_mac_data(aad, ciphertext)
      let expected_tag = @poly1305.poly1305_mac(poly_key, mac_data)
      if !constant_time_eq(expected_tag, tag) {
        return Err("Authentication failed")
      }
      // Step 3: Decrypt (counter is already 1)
      let plaintext = cipher.apply_keystream(ciphertext)
      Ok(plaintext)
    }
  }
}

/// Encrypt and authenticate using ChaCha20-Poly1305 AEAD (Bytes API).
pub fn aead_encrypt_bytes(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Result[(Bytes, Bytes), String] {
  let key_u = bytes_to_uint_array(key)
  let nonce_u = bytes_to_uint_array(nonce)
  let aad_u = bytes_to_uint_array(aad)
  let pt_u = bytes_to_uint_array(plaintext)
  match aead_encrypt(key_u, nonce_u, aad_u, pt_u) {
    Err(e) => Err(e)
    Ok((ct, tag)) => Ok((uints_to_bytes(ct), uints_to_bytes(tag)))
  }
}

/// Decrypt and verify using ChaCha20-Poly1305 AEAD (Bytes API).
pub fn aead_decrypt_bytes(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
  tag : Bytes,
) -> Result[Bytes, String] {
  let key_u = bytes_to_uint_array(key)
  let nonce_u = bytes_to_uint_array(nonce)
  let aad_u = bytes_to_uint_array(aad)
  let ct_u = bytes_to_uint_array(ciphertext)
  let tag_u = bytes_to_uint_array(tag)
  match aead_decrypt(key_u, nonce_u, aad_u, ct_u, tag_u) {
    Err(e) => Err(e)
    Ok(pt) => Ok(uints_to_bytes(pt))
  }
}
