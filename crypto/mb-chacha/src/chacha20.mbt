const SIGMA0 : UInt = 0x61707865U // "expa"
const SIGMA1 : UInt = 0x3320646eU // "nd 3"
const SIGMA2 : UInt = 0x79622d32U // "2-by"
const SIGMA3 : UInt = 0x6b206574U // "te k"

fn rotate_left_u32(value : UInt, shift : Int) -> UInt {
  let s = ((shift % 32) + 32) % 32
  if s == 0 {
    return value
  }
  ((value << s) | (value >> (32 - s))) & 0xFFFFFFFFU
}

fn load_le32_from_uints(bytes : Array[UInt], offset : Int) -> UInt {
  (bytes[offset] & 0xFFU) |
    ((bytes[offset + 1] & 0xFFU) << 8) |
    ((bytes[offset + 2] & 0xFFU) << 16) |
    ((bytes[offset + 3] & 0xFFU) << 24)
}

fn store_le32_into_fixed(bytes : FixedArray[UInt], offset : Int, value : UInt) -> Unit {
  bytes[offset] = value & 0xFFU
  bytes[offset + 1] = (value >> 8) & 0xFFU
  bytes[offset + 2] = (value >> 16) & 0xFFU
  bytes[offset + 3] = (value >> 24) & 0xFFU
}

fn bytes_to_uint_array(bytes : Bytes) -> Array[UInt] {
  let arr : Array[UInt] = []
  for i in 0..<bytes.length() {
    arr.push(bytes[i].to_int().reinterpret_as_uint())
  }
  arr
}

fn key_words_from_bytes(bytes : Array[UInt]) -> FixedArray[UInt] {
  let words = FixedArray::make(8, 0U)
  for i in 0..<8 {
    words[i] = load_le32_from_uints(bytes, i * 4)
  }
  words
}

fn uints_to_bytes(values : Array[UInt]) -> Bytes {
  let buf : Array[Byte] = []
  for value in values {
    buf.push((value & 0xFFU).to_byte())
  }
  Bytes::from_array(buf)
}



fn nonce_words_from_bytes(bytes : Array[UInt]) -> FixedArray[UInt] {
  let words = FixedArray::make(3, 0U)
  for i in 0..<3 {
    words[i] = load_le32_from_uints(bytes, i * 4)
  }
  words
}

fn quarter_round(state : FixedArray[UInt], a : Int, b : Int, c : Int, d : Int) -> Unit {
  state[a] = state[a] + state[b]
  state[d] = rotate_left_u32(state[d] ^ state[a], 16)

  state[c] = state[c] + state[d]
  state[b] = rotate_left_u32(state[b] ^ state[c], 12)

  state[a] = state[a] + state[b]
  state[d] = rotate_left_u32(state[d] ^ state[a], 8)

  state[c] = state[c] + state[d]
  state[b] = rotate_left_u32(state[b] ^ state[c], 7)
}

fn chacha20_core(state : FixedArray[UInt]) -> Unit {
  let mut round = 0
  while round < 10 {
    // Column rounds
    quarter_round(state, 0, 4, 8, 12)
    quarter_round(state, 1, 5, 9, 13)
    quarter_round(state, 2, 6, 10, 14)
    quarter_round(state, 3, 7, 11, 15)
    // Diagonal rounds
    quarter_round(state, 0, 5, 10, 15)
    quarter_round(state, 1, 6, 11, 12)
    quarter_round(state, 2, 7, 8, 13)
    quarter_round(state, 3, 4, 9, 14)
    round = round + 1
  }
}

fn chacha20_block(
  key_words : FixedArray[UInt],
  counter : UInt,
  nonce_words : FixedArray[UInt],
) -> FixedArray[UInt] {
  let state = FixedArray::make(16, 0U)
  state[0] = SIGMA0
  state[1] = SIGMA1
  state[2] = SIGMA2
  state[3] = SIGMA3
  for i in 0..<8 {
    state[4 + i] = key_words[i]
  }
  state[12] = counter
  state[13] = nonce_words[0]
  state[14] = nonce_words[1]
  state[15] = nonce_words[2]

  let working_state = FixedArray::make(16, 0U)
  for i in 0..<16 {
    working_state[i] = state[i]
  }

  chacha20_core(working_state)

  let output = FixedArray::make(64, 0U)
  for i in 0..<16 {
    let sum = working_state[i] + state[i]
    store_le32_into_fixed(output, i * 4, sum)
  }
  output
}

pub fn hchacha20(
  key_words : FixedArray[UInt],
  nonce_words : FixedArray[UInt],
) -> FixedArray[UInt] {
  let state = FixedArray::make(16, 0U)
  state[0] = SIGMA0
  state[1] = SIGMA1
  state[2] = SIGMA2
  state[3] = SIGMA3
  for i in 0..<8 {
    state[4 + i] = key_words[i]
  }
  for i in 0..<4 {
    state[12 + i] = nonce_words[i]
  }

  chacha20_core(state)

  let result = FixedArray::make(8, 0U)
  for i in 0..<4 {
    result[i] = state[i]
  }
  for i in 0..<4 {
    result[4 + i] = state[12 + i]
  }
  result
}

fn derived_nonce_from_xnonce(xnonce : Array[UInt]) -> FixedArray[UInt] {
  let nonce = FixedArray::make(3, 0U)
  nonce[0] = 0U
  nonce[1] = load_le32_from_uints(xnonce, 16)
  nonce[2] = load_le32_from_uints(xnonce, 20)
  nonce
}

pub struct ChaCha20 {
  key_words : FixedArray[UInt]
  nonce_words : FixedArray[UInt]
  mut counter : UInt
}

fn make_chacha20(
  key_words : FixedArray[UInt],
  nonce_words : FixedArray[UInt],
  counter : UInt,
) -> ChaCha20 {
  ChaCha20::{ key_words, nonce_words, counter }
}

pub fn ChaCha20::new(key : Bytes, nonce : Bytes) -> Result[ChaCha20, String] {
  ChaCha20::new_with_counter(key, nonce, 0U)
}

pub fn ChaCha20::new_with_counter(
  key : Bytes,
  nonce : Bytes,
  counter : UInt,
) -> Result[ChaCha20, String] {
  let key_uints = bytes_to_uint_array(key)
  let nonce_uints = bytes_to_uint_array(nonce)
  ChaCha20::new_from_uints_with_counter(key_uints, nonce_uints, counter)
}

pub fn ChaCha20::new_from_uints(
  key : Array[UInt],
  nonce : Array[UInt],
) -> Result[ChaCha20, String] {
  ChaCha20::new_from_uints_with_counter(key, nonce, 0U)
}

pub fn ChaCha20::new_from_uints_with_counter(
  key : Array[UInt],
  nonce : Array[UInt],
  counter : UInt,
) -> Result[ChaCha20, String] {
  if key.length() != 32 {
    return Err("ChaCha20 key must be 32 bytes")
  }
  if nonce.length() != 12 {
    return Err("ChaCha20 nonce must be 12 bytes")
  }
  let key_words = key_words_from_bytes(key)
  let nonce_words = nonce_words_from_bytes(nonce)
  Ok(make_chacha20(key_words, nonce_words, counter))
}

pub fn ChaCha20::set_counter(self : ChaCha20, counter : UInt) -> Unit {
  self.counter = counter
}

pub fn ChaCha20::get_counter(self : ChaCha20) -> UInt {
  self.counter
}

pub fn ChaCha20::generate_block(self : ChaCha20) -> FixedArray[UInt] {
  let block = chacha20_block(self.key_words, self.counter, self.nonce_words)
  self.counter = self.counter + 1U
  block
}

pub fn ChaCha20::apply_keystream(
  self : ChaCha20,
  input : Array[UInt],
) -> Array[UInt] {
  let mut offset = 0
  let len = input.length()
  let output = Array::make(len, 0U)
  while offset < len {
    let block = self.generate_block()
    let remaining = len - offset
    let chunk = if remaining < 64 { remaining } else { 64 }
    for i in 0..<chunk {
      output[offset + i] = input[offset + i] ^ block[i]
    }
    offset = offset + chunk
  }
  output
}

pub fn ChaCha20::apply_keystream_bytes(
  self : ChaCha20,
  input : Bytes,
) -> Bytes {
  let input_uints = bytes_to_uint_array(input)
  let xored = self.apply_keystream(input_uints)
  uints_to_bytes(xored)
}

pub fn ChaCha20::encrypt(
  self : ChaCha20,
  plaintext : Array[UInt],
) -> Array[UInt] {
  self.apply_keystream(plaintext)
}

pub fn ChaCha20::encrypt_bytes(self : ChaCha20, plaintext : Bytes) -> Bytes {
  self.apply_keystream_bytes(plaintext)
}

pub fn ChaCha20::decrypt(
  self : ChaCha20,
  ciphertext : Array[UInt],
) -> Array[UInt] {
  self.apply_keystream(ciphertext)
}

pub fn ChaCha20::decrypt_bytes(self : ChaCha20, ciphertext : Bytes) -> Bytes {
  self.apply_keystream_bytes(ciphertext)
}

pub struct XChaCha20 {
  inner : ChaCha20
}

fn xchacha20_from_uints_with_counter(
  key : Array[UInt],
  nonce : Array[UInt],
  counter : UInt,
) -> Result[XChaCha20, String] {
  if key.length() != 32 {
    return Err("XChaCha20 key must be 32 bytes")
  }
  if nonce.length() != 24 {
    return Err("XChaCha20 nonce must be 24 bytes")
  }
  let key_words = key_words_from_bytes(key)

  let nonce_words = FixedArray::make(4, 0U)
  for i in 0..<4 {
    nonce_words[i] = load_le32_from_uints(nonce, i * 4)
  }

  let derived_key_words = hchacha20(key_words, nonce_words)
  let derived_nonce_words = derived_nonce_from_xnonce(nonce)
  let derived_inner = make_chacha20(derived_key_words, derived_nonce_words, counter)
  Ok(XChaCha20::{ inner: derived_inner })
}

pub fn XChaCha20::new(key : Bytes, nonce : Bytes) -> Result[XChaCha20, String] {
  XChaCha20::new_with_counter(key, nonce, 0U)
}

pub fn XChaCha20::new_with_counter(
  key : Bytes,
  nonce : Bytes,
  counter : UInt,
) -> Result[XChaCha20, String] {
  let key_uints = bytes_to_uint_array(key)
  let nonce_uints = bytes_to_uint_array(nonce)
  xchacha20_from_uints_with_counter(key_uints, nonce_uints, counter)
}

pub fn XChaCha20::apply_keystream(
  self : XChaCha20,
  input : Array[UInt],
) -> Array[UInt] {
  self.inner.apply_keystream(input)
}

pub fn XChaCha20::apply_keystream_bytes(
  self : XChaCha20,
  input : Bytes,
) -> Bytes {
  self.inner.apply_keystream_bytes(input)
}

pub fn XChaCha20::encrypt(
  self : XChaCha20,
  plaintext : Array[UInt],
) -> Array[UInt] {
  self.inner.encrypt(plaintext)
}

pub fn XChaCha20::encrypt_bytes(
  self : XChaCha20,
  plaintext : Bytes,
) -> Bytes {
  self.inner.encrypt_bytes(plaintext)
}

pub fn XChaCha20::decrypt(
  self : XChaCha20,
  ciphertext : Array[UInt],
) -> Array[UInt] {
  self.inner.decrypt(ciphertext)
}

pub fn XChaCha20::decrypt_bytes(
  self : XChaCha20,
  ciphertext : Bytes,
) -> Bytes {
  self.inner.decrypt_bytes(ciphertext)
}
