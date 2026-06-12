///|
fn compress_u32(state : FixedArray[UInt], block : FixedArray[UInt]) -> Unit {
  let mut a : UInt = state[0]
  let mut b : UInt = state[1]
  let mut c : UInt = state[2]
  let mut d : UInt = state[3]
  let mut e : UInt = state[4]
  let mut f : UInt = state[5]
  let mut g : UInt = state[6]
  let mut h : UInt = state[7]
  let k = get_k32() // Get constants array once
  for i in 0..<64 {
    let w : UInt = if i < 16 {
      block[i]
    } else {
      let w15 = block[(i - 15) % 16]
      let s0 = rotate_right_u32(w15, 7) ^ rotate_right_u32(w15, 18) ^ (w15 >> 3)
      let w2 = block[(i - 2) % 16]
      let s1 = rotate_right_u32(w2, 17) ^ rotate_right_u32(w2, 19) ^ (w2 >> 10)
      let new_w = block[(i - 16) % 16] + s0 + block[(i - 7) % 16] + s1
      block[i % 16] = new_w
      new_w
    }
    let s1 = rotate_right_u32(e, 6) ^
      rotate_right_u32(e, 11) ^
      rotate_right_u32(e, 25)
    let ch = (e & f) ^ ((e ^ 0xFFFFFFFF) & g)
    let temp1 = s1 + ch + k[i] + w + h
    let s0 = rotate_right_u32(a, 2) ^
      rotate_right_u32(a, 13) ^
      rotate_right_u32(a, 22)
    let maj = (a & b) ^ (a & c) ^ (b & c)
    let temp2 = s0 + maj
    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2
  }
  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
  state[4] = state[4] + e
  state[5] = state[5] + f
  state[6] = state[6] + g
  state[7] = state[7] + h
}

///|
fn compress256(
  state : FixedArray[UInt],
  blocks : FixedArray[FixedArray[UInt]],
) -> Unit {
  for block in blocks {
    compress_u32(state, block)
  }
}

///|
pub struct Sha256 {
  state : FixedArray[UInt]
  buffer : FixedArray[UInt]
  mut buffer_len : Int
  mut total_len : UInt64
}

///|
pub fn Sha256::new() -> Sha256 {
  // Create a fresh copy of the initial state
  let initial_state = sha256_state()
  let state = FixedArray::make(8, 0U)
  for i in 0..<8 {
    state[i] = initial_state[i]
  }
  return Sha256::{
    state,
    buffer: FixedArray::make(64, 0U),
    buffer_len: 0,
    total_len: 0UL,
  }
}

///|
pub fn Sha256::update(self : Sha256, input : Array[UInt]) -> Unit {
  let mut input_offset = 0
  let input_len = input.length()
  self.total_len = self.total_len + input_len.to_uint64()

  // If we have buffered data, try to fill the buffer and process it
  if self.buffer_len > 0 {
    let space_left = 64 - self.buffer_len
    let to_copy = if input_len < space_left { input_len } else { space_left }
    for i in 0..<to_copy {
      self.buffer[self.buffer_len + i] = input[i]
    }
    self.buffer_len = self.buffer_len + to_copy
    input_offset = to_copy

    // If buffer is full, process it
    if self.buffer_len == 64 {
      // Convert buffer to UInt32 array for processing
      let block = FixedArray::make(16, 0U)
      for i in 0..<16 {
        let idx = i * 4
        block[i] = (self.buffer[idx] << 24) |
          (self.buffer[idx + 1] << 16) |
          (self.buffer[idx + 2] << 8) |
          self.buffer[idx + 3]
      }
      let blocks = FixedArray::make(1, block)
      compress256(self.state, blocks)
      self.buffer_len = 0
    }
  }

  // Process complete 64-byte blocks directly from input
  while input_offset + 64 <= input_len {
    let block = FixedArray::make(16, 0U)
    for i in 0..<16 {
      let idx = input_offset + i * 4
      block[i] = (input[idx] << 24) |
        (input[idx + 1] << 16) |
        (input[idx + 2] << 8) |
        input[idx + 3]
    }
    let blocks = FixedArray::make(1, block)
    compress256(self.state, blocks)
    input_offset = input_offset + 64
  }

  // Buffer any remaining bytes
  while input_offset < input_len {
    self.buffer[self.buffer_len] = input[input_offset]
    self.buffer_len = self.buffer_len + 1
    input_offset = input_offset + 1
  }
}

///|
pub fn Sha256::finalize(self : Sha256) -> FixedArray[UInt] {
  // Save the message length in bits
  let bit_len = self.total_len * 8UL

  // Append 0x80 byte (1 bit followed by zeros)
  self.buffer[self.buffer_len] = 0x80U
  self.buffer_len = self.buffer_len + 1

  // If there's not enough room for length (8 bytes), process this block and pad next
  if self.buffer_len > 56 {
    // Fill rest with zeros
    while self.buffer_len < 64 {
      self.buffer[self.buffer_len] = 0U
      self.buffer_len = self.buffer_len + 1
    }

    // Process this block
    let block = FixedArray::make(16, 0U)
    for i in 0..<16 {
      let idx = i * 4
      block[i] = (self.buffer[idx] << 24) |
        (self.buffer[idx + 1] << 16) |
        (self.buffer[idx + 2] << 8) |
        self.buffer[idx + 3]
    }
    let blocks = FixedArray::make(1, block)
    compress256(self.state, blocks)
    self.buffer_len = 0
  }

  // Pad with zeros until we reach 56 bytes (leaving 8 bytes for length)
  while self.buffer_len < 56 {
    self.buffer[self.buffer_len] = 0U
    self.buffer_len = self.buffer_len + 1
  }

  // Append length in bits as 64-bit big-endian
  self.buffer[56] = ((bit_len >> 56) & 0xFFUL).to_uint()
  self.buffer[57] = ((bit_len >> 48) & 0xFFUL).to_uint()
  self.buffer[58] = ((bit_len >> 40) & 0xFFUL).to_uint()
  self.buffer[59] = ((bit_len >> 32) & 0xFFUL).to_uint()
  self.buffer[60] = ((bit_len >> 24) & 0xFFUL).to_uint()
  self.buffer[61] = ((bit_len >> 16) & 0xFFUL).to_uint()
  self.buffer[62] = ((bit_len >> 8) & 0xFFUL).to_uint()
  self.buffer[63] = (bit_len & 0xFFUL).to_uint()

  // Process final block
  let block = FixedArray::make(16, 0U)
  for i in 0..<16 {
    let idx = i * 4
    block[i] = (self.buffer[idx] << 24) |
      (self.buffer[idx + 1] << 16) |
      (self.buffer[idx + 2] << 8) |
      self.buffer[idx + 3]
  }
  let blocks = FixedArray::make(1, block)
  compress256(self.state, blocks)

  // Convert state from UInt32 to bytes
  let result = FixedArray::make(32, 0U)
  for i in 0..<8 {
    let v = self.state[i]
    result[i * 4] = (v >> 24) & 0xFFU
    result[i * 4 + 1] = (v >> 16) & 0xFFU
    result[i * 4 + 2] = (v >> 8) & 0xFFU
    result[i * 4 + 3] = v & 0xFFU
  }
  return result
}

///|
pub fn Sha256::digest(input : Array[UInt]) -> FixedArray[UInt] {
  let sha256 = Sha256::new()
  sha256.update(input)
  return sha256.finalize()
}

// Additional methods for different input types

///|
pub fn Sha256::digest_bytes(input : Bytes) -> FixedArray[UInt] {
  let sha256 = Sha256::new()
  let arr : Array[UInt] = []
  // Filter out zero bytes to handle UTF-16LE-like encodings from some to_bytes() implementations
  for i in 0..<input.length() {
    let v = input[i].to_int()
    if v != 0 { arr.push(v.reinterpret_as_uint()) }
  }
  sha256.update(arr)
  return sha256.finalize()
}

///|
pub fn Sha256::digest_string(input : String) -> FixedArray[UInt] {
  let sha256 = Sha256::new()
  let bytes = @utf8.encode(input)
  let arr : Array[UInt] = []
  for i in 0..<bytes.length() {
    arr.push(bytes[i].to_int().reinterpret_as_uint())
  }
  sha256.update(arr)
  return sha256.finalize()
}
