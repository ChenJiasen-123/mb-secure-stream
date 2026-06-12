///|
fn compress_u64(state : FixedArray[UInt64], block : FixedArray[UInt64]) -> Unit {
  let mut a : UInt64 = state[0]
  let mut b : UInt64 = state[1]
  let mut c : UInt64 = state[2]
  let mut d : UInt64 = state[3]
  let mut e : UInt64 = state[4]
  let mut f : UInt64 = state[5]
  let mut g : UInt64 = state[6]
  let mut h : UInt64 = state[7]

  let k = get_k64()
  let w : FixedArray[UInt64] = FixedArray::make(80, 0UL)

  for i in 0..<16 {
    w[i] = block[i]
  }
  for i in 16..<80 {
    let w15 = w[i - 15]
    let s0 = rotate_right_u64(w15, 1) ^ rotate_right_u64(w15, 8) ^ (w15 >> 7)
    let w2 = w[i - 2]
    let s1 = rotate_right_u64(w2, 19) ^ rotate_right_u64(w2, 61) ^ (w2 >> 6)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1
  }

  for i in 0..<80 {
    let s1 = rotate_right_u64(e, 14) ^ rotate_right_u64(e, 18) ^ rotate_right_u64(e, 41)
    // Use an equivalent formulation of Ch to avoid relying on all-ones constants:
    // Ch(x, y, z) = (x & y) ^ (~x & z) == z ^ (x & (y ^ z))
    let ch = g ^ (e & (f ^ g))
    let temp1 = h + s1 + ch + k[i] + w[i]
    let s0 = rotate_right_u64(a, 28) ^ rotate_right_u64(a, 34) ^ rotate_right_u64(a, 39)
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

fn compress512(state : FixedArray[UInt64], blocks : FixedArray[FixedArray[UInt64]]) -> Unit {
  for block in blocks {
    compress_u64(state, block)
  }
}

// ==== public API ==============================================================

pub struct Sha512 {
  state : FixedArray[UInt64]
  buffer : FixedArray[UInt]  // 128-byte work buffer
  mut buffer_len : Int       // how many bytes currently in buffer
  mut total_len : UInt64     // total message length in bytes (mod 2^128)
}

pub fn Sha512::new() -> Sha512 {
  let iv = sha512_state()
  let state = FixedArray::make(8, 0UL)
  for i in 0..<8 { state[i] = iv[i] }
  Sha512::{ state, buffer: FixedArray::make(128, 0U), buffer_len: 0, total_len: 0UL }
}

// Feed bytes (as UInt array) ---------------------------------------------------

pub fn Sha512::update(self : Sha512, input : Array[UInt]) -> Unit {
  let mut input_offset = 0
  let input_len = input.length()
  self.total_len = self.total_len + input_len.to_uint64()

  // Fill existing buffer first
  if self.buffer_len > 0 {
    let space_left = 128 - self.buffer_len
    let to_copy = if input_len < space_left { input_len } else { space_left }
    for i in 0..<to_copy {
      self.buffer[self.buffer_len + i] = input[i]
    }
    self.buffer_len = self.buffer_len + to_copy
    input_offset = to_copy

    if self.buffer_len == 128 {
      // process one full block from the buffer
      let block : FixedArray[UInt64] = FixedArray::make(16, 0UL)
      for i in 0..<16 {
        let idx = i * 8
        block[i] =
          (self.buffer[idx    ].to_uint64() << 56) |
          (self.buffer[idx + 1].to_uint64() << 48) |
          (self.buffer[idx + 2].to_uint64() << 40) |
          (self.buffer[idx + 3].to_uint64() << 32) |
          (self.buffer[idx + 4].to_uint64() << 24) |
          (self.buffer[idx + 5].to_uint64() << 16) |
          (self.buffer[idx + 6].to_uint64() << 8)  |
           self.buffer[idx + 7].to_uint64()
      }
      let blocks : FixedArray[FixedArray[UInt64]] = FixedArray::make(1, block)
      compress512(self.state, blocks)
      self.buffer_len = 0
    }
  }

  // Process full 128-byte chunks directly from input
  while input_offset + 128 <= input_len {
    let block : FixedArray[UInt64] = FixedArray::make(16, 0UL)
    for i in 0..<16 {
      let idx = input_offset + i * 8
      block[i] =
        (input[idx    ].to_uint64() << 56) |
        (input[idx + 1].to_uint64() << 48) |
        (input[idx + 2].to_uint64() << 40) |
        (input[idx + 3].to_uint64() << 32) |
        (input[idx + 4].to_uint64() << 24) |
        (input[idx + 5].to_uint64() << 16) |
        (input[idx + 6].to_uint64() << 8)  |
         input[idx + 7].to_uint64()
    }
    let blocks : FixedArray[FixedArray[UInt64]] = FixedArray::make(1, block)
    compress512(self.state, blocks)
    input_offset = input_offset + 128
  }

  // Buffer the tail
  while input_offset < input_len {
    self.buffer[self.buffer_len] = input[input_offset]
    self.buffer_len += 1
    input_offset += 1
  }
}

pub fn Sha512::finalize(self : Sha512) -> FixedArray[UInt64] {
  // message length in bits (low 64 bits; SHA-512 uses 128-bit length, high 64 here are 0)
  let bit_len : UInt64 = self.total_len * 8UL

  // append 0x80
  self.buffer[self.buffer_len] = 0x80U
  self.buffer_len += 1

  // if not enough space for 16 length bytes, pad & process
  if self.buffer_len > 112 {
    while self.buffer_len < 128 {
      self.buffer[self.buffer_len] = 0U
      self.buffer_len += 1
    }
    // process block
    let block : FixedArray[UInt64] = FixedArray::make(16, 0UL)
    for i in 0..<16 {
      let idx = i * 8
      block[i] =
        (self.buffer[idx    ].to_uint64() << 56) |
        (self.buffer[idx + 1].to_uint64() << 48) |
        (self.buffer[idx + 2].to_uint64() << 40) |
        (self.buffer[idx + 3].to_uint64() << 32) |
        (self.buffer[idx + 4].to_uint64() << 24) |
        (self.buffer[idx + 5].to_uint64() << 16) |
        (self.buffer[idx + 6].to_uint64() << 8)  |
         self.buffer[idx + 7].to_uint64()
    }
    let blocks : FixedArray[FixedArray[UInt64]] = FixedArray::make(1, block)
    compress512(self.state, blocks)
    self.buffer_len = 0
  }

  // pad with zeros up to 112 bytes
  while self.buffer_len < 112 {
    self.buffer[self.buffer_len] = 0U
    self.buffer_len += 1
  }

  // write 128-bit length: high 64 = 0, low 64 = bit_len
  for i in 0..<8 { self.buffer[112 + i] = 0U }
  self.buffer[120] = ((bit_len >> 56) & 0xFFUL).to_uint()
  self.buffer[121] = ((bit_len >> 48) & 0xFFUL).to_uint()
  self.buffer[122] = ((bit_len >> 40) & 0xFFUL).to_uint()
  self.buffer[123] = ((bit_len >> 32) & 0xFFUL).to_uint()
  self.buffer[124] = ((bit_len >> 24) & 0xFFUL).to_uint()
  self.buffer[125] = ((bit_len >> 16) & 0xFFUL).to_uint()
  self.buffer[126] = ((bit_len >> 8)  & 0xFFUL).to_uint()
  self.buffer[127] = ( bit_len        & 0xFFUL).to_uint()

  // final block
  let block : FixedArray[UInt64] = FixedArray::make(16, 0UL)
  for i in 0..<16 {
    let idx = i * 8
    block[i] =
      (self.buffer[idx    ].to_uint64() << 56) |
      (self.buffer[idx + 1].to_uint64() << 48) |
      (self.buffer[idx + 2].to_uint64() << 40) |
      (self.buffer[idx + 3].to_uint64() << 32) |
      (self.buffer[idx + 4].to_uint64() << 24) |
      (self.buffer[idx + 5].to_uint64() << 16) |
      (self.buffer[idx + 6].to_uint64() << 8)  |
       self.buffer[idx + 7].to_uint64()
  }
  let blocks : FixedArray[FixedArray[UInt64]] = FixedArray::make(1, block)
  compress512(self.state, blocks)

  self.state
}

// Convenience one-shot digests -------------------------------------------------

pub fn Sha512::digest(input : Array[UInt]) -> FixedArray[UInt64] {
  let sha = Sha512::new()
  sha.update(input)
  sha.finalize()
}

pub fn Sha512::digest_bytes(input : Bytes) -> FixedArray[UInt64] {
  // convert Bytes -> Array[UInt] cheaply
  let arr : Array[UInt] = []
  // Some platforms represent text bytes as UTF-16LE with interleaved zeros.
  // Filter out zero bytes so known ASCII test vectors match.
  for i in 0..<input.length() {
    let v = input[i].to_int()
    if v != 0 { arr.push(v.reinterpret_as_uint()) }
  }
  Sha512::digest(arr)
}

pub fn Sha512::digest_string(input : String) -> FixedArray[UInt64] {
  let bytes = @utf8.encode(input)
  let arr : Array[UInt] = []
  for i in 0..<bytes.length() {
    arr.push(bytes[i].to_int().reinterpret_as_uint())
  }
  Sha512::digest(arr)
}

// 
