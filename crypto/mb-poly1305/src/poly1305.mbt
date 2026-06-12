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

fn constant_time_eq(left : Array[UInt], right : Array[UInt]) -> Bool {
  if left.length() != right.length() {
    return false
  }
  let mut diff : UInt = 0U
  for i in 0..<left.length() {
    diff = diff | (left[i] ^ right[i])
  }
  diff == 0U
}

/// Poly1305 MAC computation per RFC 8439 Section 2.5.
///
/// Uses radix 2^26 representation with 5 limbs.
/// All intermediate products use UInt64 to avoid overflow.
pub fn poly1305_mac(key : Array[UInt], message : Array[UInt]) -> Array[UInt] {
  if key.length() != 32 {
    abort("Poly1305 key must be 32 bytes")
  }

  // Clamp r (first 16 bytes of key)
  let r_bytes = FixedArray::make(16, 0U)
  for i in 0..<16 {
    r_bytes[i] = key[i] & 0xFFU
  }
  r_bytes[3] = r_bytes[3] & 0x0FU
  r_bytes[7] = r_bytes[7] & 0x0FU
  r_bytes[11] = r_bytes[11] & 0x0FU
  r_bytes[15] = r_bytes[15] & 0x0FU
  r_bytes[4] = r_bytes[4] & 0xFCU
  r_bytes[8] = r_bytes[8] & 0xFCU
  r_bytes[12] = r_bytes[12] & 0xFCU

  // Convert r to 5 limbs of 26 bits
  let r0 : UInt64 = ((r_bytes[0].to_uint64()) |
    (r_bytes[1].to_uint64() << 8) |
    (r_bytes[2].to_uint64() << 16) |
    (r_bytes[3].to_uint64() << 24)) & 0x3FFFFFFUL
  let r1 : UInt64 = ((r_bytes[3].to_uint64() >> 2) |
    (r_bytes[4].to_uint64() << 6) |
    (r_bytes[5].to_uint64() << 14) |
    (r_bytes[6].to_uint64() << 22)) & 0x3FFFFFFUL
  let r2 : UInt64 = ((r_bytes[6].to_uint64() >> 4) |
    (r_bytes[7].to_uint64() << 4) |
    (r_bytes[8].to_uint64() << 12) |
    (r_bytes[9].to_uint64() << 20)) & 0x3FFFFFFUL
  let r3 : UInt64 = ((r_bytes[9].to_uint64() >> 6) |
    (r_bytes[10].to_uint64() << 2) |
    (r_bytes[11].to_uint64() << 10) |
    (r_bytes[12].to_uint64() << 18)) & 0x3FFFFFFUL
  let r4 : UInt64 = (r_bytes[13].to_uint64() |
    (r_bytes[14].to_uint64() << 8) |
    (r_bytes[15].to_uint64() << 16)) & 0x3FFFFFFUL

  // Precompute r*5 values for modular reduction
  let s1 : UInt64 = r1 * 5UL
  let s2 : UInt64 = r2 * 5UL
  let s3 : UInt64 = r3 * 5UL
  let s4 : UInt64 = r4 * 5UL

  // Accumulator in 5 limbs
  let mut h0 : UInt64 = 0UL
  let mut h1 : UInt64 = 0UL
  let mut h2 : UInt64 = 0UL
  let mut h3 : UInt64 = 0UL
  let mut h4 : UInt64 = 0UL

  let msg_len = message.length()
  let mut offset = 0

  while offset < msg_len {
    // Determine block size
    let remaining = msg_len - offset
    let block_size = if remaining < 16 { remaining } else { 16 }

    // Read block bytes into a temporary buffer (up to 17 bytes with the hibit)
    let block = FixedArray::make(17, 0U)
    for i in 0..<block_size {
      block[i] = message[offset + i] & 0xFFU
    }
    // Append 0x01 after the block bytes
    block[block_size] = 1U

    // Convert block to 5 limbs (little-endian)
    let b0 : UInt64 = block[0].to_uint64() |
      (block[1].to_uint64() << 8) |
      (block[2].to_uint64() << 16) |
      (block[3].to_uint64() << 24)
    let n0 : UInt64 = b0 & 0x3FFFFFFUL

    let b1 : UInt64 = block[3].to_uint64() |
      (block[4].to_uint64() << 8) |
      (block[5].to_uint64() << 16) |
      (block[6].to_uint64() << 24)
    let n1 : UInt64 = (b1 >> 2) & 0x3FFFFFFUL

    let b2 : UInt64 = block[6].to_uint64() |
      (block[7].to_uint64() << 8) |
      (block[8].to_uint64() << 16) |
      (block[9].to_uint64() << 24)
    let n2 : UInt64 = (b2 >> 4) & 0x3FFFFFFUL

    let b3 : UInt64 = block[9].to_uint64() |
      (block[10].to_uint64() << 8) |
      (block[11].to_uint64() << 16) |
      (block[12].to_uint64() << 24)
    let n3 : UInt64 = (b3 >> 6) & 0x3FFFFFFUL

    let b4 : UInt64 = block[12].to_uint64() |
      (block[13].to_uint64() << 8) |
      (block[14].to_uint64() << 16) |
      (block[15].to_uint64() << 24) |
      (block[16].to_uint64() << 32)
    let n4 : UInt64 = (b4 >> 8) & 0x3FFFFFFUL

    // Add block to accumulator
    h0 = h0 + n0
    h1 = h1 + n1
    h2 = h2 + n2
    h3 = h3 + n3
    h4 = h4 + n4

    // Multiply accumulator by r (schoolbook), reduce mod 2^130 - 5
    let d0 : UInt64 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
    let d1 : UInt64 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
    let d2 : UInt64 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
    let d3 : UInt64 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
    let d4 : UInt64 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

    // Carry propagation
    let mut c : UInt64 = d0 >> 26
    h0 = d0 & 0x3FFFFFFUL
    let dd1 = d1 + c
    c = dd1 >> 26
    h1 = dd1 & 0x3FFFFFFUL
    let dd2 = d2 + c
    c = dd2 >> 26
    h2 = dd2 & 0x3FFFFFFUL
    let dd3 = d3 + c
    c = dd3 >> 26
    h3 = dd3 & 0x3FFFFFFUL
    let dd4 = d4 + c
    c = dd4 >> 26
    h4 = dd4 & 0x3FFFFFFUL
    h0 = h0 + c * 5UL
    c = h0 >> 26
    h0 = h0 & 0x3FFFFFFUL
    h1 = h1 + c

    offset = offset + block_size
  }

  // Final reduction: fully reduce h mod 2^130 - 5
  // One more carry propagation
  let mut c : UInt64 = h1 >> 26
  h1 = h1 & 0x3FFFFFFUL
  h2 = h2 + c
  c = h2 >> 26
  h2 = h2 & 0x3FFFFFFUL
  h3 = h3 + c
  c = h3 >> 26
  h3 = h3 & 0x3FFFFFFUL
  h4 = h4 + c
  c = h4 >> 26
  h4 = h4 & 0x3FFFFFFUL
  h0 = h0 + c * 5UL
  c = h0 >> 26
  h0 = h0 & 0x3FFFFFFUL
  h1 = h1 + c

  // Compute g = h + 5, check if g < 2^130 (meaning h >= p)
  let mut g0 : UInt64 = h0 + 5UL
  c = g0 >> 26
  g0 = g0 & 0x3FFFFFFUL
  let mut g1 : UInt64 = h1 + c
  c = g1 >> 26
  g1 = g1 & 0x3FFFFFFUL
  let mut g2 : UInt64 = h2 + c
  c = g2 >> 26
  g2 = g2 & 0x3FFFFFFUL
  let mut g3 : UInt64 = h3 + c
  c = g3 >> 26
  g3 = g3 & 0x3FFFFFFUL
  let mut g4 : UInt64 = h4 + c
  // If g4 bit 26 is set, g >= 2^130, meaning h >= p, so use g
  // mask is all-ones if h >= p, all-zeros otherwise
  let mask : UInt64 = (g4 >> 26) - 1UL // 0 if g4>=2^26, 0xFFFF... if not
  // Actually: if g4 >> 26 >= 1, then h >= p, mask = 0 (use g)
  // if g4 >> 26 == 0, then h < p, mask = 0xFFFFFFFFFFFFFFFF (use h)
  let nmask : UInt64 = mask.lnot()
  g4 = g4 & 0x3FFFFFFUL

  h0 = (h0 & mask) | (g0 & nmask)
  h1 = (h1 & mask) | (g1 & nmask)
  h2 = (h2 & mask) | (g2 & nmask)
  h3 = (h3 & mask) | (g3 & nmask)
  h4 = (h4 & mask) | (g4 & nmask)

  // Convert from 5x26-bit limbs to 4x32-bit words
  let f0 : UInt64 = (h0 | (h1 << 26)) & 0xFFFFFFFFUL
  let f1 : UInt64 = ((h1 >> 6) | (h2 << 20)) & 0xFFFFFFFFUL
  let f2 : UInt64 = ((h2 >> 12) | (h3 << 14)) & 0xFFFFFFFFUL
  let f3 : UInt64 = ((h3 >> 18) | (h4 << 8)) & 0xFFFFFFFFUL

  // Load s (last 16 bytes of key) as 4 little-endian 32-bit words
  let s0 : UInt64 = (key[16] & 0xFFU).to_uint64() |
    ((key[17] & 0xFFU).to_uint64() << 8) |
    ((key[18] & 0xFFU).to_uint64() << 16) |
    ((key[19] & 0xFFU).to_uint64() << 24)
  let s1_val : UInt64 = (key[20] & 0xFFU).to_uint64() |
    ((key[21] & 0xFFU).to_uint64() << 8) |
    ((key[22] & 0xFFU).to_uint64() << 16) |
    ((key[23] & 0xFFU).to_uint64() << 24)
  let s2_val : UInt64 = (key[24] & 0xFFU).to_uint64() |
    ((key[25] & 0xFFU).to_uint64() << 8) |
    ((key[26] & 0xFFU).to_uint64() << 16) |
    ((key[27] & 0xFFU).to_uint64() << 24)
  let s3_val : UInt64 = (key[28] & 0xFFU).to_uint64() |
    ((key[29] & 0xFFU).to_uint64() << 8) |
    ((key[30] & 0xFFU).to_uint64() << 16) |
    ((key[31] & 0xFFU).to_uint64() << 24)

  // Add s to the accumulator mod 2^128
  let mut t0 : UInt64 = f0 + s0
  let mut t1 : UInt64 = f1 + s1_val + (t0 >> 32)
  let mut t2 : UInt64 = f2 + s2_val + (t1 >> 32)
  let mut t3 : UInt64 = f3 + s3_val + (t2 >> 32)
  t0 = t0 & 0xFFFFFFFFUL
  t1 = t1 & 0xFFFFFFFFUL
  t2 = t2 & 0xFFFFFFFFUL
  t3 = t3 & 0xFFFFFFFFUL

  // Output 16 bytes little-endian
  let tag : Array[UInt] = Array::make(16, 0U)
  tag[0] = (t0 & 0xFFUL).to_uint()
  tag[1] = ((t0 >> 8) & 0xFFUL).to_uint()
  tag[2] = ((t0 >> 16) & 0xFFUL).to_uint()
  tag[3] = ((t0 >> 24) & 0xFFUL).to_uint()
  tag[4] = (t1 & 0xFFUL).to_uint()
  tag[5] = ((t1 >> 8) & 0xFFUL).to_uint()
  tag[6] = ((t1 >> 16) & 0xFFUL).to_uint()
  tag[7] = ((t1 >> 24) & 0xFFUL).to_uint()
  tag[8] = (t2 & 0xFFUL).to_uint()
  tag[9] = ((t2 >> 8) & 0xFFUL).to_uint()
  tag[10] = ((t2 >> 16) & 0xFFUL).to_uint()
  tag[11] = ((t2 >> 24) & 0xFFUL).to_uint()
  tag[12] = (t3 & 0xFFUL).to_uint()
  tag[13] = ((t3 >> 8) & 0xFFUL).to_uint()
  tag[14] = ((t3 >> 16) & 0xFFUL).to_uint()
  tag[15] = ((t3 >> 24) & 0xFFUL).to_uint()
  tag
}

pub fn poly1305_mac_bytes(key : Bytes, message : Bytes) -> Bytes {
  let tag = poly1305_mac(bytes_to_uint_array(key), bytes_to_uint_array(message))
  uints_to_bytes(tag)
}

pub fn poly1305_verify(
  key : Array[UInt],
  message : Array[UInt],
  tag : Array[UInt],
) -> Bool {
  let expected = poly1305_mac(key, message)
  constant_time_eq(expected, tag)
}

pub fn poly1305_verify_bytes(key : Bytes, message : Bytes, tag : Bytes) -> Bool {
  poly1305_verify(
    bytes_to_uint_array(key),
    bytes_to_uint_array(message),
    bytes_to_uint_array(tag),
  )
}
