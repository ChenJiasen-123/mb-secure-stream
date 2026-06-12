///|
pub fn rotate_right_u32(value : UInt, n : Int) -> UInt {
  let n = n % 32
  return (value >> n) | (value << (32 - n))
}

///|
test "test_rotate_right_u32" {
  assert_eq(rotate_right_u32(0x12345678U, 4), 0x81234567U)
  assert_eq(rotate_right_u32(0x12345678U, 8), 0x78123456U)
  assert_eq(rotate_right_u32(0x12345678U, 16), 0x56781234U)
  assert_eq(rotate_right_u32(0x12345678U, 32), 0x12345678U)
  assert_eq(rotate_right_u32(0x12345678U, 36), 0x81234567U)
}

pub fn rotate_right_u64(value : UInt64, n : Int) -> UInt64 {
  // Normalize rotation to [0, 63]
  let r = ((n % 64) + 64) % 64
  // Ensure shifts stay within 0..63 and mask to 64 bits
  let lhs = value >> r
  let rhs = if r == 0 { 0UL } else { value << (64 - r) }
  (lhs | rhs) & 0xFFFFFFFFFFFFFFFFUL
}

test "test_rotate_right_u64" {
  assert_eq(rotate_right_u64(0x1234567890abcdefUL, 4), 0xf1234567890abcdeUL)
  assert_eq(rotate_right_u64(0x1234567890abcdefUL, 8), 0xef1234567890abcdUL)
  assert_eq(rotate_right_u64(0x1234567890abcdefUL, 16), 0xcdef1234567890abUL)
  assert_eq(rotate_right_u64(0x1234567890abcdefUL, 32), 0x90abcdef12345678UL)
  assert_eq(rotate_right_u64(0x1234567890abcdefUL, 64), 0x1234567890abcdefUL)
  assert_eq(rotate_right_u64(0x1234567890abcdefUL, 68), 0xf1234567890abcdeUL)
}

pub fn hash_to_hex(hash: FixedArray[UInt]) -> String {
  let hex_chars = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
  let mut result = ""
  for byte in hash {
    let high = (byte >> 4) & 0xFU
    let low = byte & 0xFU
    result = result + hex_chars[high.reinterpret_as_int()].to_string() + hex_chars[low.reinterpret_as_int()].to_string()
  }
  result
}