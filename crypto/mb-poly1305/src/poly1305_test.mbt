fn hex_to_uints(hex : String) -> Array[UInt] {
  let arr : Array[UInt] = []
  let bytes = hex.to_array()
  let mut i = 0
  while i < bytes.length() {
    let hi = hex_char_to_uint(bytes[i])
    let lo = hex_char_to_uint(bytes[i + 1])
    arr.push((hi << 4) | lo)
    i = i + 2
  }
  arr
}

fn hex_char_to_uint(c : Char) -> UInt {
  if c >= '0' && c <= '9' {
    (c.to_int() - 48).reinterpret_as_uint()
  } else if c >= 'a' && c <= 'f' {
    (c.to_int() - 87).reinterpret_as_uint()
  } else if c >= 'A' && c <= 'F' {
    (c.to_int() - 55).reinterpret_as_uint()
  } else {
    0U
  }
}

fn uints_to_hex(arr : Array[UInt]) -> String {
  let mut s = ""
  for value in arr {
    let hi = (value >> 4) & 0xFU
    let lo = value & 0xFU
    s = s + nibble_to_hex(hi) + nibble_to_hex(lo)
  }
  s
}

fn nibble_to_hex(n : UInt) -> String {
  if n < 10U {
    (n.reinterpret_as_int() + 48).unsafe_to_char().to_string()
  } else {
    (n.reinterpret_as_int() + 87).unsafe_to_char().to_string()
  }
}

fn ascii_to_uints(s : String) -> Array[UInt] {
  let arr : Array[UInt] = []
  let chars = s.to_array()
  for i in 0..<chars.length() {
    arr.push(chars[i].to_int().reinterpret_as_uint())
  }
  arr
}

/// Test 1: RFC 8439 Section 2.5.2
test "poly1305_rfc8439_section_2_5_2" {
  let key = hex_to_uints(
    "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
  )
  let message = ascii_to_uints("Cryptographic Forum Research Group")
  let expected_tag = hex_to_uints("a8061dc1305136c6c22b8baf0c0127a9")
  let tag = poly1305_mac(key, message)
  let tag_hex = uints_to_hex(tag)
  let expected_hex = uints_to_hex(expected_tag)
  assert_eq(tag_hex, expected_hex)
}

/// Test 2: All zeros key produces zero tag
test "poly1305_zero_key" {
  let key = Array::make(32, 0U)
  let message : Array[UInt] = [0U, 1U, 2U, 3U]
  let expected_tag = Array::make(16, 0U)
  let tag = poly1305_mac(key, message)
  assert_eq(uints_to_hex(tag), uints_to_hex(expected_tag))
}

/// Test 3: Verify returns true for correct tag
test "poly1305_verify_correct" {
  let key = hex_to_uints(
    "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
  )
  let message = ascii_to_uints("Cryptographic Forum Research Group")
  let tag = hex_to_uints("a8061dc1305136c6c22b8baf0c0127a9")
  assert_true(poly1305_verify(key, message, tag))
}

/// Test 4: Verify returns false for wrong tag
test "poly1305_verify_wrong_tag" {
  let key = hex_to_uints(
    "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
  )
  let message = ascii_to_uints("Cryptographic Forum Research Group")
  let tag16 : Array[UInt] = Array::make(16, 0U)
  assert_false(poly1305_verify(key, message, tag16))
}

/// Test 5: r=0 means tag equals s
test "poly1305_r_zero_tag_equals_s" {
  let key = hex_to_uints(
    "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
  )
  let message = ascii_to_uints("Hello world!")
  let expected_tag = hex_to_uints("36e5f6b5c5e06070f0efca96227a863e")
  let tag = poly1305_mac(key, message)
  assert_eq(uints_to_hex(tag), uints_to_hex(expected_tag))
}
