fn hex_to_uints(hex: String) -> Array[UInt] {
  let raw = @utf8.encode(hex)
  let arr : Array[Int] = []
  for i in 0..<raw.length() {
    arr.push(raw[i].to_int())
  }
  let accumulator : Array[UInt] = []
  let mut i = 0
  while i + 1 < arr.length() {
    let hi = arr[i]
    let lo = arr[i + 1]
    let value = (parse_hex_digit(hi) << 4) | parse_hex_digit(lo)
    accumulator.push(value.reinterpret_as_uint())
    i = i + 2
  }
  accumulator
}

fn parse_hex_digit(ch: Int) -> Int {
  if ch >= 48 && ch <= 57 {
    ch - 48
  } else if ch >= 97 && ch <= 102 {
    ch - 87
  } else if ch >= 65 && ch <= 70 {
    ch - 55
  } else {
    0
  }
}

fn uints_to_bytes(values: Array[UInt]) -> Bytes {
  let bytes : Array[Byte] = []
  for value in values {
    bytes.push((value & 0xFFU).to_byte())
  }
  Bytes::from_array(bytes)
}

test "RFC4231 test case 1 (SHA-256)" {
  let key = uints_to_bytes(Array::make(20, 0x0bU))
  let data = uints_to_bytes([0x48U, 0x69U, 0x20U, 0x54U, 0x68U, 0x65U, 0x72U, 0x65U])
  let mac = hmac_sha256_bytes(data, key)
  let expected = hex_to_uints("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
  for i in 0..<expected.length() {
    assert_eq(mac[i], expected[i])
  }
}

test "RFC4231 test case 2 (SHA-256)" {
  let key = uints_to_bytes([0x4aU, 0x65U, 0x66U, 0x65U])
  let data = uints_to_bytes([
    0x77U, 0x68U, 0x61U, 0x74U, 0x20U, 0x64U, 0x6fU, 0x20U,
    0x79U, 0x61U, 0x20U, 0x77U, 0x61U, 0x6eU, 0x74U, 0x20U,
    0x66U, 0x6fU, 0x72U, 0x20U, 0x6eU, 0x6fU, 0x74U, 0x68U,
    0x69U, 0x6eU, 0x67U, 0x3fU,
  ])
  let mac = hmac_sha256_bytes(data, key)
  let expected = hex_to_uints("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
  for i in 0..<expected.length() {
    assert_eq(mac[i], expected[i])
  }
}

test "RFC4231 test case 3 (SHA-256)" {
  let key = uints_to_bytes(Array::make(20, 0xaaU))
  let data = uints_to_bytes(Array::make(50, 0xddU))
  let mac = hmac_sha256_bytes(data, key)
  let expected = hex_to_uints("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
  for i in 0..<expected.length() {
    assert_eq(mac[i], expected[i])
  }
}

test "RFC4231 test case 1 (SHA-512)" {
  let key = uints_to_bytes(Array::make(20, 0x0bU))
  let data = uints_to_bytes([0x48U, 0x69U, 0x20U, 0x54U, 0x68U, 0x65U, 0x72U, 0x65U])
  let mac = hmac_sha512_bytes(data, key)
  let expected = hex_to_uints("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
  for i in 0..<expected.length() {
    assert_eq(mac[i], expected[i])
  }
}

test "RFC4231 test case 2 (SHA-512)" {
  let key = uints_to_bytes([0x4aU, 0x65U, 0x66U, 0x65U])
  let data = uints_to_bytes([
    0x77U, 0x68U, 0x61U, 0x74U, 0x20U, 0x64U, 0x6fU, 0x20U,
    0x79U, 0x61U, 0x20U, 0x77U, 0x61U, 0x6eU, 0x74U, 0x20U,
    0x66U, 0x6fU, 0x72U, 0x20U, 0x6eU, 0x6fU, 0x74U, 0x68U,
    0x69U, 0x6eU, 0x67U, 0x3fU,
  ])
  let mac = hmac_sha512_bytes(data, key)
  let expected = hex_to_uints("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")
  for i in 0..<expected.length() {
    assert_eq(mac[i], expected[i])
  }
}
