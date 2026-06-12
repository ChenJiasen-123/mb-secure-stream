
///|
test "chacha20 block matches RFC 8439 test vector" {
  let key = hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = hex_to_bytes("000000090000004a00000000")
  match ChaCha20::new_with_counter(key, nonce, 1U) {
    Ok(cipher) => {
      let block = cipher.generate_block()
      let expected = hex_to_bytes(
        "10f1e7e4d13b5915500fdd1fa32071c4" +
          "c7d1f4c733c068030422aa9ac3d46c4e" +
          "d2826446079faa0914c2d705d98b02a2" +
          "b5129cd1de164eb9cbd083e8a2503c4e",
      )
      let expected_uints = bytes_to_uint_array(expected)
      for i in 0..<expected_uints.length() {
        assert_eq(block[i], expected_uints[i])
      }
    }
    Err(_) => assert_true(false)
  }
}

test "chacha20 encrypts RFC 8439 sample plaintext" {
  let key = hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = hex_to_bytes("000000000000004a00000000")
  let plaintext = hex_to_bytes(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
      "73206f66205939393a204966204920636f756c64206f6666657220796f75206f" +
      "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
      "637265656e20776f756c642062652069742e",
  )
  let expected = hex_to_bytes(
    "6e2e359a2568f98041ba0728dd0d6981" +
      "e97e7aec1d4360c20a27afccfd9fae0b" +
      "f91b65c5523933ab8f593dabcd62b357" +
      "1639d624e65152ab8f530c359f0861d8" +
      "07ca0dbf500d6a6156a38e088a22b65e" +
      "52bc514d16ccf806818ce91ab7793736" +
      "5af90bbf74a35be6b40b8eedf2785e42" +
      "874d",
  )

  match ChaCha20::new_with_counter(key, nonce, 1U) {
    Ok(cipher) => {
      let ciphertext = cipher.apply_keystream_bytes(plaintext)
      let expected_uints = bytes_to_uint_array(expected)
      let result_uints = bytes_to_uint_array(ciphertext)
      for i in 0..<expected_uints.length() {
        assert_eq(result_uints[i], expected_uints[i])
      }
    }
    Err(_) => assert_true(false)
  }
}

test "xchacha20 derives the expected subkey" {
  let key = hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = hex_to_bytes(
    "000000090000004a0000000031415927",
  )

  let key_uints = bytes_to_uint_array(key)
  let nonce_uints = bytes_to_uint_array(nonce)

  let key_words = key_words_from_bytes(key_uints)
  let nonce_words = FixedArray::make(4, 0U)
  for i in 0..<4 {
    nonce_words[i] = load_le32_from_uints(nonce_uints, i * 4)
  }

  let derived = hchacha20(key_words, nonce_words)
  let expected = [
    0x423b4182U,
    0xfe7bb227U,
    0x50420ed3U,
    0x737d878aU,
    0xd5e4f9a0U,
    0x53a8748aU,
    0x13c42ec1U,
    0xdcecd326U,
  ]

  for i in 0..<8 {
    assert_eq(derived[i], expected[i])
  }
}

fn bytes_to_uint_array(bytes : Bytes) -> Array[UInt] {
  let arr : Array[UInt] = []
  for i in 0..<bytes.length() {
    arr.push(bytes[i].to_int().reinterpret_as_uint())
  }
  arr
}

fn parse_hex_digit(ch : Int) -> Int {
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

fn hex_to_bytes(hex : String) -> Bytes {
  let raw = @utf8.encode(hex)
  let filtered : Array[Int] = []
  for i in 0..<raw.length() {
    let ch = raw[i].to_int()
    if (ch >= 48 && ch <= 57) ||
      (ch >= 65 && ch <= 70) ||
      (ch >= 97 && ch <= 102) {
      filtered.push(ch)
    }
  }

  let buf : Array[Byte] = []
  let mut i = 0
  while i + 1 < filtered.length() {
    let hi = parse_hex_digit(filtered[i])
    let lo = parse_hex_digit(filtered[i + 1])
    buf.push(((hi << 4) | lo).to_byte())
    i = i + 2
  }
  Bytes::from_array(buf)
}

fn load_le32_from_uints(bytes : Array[UInt], offset : Int) -> UInt {
  (bytes[offset] & 0xFFU) |
    ((bytes[offset + 1] & 0xFFU) << 8) |
    ((bytes[offset + 2] & 0xFFU) << 16) |
    ((bytes[offset + 3] & 0xFFU) << 24)
}

fn key_words_from_bytes(bytes : Array[UInt]) -> FixedArray[UInt] {
  let words = FixedArray::make(8, 0U)
  for i in 0..<8 {
    words[i] = load_le32_from_uints(bytes, i * 4)
  }
  words
}
