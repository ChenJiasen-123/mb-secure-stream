fn parse_hex_digit(ch : UInt) -> UInt {
  if ch >= 48 && ch <= 57 {
    ch - 48U
  } else if ch >= 97 && ch <= 102 {
    ch - 87U
  } else if ch >= 65 && ch <= 70 {
    ch - 55U
  } else {
    0U
  }
}

fn hex_to_uints(hex : String) -> Array[UInt] {
  let accumulator : Array[UInt] = []
  let len = hex.length()
  let mut i = 0
  while i + 1 < len {
    let hi = parse_hex_digit(hex[i].to_uint())
    let lo = parse_hex_digit(hex[i + 1].to_uint())
    accumulator.push((hi << 4) | lo)
    i = i + 2
  }
  accumulator
}

fn uints_to_hex(arr : Array[UInt]) -> String {
  let hex_chars = "0123456789abcdef"
  let buf = StringBuilder::new()
  for i in 0..<arr.length() {
    let b = arr[i]
    let hi = ((b >> 4) & 0xFU).reinterpret_as_int()
    let lo = (b & 0xFU).reinterpret_as_int()
    buf.write_char(hex_chars[hi].to_uint().reinterpret_as_int().unsafe_to_char())
    buf.write_char(hex_chars[lo].to_uint().reinterpret_as_int().unsafe_to_char())
  }
  buf.to_string()
}

// RFC 5869 Appendix A - Test Case 1 (SHA-256)
test "hkdf_sha256 test case 1" {
  let ikm = hex_to_uints("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let salt = hex_to_uints("000102030405060708090a0b0c")
  let info = hex_to_uints("f0f1f2f3f4f5f6f7f8f9")
  let length = 42

  // Test extract
  let prk = hkdf_extract_sha256(salt, ikm)
  let prk_hex = uints_to_hex(prk)
  assert_eq(
    prk_hex,
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
  )

  // Test expand
  let okm = hkdf_expand_sha256(prk, info, length)
  match okm {
    Ok(result) => {
      let okm_hex = uints_to_hex(result)
      assert_eq(
        okm_hex,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
      )
    }
    Err(e) => fail("unexpected error: \{e}")
  }

  // Test combined
  let combined = hkdf_sha256(salt, ikm, info, length)
  match combined {
    Ok(result) => {
      let combined_hex = uints_to_hex(result)
      assert_eq(
        combined_hex,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
      )
    }
    Err(e) => fail("unexpected error: \{e}")
  }
}

// RFC 5869 Appendix A - Test Case 3 (SHA-256, empty salt and info)
test "hkdf_sha256 test case 3 - empty salt and info" {
  let ikm = hex_to_uints("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let salt : Array[UInt] = []
  let info : Array[UInt] = []
  let length = 42

  // Test extract
  let prk = hkdf_extract_sha256(salt, ikm)
  let prk_hex = uints_to_hex(prk)
  assert_eq(
    prk_hex,
    "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
  )

  // Test combined
  let combined = hkdf_sha256(salt, ikm, info, length)
  match combined {
    Ok(result) => {
      let combined_hex = uints_to_hex(result)
      assert_eq(
        combined_hex,
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
      )
    }
    Err(e) => fail("unexpected error: \{e}")
  }
}

// Test error case: length too large
test "hkdf_expand_sha256 rejects excessive length" {
  let prk = Array::make(32, 0U)
  let info : Array[UInt] = []
  let result = hkdf_expand_sha256(prk, info, 8161)
  match result {
    Ok(_) => fail("expected error for excessive length")
    Err(_) => ()
  }
}

// Test error case: length zero
test "hkdf_expand_sha256 rejects zero length" {
  let prk = Array::make(32, 0U)
  let info : Array[UInt] = []
  let result = hkdf_expand_sha256(prk, info, 0)
  match result {
    Ok(_) => fail("expected error for zero length")
    Err(_) => ()
  }
}

// RFC 5869 Appendix A - Test Case 1 using SHA-256 combined via Bytes wrapper
test "hkdf_sha256_bytes test case 1" {
  let ikm_arr = hex_to_uints("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let salt_arr = hex_to_uints("000102030405060708090a0b0c")
  let info_arr = hex_to_uints("f0f1f2f3f4f5f6f7f8f9")
  let ikm = uints_to_bytes_test(ikm_arr)
  let salt = uints_to_bytes_test(salt_arr)
  let info = uints_to_bytes_test(info_arr)
  let result = hkdf_sha256_bytes(salt, ikm, info, 42)
  match result {
    Ok(okm) => {
      let okm_uints = bytes_to_uints_test(okm)
      let okm_hex = uints_to_hex(okm_uints)
      assert_eq(
        okm_hex,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
      )
    }
    Err(e) => fail("unexpected error: \{e}")
  }
}

fn uints_to_bytes_test(arr : Array[UInt]) -> Bytes {
  let buf : Array[Byte] = []
  for value in arr {
    buf.push((value & 0xFFU).to_byte())
  }
  Bytes::from_array(buf)
}

fn bytes_to_uints_test(bytes : Bytes) -> Array[UInt] {
  let arr : Array[UInt] = []
  for i in 0..<bytes.length() {
    arr.push(bytes[i].to_int().reinterpret_as_uint())
  }
  arr
}
