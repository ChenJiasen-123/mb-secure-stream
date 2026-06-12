fn hex_to_uints(hex : String) -> Array[UInt] {
  let raw = @utf8.encode(hex)
  let chars : Array[Int] = []
  for i in 0..<raw.length() {
    let ch = raw[i].to_int()
    if (ch >= 48 && ch <= 57) || (ch >= 65 && ch <= 70) || (ch >= 97 && ch <= 102) {
      chars.push(ch)
    }
  }
  let result : Array[UInt] = []
  let mut i = 0
  while i + 1 < chars.length() {
    let hi = parse_hex_digit(chars[i])
    let lo = parse_hex_digit(chars[i + 1])
    result.push(((hi << 4) | lo).reinterpret_as_uint())
    i = i + 2
  }
  result
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

/// RFC 8439 Section 2.8.2 - ChaCha20-Poly1305 AEAD test vector
test "aead encrypt RFC 8439" {
  let key = hex_to_uints(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex_to_uints("070000004041424344454647")
  let aad = hex_to_uints("50515253c0c1c2c3c4c5c6c7")
  let plaintext = hex_to_uints(
    "4c616469657320616e642047656e746c" +
      "656d656e206f662074686520636c6173" +
      "73206f66202739393a20496620492063" +
      "6f756c64206f6666657220796f75206f" +
      "6e6c79206f6e652074697020666f7220" +
      "746865206675747572652c2073756e73" +
      "637265656e20776f756c642062652069" +
      "742e",
  )
  let expected_ct = hex_to_uints(
    "d31a8d34648e60db7b86afbc53ef7ec2" +
      "a4aded51296e08fea9e2b5a736ee62d6" +
      "3dbea45e8ca9671282fafb69da92728b" +
      "1a71de0a9e060b2905d6a5b67ecd3b36" +
      "92ddbd7f2d778b8c9803aee328091b58" +
      "fab324e4fad675945585808b4831d7bc" +
      "3ff4def08e4b7a9de576d26586cec64b" +
      "6116",
  )
  let expected_tag = hex_to_uints("1ae10b594f09e26a7e902ecbd0600691")

  match aead_encrypt(key, nonce, aad, plaintext) {
    Ok((ct, tag)) => {
      assert_eq(ct.length(), expected_ct.length())
      for i in 0..<ct.length() {
        assert_eq(ct[i], expected_ct[i])
      }
      assert_eq(tag.length(), 16)
      for i in 0..<16 {
        assert_eq(tag[i], expected_tag[i])
      }
    }
    Err(e) => {
      println("Encrypt failed: \{e}")
      assert_true(false)
    }
  }
}

/// Decrypt the RFC 8439 test vector
test "aead decrypt RFC 8439" {
  let key = hex_to_uints(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex_to_uints("070000004041424344454647")
  let aad = hex_to_uints("50515253c0c1c2c3c4c5c6c7")
  let ciphertext = hex_to_uints(
    "d31a8d34648e60db7b86afbc53ef7ec2" +
      "a4aded51296e08fea9e2b5a736ee62d6" +
      "3dbea45e8ca9671282fafb69da92728b" +
      "1a71de0a9e060b2905d6a5b67ecd3b36" +
      "92ddbd7f2d778b8c9803aee328091b58" +
      "fab324e4fad675945585808b4831d7bc" +
      "3ff4def08e4b7a9de576d26586cec64b" +
      "6116",
  )
  let tag = hex_to_uints("1ae10b594f09e26a7e902ecbd0600691")
  let expected_pt = hex_to_uints(
    "4c616469657320616e642047656e746c" +
      "656d656e206f662074686520636c6173" +
      "73206f66202739393a20496620492063" +
      "6f756c64206f6666657220796f75206f" +
      "6e6c79206f6e652074697020666f7220" +
      "746865206675747572652c2073756e73" +
      "637265656e20776f756c642062652069" +
      "742e",
  )

  match aead_decrypt(key, nonce, aad, ciphertext, tag) {
    Ok(pt) => {
      assert_eq(pt.length(), expected_pt.length())
      for i in 0..<pt.length() {
        assert_eq(pt[i], expected_pt[i])
      }
    }
    Err(e) => {
      println("Decrypt failed: \{e}")
      assert_true(false)
    }
  }
}

/// Authentication failure: tampered ciphertext should be rejected
test "aead decrypt rejects tampered ciphertext" {
  let key = hex_to_uints(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex_to_uints("070000004041424344454647")
  let aad = hex_to_uints("50515253c0c1c2c3c4c5c6c7")
  let ciphertext = hex_to_uints(
    "d31a8d34648e60db7b86afbc53ef7ec2" +
      "a4aded51296e08fea9e2b5a736ee62d6" +
      "3dbea45e8ca9671282fafb69da92728b" +
      "1a71de0a9e060b2905d6a5b67ecd3b36" +
      "92ddbd7f2d778b8c9803aee328091b58" +
      "fab324e4fad675945585808b4831d7bc" +
      "3ff4def08e4b7a9de576d26586cec64b" +
      "6116",
  )
  let tag = hex_to_uints("1ae10b594f09e26a7e902ecbd0600691")

  // Tamper with ciphertext
  ciphertext[0] = ciphertext[0] ^ 0x01U

  match aead_decrypt(key, nonce, aad, ciphertext, tag) {
    Ok(_) => assert_true(false) // should have failed
    Err(msg) => assert_eq(msg, "Authentication failed")
  }
}

/// Round-trip: encrypt then decrypt
test "aead round trip" {
  let key = hex_to_uints(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = hex_to_uints("000000000000000000000001")
  let aad = hex_to_uints("aabbccdd")
  let plaintext = hex_to_uints("48656c6c6f20576f726c6421") // "Hello World!"

  match aead_encrypt(key, nonce, aad, plaintext) {
    Ok((ct, tag)) => {
      match aead_decrypt(key, nonce, aad, ct, tag) {
        Ok(pt) => {
          assert_eq(pt.length(), plaintext.length())
          for i in 0..<pt.length() {
            assert_eq(pt[i], plaintext[i])
          }
        }
        Err(e) => {
          println("Decrypt failed: \{e}")
          assert_true(false)
        }
      }
    }
    Err(e) => {
      println("Encrypt failed: \{e}")
      assert_true(false)
    }
  }
}
