test "SHA512 empty string" {
  let hash = @sha2.Sha512::digest_string("")
  let expected = [
    0xcf83e1357eefb8bdUL, 0xf1542850d66d8007UL, 0xd620e4050b5715dcUL, 0x83f4a921d36ce9ceUL,
    0x47d0d13c5d85f2b0UL, 0xff8318d2877eec2fUL, 0x63b931bd47417a81UL, 0xa538327af927da3eUL
  ]
  for i in 0..<8 {
    assert_eq(hash[i], expected[i])
  }
}

test "SHA512 single character 'a'" {
  let hash = @sha2.Sha512::digest_string("a")
  let expected = [
    0x1f40fc92da241694UL, 0x750979ee6cf582f2UL, 0xd5d7d28e18335de0UL, 0x5abc54d0560e0f53UL,
    0x02860c652bf08d56UL, 0x0252aa5e74210546UL, 0xf369fbbbce8c12cfUL, 0xc7957b2652fe9a75UL
  ]
  for i in 0..<8 {
    assert_eq(hash[i], expected[i])
  }
}

test "SHA512 abc" {
  let hash = @sha2.Sha512::digest_string("abc")
  let expected = [
    0xddaf35a193617abaUL, 0xcc417349ae204131UL, 0x12e6fa4e89a97ea2UL, 0x0a9eeee64b55d39aUL,
    0x2192992a274fc1a8UL, 0x36ba3c23a3feebbdUL, 0x454d4423643ce80eUL, 0x2a9ac94fa54ca49fUL
  ]
  for i in 0..<8 {
    assert_eq(hash[i], expected[i])
  }
}

test "SHA512 448-bit message" {
  let hash = @sha2.Sha512::digest_string("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
  let expected = [
    0x204a8fc6dda82f0aUL, 0x0ced7beb8e08a416UL, 0x57c16ef468b228a8UL, 0x279be331a703c335UL,
    0x96fd15c13b1b07f9UL, 0xaa1d3bea57789ca0UL, 0x31ad85c7a71dd703UL, 0x54ec631238ca3445UL
  ]
  for i in 0..<8 {
    assert_eq(hash[i], expected[i])
  }
}

test "SHA512 896-bit message" {
  let hash = @sha2.Sha512::digest_string("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
  let expected = [
    0x8e959b75dae313daUL, 0x8cf4f72814fc143fUL, 0x8f7779c6eb9f7fa1UL, 0x7299aeadb6889018UL,
    0x501d289e4900f7e4UL, 0x331b99dec4b5433aUL, 0xc7d329eeb6dd2654UL, 0x5e96e55b874be909UL
  ]
  for i in 0..<8 {
    assert_eq(hash[i], expected[i])
  }
}

test "SHA512 one million 'a' characters" {
  let sha512 = @sha2.Sha512::new()
  let chunk = Array::make(1000, 97U) // 'a' character
  for _ in 0..<1000 {
    sha512.update(chunk)
  }
  let hash = sha512.finalize()
  let expected = [
    0xe718483d0ce76964UL, 0x4e2e42c7bc15b463UL, 0x8e1f98b13b204428UL, 0x5632a803afa973ebUL,
    0xde0ff244877ea60aUL, 0x4cb0432ce577c31bUL, 0xeb009c5c2c49aa2eUL, 0x4eadb217ad8cc09bUL
  ]
  for i in 0..<8 {
    assert_eq(hash[i], expected[i])
  }
}

test "SHA512 digest_bytes function" {
  let bytes = @utf8.encode("abc")
  let hash = @sha2.Sha512::digest_bytes(bytes)
  let expected = [
    0xddaf35a193617abaUL, 0xcc417349ae204131UL, 0x12e6fa4e89a97ea2UL, 0x0a9eeee64b55d39aUL,
    0x2192992a274fc1a8UL, 0x36ba3c23a3feebbdUL, 0x454d4423643ce80eUL, 0x2a9ac94fa54ca49fUL
  ]
  for i in 0..<8 {
    assert_eq(hash[i], expected[i])
  }
}

test "SHA512 incremental update" {
  let sha512_1 = @sha2.Sha512::new()
  sha512_1.update([97, 98, 99]) // "abc"
  let hash_1 = sha512_1.finalize()
  
  let sha512_2 = @sha2.Sha512::new()
  sha512_2.update([97]) // "a"
  sha512_2.update([98]) // "b"
  sha512_2.update([99]) // "c"
  let hash_2 = sha512_2.finalize()
  
  for i in 0..<8 {
    assert_eq(hash_1[i], hash_2[i])
  }
}

test "SHA512 large block boundary" {
  // Test message that crosses 128-byte boundary
  let message = Array::make(130, 65U) // 130 'A' characters
  let hash = @sha2.Sha512::digest(message)
  
  // Verify by computing incrementally
  let sha512 = @sha2.Sha512::new()
  sha512.update(message)
  let hash_incremental = sha512.finalize()
  
  for i in 0..<8 {
    assert_eq(hash[i], hash_incremental[i])
  }
}

test "SHA512 multiple block updates" {
  let sha512 = @sha2.Sha512::new()
  
  // Add 3 full blocks (384 bytes total)
  let block = Array::make(128, 66U) // 'B' characters
  sha512.update(block)
  sha512.update(block)
  sha512.update(block)
  
  let hash = sha512.finalize()
  
  // Compare with single update
  let all_data = Array::make(384, 66U)
  let hash_single = @sha2.Sha512::digest(all_data)
  
  for i in 0..<8 {
    assert_eq(hash[i], hash_single[i])
  }
}

test "SHA512 padding edge case - 111 bytes" {
  // 111 bytes requires padding to span two blocks
  let message = Array::make(111, 88U) // 'X' characters
  let hash = @sha2.Sha512::digest(message)
  
  // Should produce consistent result
  let sha512 = @sha2.Sha512::new()
  sha512.update(message)
  let hash_incremental = sha512.finalize()
  
  for i in 0..<8 {
    assert_eq(hash[i], hash_incremental[i])
  }
}

test "SHA512 padding edge case - 112 bytes" {
  // 112 bytes is exactly at the padding boundary
  let message = Array::make(112, 89U) // 'Y' characters
  let hash = @sha2.Sha512::digest(message)
  
  let sha512 = @sha2.Sha512::new()
  sha512.update(message)
  let hash_incremental = sha512.finalize()
  
  for i in 0..<8 {
    assert_eq(hash[i], hash_incremental[i])
  }
}
