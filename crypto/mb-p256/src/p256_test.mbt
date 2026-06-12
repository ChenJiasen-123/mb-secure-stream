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
    let hi = parse_hex_ch(chars[i])
    let lo = parse_hex_ch(chars[i + 1])
    result.push(((hi << 4) | lo).reinterpret_as_uint())
    i = i + 2
  }
  result
}

fn parse_hex_ch(ch : Int) -> Int {
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

fn uints_to_hex(arr : Array[UInt]) -> String {
  let mut result = ""
  for v in arr {
    let hi = ((v >> 4) & 0xFU).reinterpret_as_int()
    let lo = (v & 0xFU).reinterpret_as_int()
    result = result + (hi + 48 + (((9 - hi) >> 31) & 39)).unsafe_to_char().to_string()
    result = result + (lo + 48 + (((9 - lo) >> 31) & 39)).unsafe_to_char().to_string()
  }
  result
}

/// Test key generation: derive public key from known private key.
/// Test vector: private key = 1, public key should be the generator point.
test "keygen with d=1 gives generator" {
  // d = 1 (32 bytes big-endian)
  let d = hex_to_uints(
    "0000000000000000000000000000000000000000000000000000000000000001",
  )
  match derive_public_key(d) {
    Ok(pub_key) => {
      assert_eq(pub_key.length(), 65)
      assert_eq(pub_key[0], 0x04U) // uncompressed
      let x_hex = uints_to_hex(pub_key.iter().drop(1).take(32).collect())
      let y_hex = uints_to_hex(pub_key.iter().drop(33).take(32).collect())
      // Generator point coordinates
      assert_eq(
        x_hex,
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      )
      assert_eq(
        y_hex,
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
      )
    }
    Err(e) => {
      println("keygen failed: \{e}")
      assert_true(false)
    }
  }
}

/// Test: 2*G (private key = 2)
test "keygen with d=2 gives 2G" {
  let d = hex_to_uints(
    "0000000000000000000000000000000000000000000000000000000000000002",
  )
  match derive_public_key(d) {
    Ok(pub_key) => {
      let x_hex = uints_to_hex(pub_key.iter().drop(1).take(32).collect())
      let y_hex = uints_to_hex(pub_key.iter().drop(33).take(32).collect())
      // 2*G coordinates (well-known)
      assert_eq(
        x_hex,
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
      )
      assert_eq(
        y_hex,
        "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
      )
    }
    Err(e) => {
      println("keygen failed: \{e}")
      assert_true(false)
    }
  }
}

/// Test ECDSA sign and verify round trip.
test "ecdsa sign and verify round trip" {
  let private_key = hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  match ecdsa_keygen(private_key) {
    Ok(keypair) => {
      let message = hex_to_uints("48656c6c6f") // "Hello"
      match ecdsa_sign_message(private_key, message) {
        Ok(sig) => {
          match ecdsa_verify_message(keypair.public_key, message, sig) {
            Ok(valid) => assert_true(valid)
            Err(e) => {
              println("verify error: \{e}")
              assert_true(false)
            }
          }
        }
        Err(e) => {
          println("sign error: \{e}")
          assert_true(false)
        }
      }
    }
    Err(e) => {
      println("keygen error: \{e}")
      assert_true(false)
    }
  }
}

/// Test ECDSA rejects tampered message.
test "ecdsa rejects tampered message" {
  let private_key = hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  match ecdsa_keygen(private_key) {
    Ok(keypair) => {
      let message = hex_to_uints("48656c6c6f") // "Hello"
      let tampered = hex_to_uints("48656c6c6e") // "Helln"
      match ecdsa_sign_message(private_key, message) {
        Ok(sig) => {
          match ecdsa_verify_message(keypair.public_key, tampered, sig) {
            Ok(valid) => assert_true(!valid)
            Err(_) => assert_true(true) // Error is also acceptable
          }
        }
        Err(e) => {
          println("sign error: \{e}")
          assert_true(false)
        }
      }
    }
    Err(e) => {
      println("keygen error: \{e}")
      assert_true(false)
    }
  }
}

/// Test ECDH key exchange.
test "ecdh key exchange" {
  let alice_priv = hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let bob_priv = hex_to_uints(
    "0000000000000000000000000000000000000000000000000000000000000002",
  )
  match (derive_public_key(alice_priv), derive_public_key(bob_priv)) {
    (Ok(alice_pub), Ok(bob_pub)) => {
      match (ecdh(alice_priv, bob_pub), ecdh(bob_priv, alice_pub)) {
        (Ok(shared1), Ok(shared2)) => {
          // Both parties should derive the same shared secret
          assert_eq(shared1.length(), 32)
          assert_eq(shared2.length(), 32)
          for i in 0..<32 {
            assert_eq(shared1[i], shared2[i])
          }
        }
        _ => assert_true(false)
      }
    }
    _ => assert_true(false)
  }
}
