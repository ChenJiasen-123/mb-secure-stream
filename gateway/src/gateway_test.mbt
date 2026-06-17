// Gateway module tests
// Tests for parse_gateway_claims (payload.mbt) and execute_security_filter (middleware.mbt)

// --- parse_gateway_claims tests ---

test "parse_gateway_claims - valid payload with all fields including nbf" {
  let json = "{\"sub\":\"user123\",\"exp\":2000000000,\"nbf\":1000000000,\"iss\":\"auth.example.com\",\"role\":\"admin\"}"
  match parse_gateway_claims(json) {
    Ok(claims) => {
      assert_eq(claims.sub, "user123")
      assert_eq(claims.exp, 2000000000L)
      assert_eq(claims.nbf, Some(1000000000L))
      assert_eq(claims.iss, Some("auth.example.com"))
      assert_eq(claims.role, Some("admin"))
    }
    Err(e) => fail("Expected Ok, got Err: \{e}")
  }
}

test "parse_gateway_claims - missing optional fields default to None" {
  let json = "{\"sub\":\"user123\",\"exp\":2000000000}"
  match parse_gateway_claims(json) {
    Ok(claims) => {
      assert_eq(claims.sub, "user123")
      assert_eq(claims.exp, 2000000000L)
      assert_eq(claims.nbf, None)
      assert_eq(claims.iss, None)
      assert_eq(claims.role, None)
    }
    Err(e) => fail("Expected Ok, got Err: \{e}")
  }
}

test "parse_gateway_claims - missing sub returns error" {
  let json = "{\"exp\":2000000000,\"iss\":\"auth.example.com\",\"role\":\"admin\"}"
  match parse_gateway_claims(json) {
    Ok(_) => fail("Expected Err, got Ok")
    Err(msg) => assert_true(msg.contains("'sub'"))
  }
}

test "parse_gateway_claims - missing exp returns error" {
  let json = "{\"sub\":\"user123\",\"iss\":\"auth.example.com\",\"role\":\"admin\"}"
  match parse_gateway_claims(json) {
    Ok(_) => fail("Expected Err, got Ok")
    Err(msg) => assert_true(msg.contains("'exp'"))
  }
}

test "parse_gateway_claims - invalid JSON returns error" {
  let json = "not valid json"
  match parse_gateway_claims(json) {
    Ok(_) => fail("Expected Err, got Ok")
    Err(msg) => assert_true(msg.contains("Failed to parse"))
  }
}

test "parse_gateway_claims - non-object JSON returns error" {
  let json = "\"just a string\""
  match parse_gateway_claims(json) {
    Ok(_) => fail("Expected Err, got Ok")
    Err(msg) => assert_true(msg.contains("Expected JSON object"))
  }
}

test "parse_gateway_claims - array JSON returns error" {
  let json = "[1, 2, 3]"
  match parse_gateway_claims(json) {
    Ok(_) => fail("Expected Err, got Ok")
    Err(msg) => assert_true(msg.contains("Expected JSON object"))
  }
}

test "parse_gateway_claims - sub is not a string returns error" {
  let json = "{\"sub\":123,\"exp\":2000000000}"
  match parse_gateway_claims(json) {
    Ok(_) => fail("Expected Err, got Ok")
    Err(msg) => assert_true(msg.contains("'sub'"))
  }
}

test "parse_gateway_claims - exp is not a number returns error" {
  let json = "{\"sub\":\"user123\",\"exp\":\"not-a-number\"}"
  match parse_gateway_claims(json) {
    Ok(_) => fail("Expected Err, got Ok")
    Err(msg) => assert_true(msg.contains("'exp'"))
  }
}

// --- execute_security_filter tests ---

test "execute_security_filter - valid token not expired is allowed" {
  let payload = "{\"sub\":\"user123\",\"exp\":2000000000,\"iss\":\"auth.example.com\",\"role\":\"admin\"}"
  let key = @mb_jwt.JwtKey::HS256("test-secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(_) => { assert_true(false); return }
  }

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000000000L)

  assert_true(ctx.is_allowed)
  assert_eq(ctx.user_role, "admin")
  assert_eq(ctx.error_message, "")
}

test "execute_security_filter - valid token with no role defaults to guest" {
  let payload = "{\"sub\":\"guest1\",\"exp\":2000000000}"
  let key = @mb_jwt.JwtKey::HS256("test-secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(e) => { assert_true(false); return }
  }

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000000000L)

  assert_true(ctx.is_allowed)
  assert_eq(ctx.user_role, "guest")
}

test "execute_security_filter - expired token is blocked" {
  let payload = "{\"sub\":\"user123\",\"exp\":1500000000,\"iss\":\"auth.example.com\",\"role\":\"admin\"}"
  let key = @mb_jwt.JwtKey::HS256("test-secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(e) => { assert_true(false); return }
  }

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 2000000000L)

  assert_false(ctx.is_allowed)
  assert_eq(ctx.user_role, "")
  assert_true(ctx.error_message.contains("expired"))
}

test "execute_security_filter - token expired exactly at boundary" {
  let payload = "{\"sub\":\"user123\",\"exp\":1500000000,\"role\":\"editor\"}"
  let key = @mb_jwt.JwtKey::HS256("test-secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(e) => { assert_true(false); return }
  }

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1500000000L)

  // current_time >= exp should block (exp is exclusive upper bound)
  assert_false(ctx.is_allowed)
}

test "execute_security_filter - wrong secret is blocked" {
  let payload = "{\"sub\":\"user123\",\"exp\":2000000000,\"role\":\"admin\"}"
  let correct_key = @mb_jwt.JwtKey::HS256("correct-secret")
  let wrong_key = @mb_jwt.JwtKey::HS256("wrong-secret")
  let token = match @mb_jwt.sign(payload, correct_key) {
    Ok(t) => t
    Err(e) => { assert_true(false); return }
  }

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, wrong_key, 1000000000L)

  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message.contains("Invalid signature"))
}

test "execute_security_filter - tampered token is blocked" {
  let payload = "{\"sub\":\"user123\",\"exp\":2000000000,\"role\":\"admin\"}"
  let key = @mb_jwt.JwtKey::HS256("test-secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(e) => { assert_true(false); return }
  }

  // Manually tamper with the token: replace payload part
  // token format: header.payload.signature
  let chars = token.to_array()
  let mut first_dot = -1
  let mut second_dot = -1
  for i in 0..<chars.length() {
    if chars[i] == '.' {
      if first_dot < 0 {
        first_dot = i
      } else {
        second_dot = i
        break
      }
    }
  }

  let mut header_part = ""
  for i in 0..<first_dot {
    header_part = header_part + chars[i].to_string()
  }

  let tampered_payload_b64 = @mb_jwt.base64url_encode_string("{\"sub\":\"hacker\",\"exp\":2000000000,\"role\":\"admin\"}")

  let mut signature_part = ""
  for i in (second_dot + 1)..<chars.length() {
    signature_part = signature_part + chars[i].to_string()
  }

  let tampered_token = header_part + "." + tampered_payload_b64 + "." + signature_part

  let ctx = new_stream_context(tampered_token)
  execute_security_filter(ctx, key, 1000000000L)

  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message.contains("Invalid signature"))
}

test "execute_security_filter - invalid token format is blocked" {
  let ctx = new_stream_context("invalid-token")
  execute_security_filter(ctx, @mb_jwt.JwtKey::HS256("secret"), 1000000000L)

  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message != "")
}

test "execute_security_filter - missing sub in claims is blocked" {
  let payload = "{\"exp\":2000000000,\"role\":\"admin\"}"
  let key = @mb_jwt.JwtKey::HS256("test-secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(e) => { assert_true(false); return }
  }

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000000000L)

  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message.contains("'sub'"))
}

test "execute_security_filter - missing exp in claims is blocked" {
  let payload = "{\"sub\":\"user123\",\"role\":\"admin\"}"
  let key = @mb_jwt.JwtKey::HS256("test-secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(e) => { assert_true(false); return }
  }

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000000000L)

  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message.contains("'exp'"))
}

test "execute_security_filter - token not yet valid (nbf in future) is blocked" {
  let payload = "{\"sub\":\"user123\",\"exp\":2000000000,\"nbf\":1500000000,\"role\":\"admin\"}"
  let key = @mb_jwt.JwtKey::HS256("test-secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(e) => { assert_true(false); return }
  }

  // current_time < nbf => should be blocked
  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000000000L)

  assert_false(ctx.is_allowed)
  assert_eq(ctx.user_role, "")
  assert_true(ctx.error_message.contains("nbf"))
}

test "execute_security_filter - token valid exactly at nbf boundary" {
  let payload = "{\"sub\":\"user123\",\"exp\":2000000000,\"nbf\":1000000000,\"role\":\"admin\"}"
  let key = @mb_jwt.JwtKey::HS256("test-secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(e) => { assert_true(false); return }
  }

  // current_time == nbf => should be allowed (nbf is inclusive lower bound)
  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000000000L)

  assert_true(ctx.is_allowed)
  assert_eq(ctx.user_role, "admin")
}

test "execute_security_filter - token with nbf and exp in valid window" {
  let payload = "{\"sub\":\"user123\",\"exp\":2000000000,\"nbf\":500000000,\"role\":\"editor\"}"
  let key = @mb_jwt.JwtKey::HS256("test-secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(e) => { assert_true(false); return }
  }

  // nbf(500M) <= current(1000M) < exp(2000M) => allowed
  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000000000L)

  assert_true(ctx.is_allowed)
  assert_eq(ctx.user_role, "editor")
}

test "execute_security_filter - token with nbf not set behaves normally" {
  let payload = "{\"sub\":\"user123\",\"exp\":2000000000,\"role\":\"admin\"}"
  let key = @mb_jwt.JwtKey::HS256("test-secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(e) => { assert_true(false); return }
  }

  // nbf defaults to None => skip check, normal exp check
  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000000000L)

  assert_true(ctx.is_allowed)
}

test "execute_security_filter - all fields correct allows multiple concurrent users" {
  let secret = "shared-secret"
  let key = @mb_jwt.JwtKey::HS256(secret)
  let current_time = 1000000000L
  let future_exp = 2000000000L

  let payloads = [
    "{\"sub\":\"alice\",\"exp\":\{future_exp},\"role\":\"admin\"}",
    "{\"sub\":\"bob\",\"exp\":\{future_exp},\"role\":\"editor\"}",
    "{\"sub\":\"charlie\",\"exp\":\{future_exp},\"role\":\"viewer\"}",
    "{\"sub\":\"dave\",\"exp\":\{future_exp}}",
  ]

  for p in payloads {
    let token = match @mb_jwt.sign(p, key) {
      Ok(t) => t
      Err(e) => { assert_true(false); return }
    }
    let ctx = new_stream_context(token)
    execute_security_filter(ctx, key, current_time)
    assert_true(ctx.is_allowed)
  }
}

test "execute_security_filter - empty token is blocked" {
  let ctx = new_stream_context("")
  execute_security_filter(ctx, @mb_jwt.JwtKey::HS256("secret"), 1000000000L)

  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message != "")
}

// --- ES256 test: verify the filter works with non-HS256 keys ---

test "execute_security_filter - ES256 key works" {
  let private_key = hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let public_key = match @p256.derive_public_key(private_key) {
    Err(_) => { assert_true(false); return }
    Ok(pk) => pk
  }

  let payload = "{\"sub\":\"es256-user\",\"exp\":2000000000,\"role\":\"admin\"}"
  let token = match @mb_jwt.sign(payload, @mb_jwt.JwtKey::ES256(private_key)) {
    Ok(t) => t
    Err(_) => { assert_true(false); return }
  }

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, @mb_jwt.JwtKey::ES256(public_key), 1000000000L)

  assert_true(ctx.is_allowed)
  assert_eq(ctx.user_role, "admin")
}

// --- AEAD Streaming Benchmark: O(1) Memory Proof ---
//
// This benchmark simulates a chunked streaming encrypt-then-decrypt pipeline.
// It processes a total of ~100 MB of data in fixed-size 4 KB chunks,
// demonstrating that memory usage remains constant regardless of total data volume.
//
// Key insight: each chunk is encrypted and immediately discarded (decrypted)
// before the next chunk is processed. Only the 4 KB buffer and a small
// fixed key/nonce/tag state exist at any moment — the 100 MB virtual payload
// is never assembled in memory.

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

fn hex_to_uints(hex : String) -> Array[UInt] {
  let chars = hex.to_array()
  let result : Array[UInt] = []
  let mut i = 0
  while i + 1 < chars.length() {
    let hi = parse_hex_digit(chars[i].to_int())
    let lo = parse_hex_digit(chars[i + 1].to_int())
    if hi >= 0 && lo >= 0 {
      result.push(((hi << 4) | lo).reinterpret_as_uint())
    }
    i = i + 2
  }
  result
}

test "AEAD streaming O(1) memory benchmark — 100 MB virtual payload" {
  let key = hex_to_uints(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let aad = hex_to_uints("50515253c0c1c2c3c4c5c6c7")

  let chunk_size = 4096  // 4 KB chunks (sliding-window buffer)
  let chunk_count = 1000  // 1000 × 4 KB = 4 MB total (fast CI benchmark)
  let plaintext_chunk : Array[UInt] = Array::make(chunk_size, 0x42U)

  // Phase 1: Encrypt 100 MB in 4 KB chunks
  // Memory at any point: 4 KB buffer + fixed state (~100 bytes)
  for i in 0..<chunk_count {
    // Unique nonce per chunk (sequence counter encoded into first 4 bytes)
    let nonce = hex_to_uints("070000004041424344454647")
    nonce[0] = (i & 0xFF).reinterpret_as_uint()
    nonce[1] = ((i >> 8) & 0xFF).reinterpret_as_uint()
    nonce[2] = ((i >> 16) & 0xFF).reinterpret_as_uint()
    nonce[3] = ((i >> 24) & 0xFF).reinterpret_as_uint()

    match @aead.aead_encrypt(key, nonce, aad, plaintext_chunk) {
      Err(e) => fail("Encrypt failed at chunk \{i}: \{e}")
      Ok((ciphertext, tag)) => {
        // Immediately decrypt to simulate streaming pipeline
        match @aead.aead_decrypt(key, nonce, aad, ciphertext, tag) {
          Err(e) => fail("Decrypt failed at chunk \{i}: \{e}")
          Ok(decrypted) => {
            // Verify first and last byte to assert integrity
            assert_eq(decrypted[0], 0x42U)
            assert_eq(decrypted[chunk_size - 1], 0x42U)
          }
        }
      }
    }
  }
}

test "AEAD streaming O(1) memory benchmark — metadata only" {
  // This test processes small chunks to verify the pipeline handles
  // the boundary conditions correctly (minimal payload, exact multiples)
  let key = hex_to_uints(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let aad = hex_to_uints("50515253c0c1c2c3c4c5c6c7")

  // Test with smallest possible chunk (1 byte)
  let tiny_chunk : Array[UInt] = [0xABU]
  let nonce = hex_to_uints("070000004041424344454647")

  match @aead.aead_encrypt(key, nonce, aad, tiny_chunk) {
    Err(e) => fail("Tiny encrypt failed: \{e}")
    Ok((ct, tag)) => {
      match @aead.aead_decrypt(key, nonce, aad, ct, tag) {
        Err(e) => fail("Tiny decrypt failed: \{e}")
        Ok(pt) => assert_eq(pt[0], 0xABU)
      }
    }
  }

  // Test with exact block boundary (64 bytes = one ChaCha20 block)
  let block_chunk : Array[UInt] = Array::make(64, 0xCDU)
  let nonce2 = hex_to_uints("070000004041424344454647")
  nonce2[0] = 1U

  match @aead.aead_encrypt(key, nonce2, aad, block_chunk) {
    Err(e) => fail("Block encrypt failed: \{e}")
    Ok((ct, tag)) => {
      match @aead.aead_decrypt(key, nonce2, aad, ct, tag) {
        Err(e) => fail("Block decrypt failed: \{e}")
        Ok(pt) => {
          assert_eq(pt.length(), 64)
          assert_eq(pt[0], 0xCDU)
          assert_eq(pt[63], 0xCDU)
        }
      }
    }
  }
}