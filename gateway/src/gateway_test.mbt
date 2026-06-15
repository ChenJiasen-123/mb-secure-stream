// Gateway module tests
// Tests for parse_gateway_claims (payload.mbt) and execute_security_filter (middleware.mbt)

// --- parse_gateway_claims tests ---

test "parse_gateway_claims - valid payload with all fields" {
  let json = "{\"sub\":\"user123\",\"exp\":2000000000,\"iss\":\"auth.example.com\",\"role\":\"admin\"}"
  match parse_gateway_claims(json) {
    Ok(claims) => {
      assert_eq(claims.sub, "user123")
      assert_eq(claims.exp, 2000000000L)
      assert_eq(claims.iss, "auth.example.com")
      assert_eq(claims.role, "admin")
    }
    Err(e) => fail("Expected Ok, got Err: \{e}")
  }
}

test "parse_gateway_claims - missing iss defaults to empty string" {
  let json = "{\"sub\":\"user123\",\"exp\":2000000000}"
  match parse_gateway_claims(json) {
    Ok(claims) => {
      assert_eq(claims.sub, "user123")
      assert_eq(claims.exp, 2000000000L)
      assert_eq(claims.iss, "")
      assert_eq(claims.role, "guest")
    }
    Err(e) => fail("Expected Ok, got Err: \{e}")
  }
}

test "parse_gateway_claims - missing role defaults to guest" {
  let json = "{\"sub\":\"user123\",\"exp\":2000000000,\"iss\":\"auth.example.com\"}"
  match parse_gateway_claims(json) {
    Ok(claims) => {
      assert_eq(claims.role, "guest")
      assert_eq(claims.iss, "auth.example.com")
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
  let secret = "test-secret"
  let token = @mb_jwt.sign(payload, secret)

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, secret, 1000000000L)

  assert_true(ctx.is_allowed)
  assert_eq(ctx.user_role, "admin")
  assert_eq(ctx.error_message, "")
}

test "execute_security_filter - valid token with guest role" {
  let payload = "{\"sub\":\"guest1\",\"exp\":2000000000}"
  let secret = "test-secret"
  let token = @mb_jwt.sign(payload, secret)

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, secret, 1000000000L)

  assert_true(ctx.is_allowed)
  assert_eq(ctx.user_role, "guest")
}

test "execute_security_filter - expired token is blocked" {
  let payload = "{\"sub\":\"user123\",\"exp\":1500000000,\"iss\":\"auth.example.com\",\"role\":\"admin\"}"
  let secret = "test-secret"
  let token = @mb_jwt.sign(payload, secret)

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, secret, 2000000000L)

  assert_false(ctx.is_allowed)
  assert_eq(ctx.user_role, "")
  assert_true(ctx.error_message.contains("Token has expired") || ctx.error_message.contains("expired"))
}

test "execute_security_filter - token expired exactly at boundary" {
  let payload = "{\"sub\":\"user123\",\"exp\":1500000000,\"role\":\"editor\"}"
  let secret = "test-secret"
  let token = @mb_jwt.sign(payload, secret)

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, secret, 1500000000L)

  // current_time >= exp should block (exp is exclusive upper bound)
  assert_false(ctx.is_allowed)
}

test "execute_security_filter - wrong secret is blocked" {
  let payload = "{\"sub\":\"user123\",\"exp\":2000000000,\"role\":\"admin\"}"
  let correct_secret = "correct-secret"
  let wrong_secret = "wrong-secret"
  let token = @mb_jwt.sign(payload, correct_secret)

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, wrong_secret, 1000000000L)

  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message.contains("Crypto Blocked"))
}

test "execute_security_filter - tampered token is blocked" {
  let payload = "{\"sub\":\"user123\",\"exp\":2000000000,\"role\":\"admin\"}"
  let secret = "test-secret"
  let token = @mb_jwt.sign(payload, secret)

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
  execute_security_filter(ctx, secret, 1000000000L)

  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message.contains("Crypto Blocked") || ctx.error_message.contains("signature"))
}

test "execute_security_filter - invalid token format is blocked" {
  let ctx = new_stream_context("invalid-token")
  execute_security_filter(ctx, "secret", 1000000000L)

  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message != "")
}

test "execute_security_filter - missing sub in claims is blocked" {
  let payload = "{\"exp\":2000000000,\"role\":\"admin\"}"
  let secret = "test-secret"
  let token = @mb_jwt.sign(payload, secret)

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, secret, 1000000000L)

  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message.contains("'sub'"))
}

test "execute_security_filter - missing exp in claims is blocked" {
  let payload = "{\"sub\":\"user123\",\"role\":\"admin\"}"
  let secret = "test-secret"
  let token = @mb_jwt.sign(payload, secret)

  let ctx = new_stream_context(token)
  execute_security_filter(ctx, secret, 1000000000L)

  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message.contains("'exp'"))
}

test "execute_security_filter - all fields correct allows multiple concurrent users" {
  let secret = "shared-secret"
  let current_time = 1000000000L
  let future_exp = 2000000000L

  let payloads = [
    "{\"sub\":\"alice\",\"exp\":\{future_exp},\"role\":\"admin\"}",
    "{\"sub\":\"bob\",\"exp\":\{future_exp},\"role\":\"editor\"}",
    "{\"sub\":\"charlie\",\"exp\":\{future_exp},\"role\":\"viewer\"}",
    "{\"sub\":\"dave\",\"exp\":\{future_exp}}",
  ]

  for p in payloads {
    let token = @mb_jwt.sign(p, secret)
    let ctx = new_stream_context(token)
    execute_security_filter(ctx, secret, current_time)
    assert_true(ctx.is_allowed)
  }
}

test "execute_security_filter - empty token is blocked" {
  let ctx = new_stream_context("")
  execute_security_filter(ctx, "secret", 1000000000L)

  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message != "")
}