// JWT tests with known test vectors

test "base64url encode simple" {
  let input : Array[UInt] = [72U, 101U, 108U, 108U, 111U]  // "Hello"
  let result = base64url_encode(input)
  assert_eq(result, "SGVsbG8")
}

test "base64url encode string" {
  let result = base64url_encode_string("Hello")
  assert_eq(result, "SGVsbG8")
}

test "base64url decode simple" {
  let result = base64url_decode("SGVsbG8")
  assert_eq(result.length(), 5)
  assert_eq(result[0], 72U)   // H
  assert_eq(result[1], 101U)  // e
  assert_eq(result[2], 108U)  // l
  assert_eq(result[3], 108U)  // l
  assert_eq(result[4], 111U)  // o
}

test "base64url roundtrip" {
  let original = "The quick brown fox jumps over the lazy dog"
  let encoded = base64url_encode_string(original)
  let decoded = base64url_decode_to_string(encoded)
  assert_eq(decoded, original)
}

test "base64url encode jwt header" {
  let header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
  let encoded = base64url_encode_string(header)
  assert_eq(encoded, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
}

test "jwt sign and verify roundtrip" {
  let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}"
  let secret = "your-256-bit-secret"

  let token = sign(payload, secret)
  let result = verify(token, secret)

  match result {
    Ok(decoded_payload) => assert_eq(decoded_payload, payload)
    Err(_) => assert_true(false)
  }
}

test "jwt verify with wrong secret fails" {
  let payload = "{\"sub\":\"1234567890\"}"
  let secret = "correct-secret"
  let wrong_secret = "wrong-secret"

  let token = sign(payload, secret)
  let result = verify(token, wrong_secret)

  match result {
    Ok(_) => assert_true(false)
    Err(_) => assert_true(true)
  }
}

test "jwt decode without verification" {
  let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\"}"
  let secret = "secret"

  let token = sign(payload, secret)
  let result = decode(token)

  match result {
    Ok(decoded_payload) => assert_eq(decoded_payload, payload)
    Err(_) => assert_true(false)
  }
}

test "jwt decode header" {
  let payload = "{\"sub\":\"test\"}"
  let secret = "secret"

  let token = sign(payload, secret)
  let header = decode_header(token)

  match header {
    Ok(h) => assert_eq(h, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}")
    Err(_) => assert_true(false)
  }
}

test "jwt invalid format" {
  let result = verify("invalid-token", "secret")
  match result {
    Ok(_) => assert_true(false)
    Err(_) => assert_true(true)
  }
}

test "jwt tampered payload fails verification" {
  let payload = "{\"sub\":\"1234567890\"}"
  let secret = "secret"

  let token = sign(payload, secret)

  // Manually tamper with the token by replacing the payload part
  // Original token: header.payload.signature
  // We'll create: header.tampered_payload.signature (same signature)
  let tampered_payload = base64url_encode_string("{\"sub\":\"hacked\"}")

  // Find the dots and reconstruct with tampered payload
  let token_bytes = @utf8.encode(token)
  let mut first_dot = -1
  let mut second_dot = -1
  for i in 0..<token_bytes.length() {
    let c = token_bytes[i].to_int()
    if c == 46 {  // '.'
      if first_dot < 0 {
        first_dot = i
      } else {
        second_dot = i
        break
      }
    }
  }

  // Extract header and signature parts
  let mut header_part = ""
  for i in 0..<first_dot {
    let c = token_bytes[i].to_int()
    header_part = header_part + c.unsafe_to_char().to_string()
  }

  let mut signature_part = ""
  for i in (second_dot + 1)..<token_bytes.length() {
    let c = token_bytes[i].to_int()
    signature_part = signature_part + c.unsafe_to_char().to_string()
  }

  let tampered_token = header_part + "." + tampered_payload + "." + signature_part

  let result = verify(tampered_token, secret)
  match result {
    Ok(_) => assert_true(false)
    Err(_) => assert_true(true)
  }
}

// Test vector from jwt.io
test "jwt.io test vector" {
  let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}"
  let secret = "your-256-bit-secret"

  let token = sign(payload, secret)

  // Verify it starts with the correct header
  assert_true(token.has_prefix("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."))

  // Verify roundtrip works
  match verify(token, secret) {
    Ok(_) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

// --- ES256 Tests ---

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
    let hi = parse_hex_digit_jwt(chars[i])
    let lo = parse_hex_digit_jwt(chars[i + 1])
    result.push(((hi << 4) | lo).reinterpret_as_uint())
    i = i + 2
  }
  result
}

fn parse_hex_digit_jwt(ch : Int) -> Int {
  if ch >= 48 && ch <= 57 { ch - 48 }
  else if ch >= 97 && ch <= 102 { ch - 87 }
  else if ch >= 65 && ch <= 70 { ch - 55 }
  else { 0 }
}

test "ES256 sign and verify round trip" {
  let private_key = hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let payload = "{\"sub\":\"1234567890\",\"name\":\"John\",\"iat\":1516239022}"

  // Derive public key
  match @p256.derive_public_key(private_key) {
    Err(e) => {
      println("keygen error: \{e}")
      assert_true(false)
    }
    Ok(public_key) => {
      match sign_es256(payload, private_key) {
        Err(e) => {
          println("sign error: \{e}")
          assert_true(false)
        }
        Ok(token) => {
          // Check header is ES256
          assert_true(token.has_prefix("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."))

          // Verify
          match verify_es256(token, public_key) {
            Ok(decoded) => assert_eq(decoded, payload)
            Err(e) => {
              println("verify error: \{e}")
              assert_true(false)
            }
          }
        }
      }
    }
  }
}

test "ES256 rejects tampered token" {
  let private_key = hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let payload = "{\"sub\":\"1234567890\"}"

  match @p256.derive_public_key(private_key) {
    Err(_) => assert_true(false)
    Ok(public_key) => {
      match sign_es256(payload, private_key) {
        Err(_) => assert_true(false)
        Ok(token) => {
          // Tamper with the payload part
          let tampered = token + "x"
          match verify_es256(tampered, public_key) {
            Ok(_) => assert_true(false) // should fail
            Err(_) => assert_true(true)
          }
        }
      }
    }
  }
}

test "ES256 decode header shows ES256 algorithm" {
  let private_key = hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  match sign_es256("{\"test\":true}", private_key) {
    Err(_) => assert_true(false)
    Ok(token) => {
      match decode_header(token) {
        Ok(header) => assert_eq(header, "{\"alg\":\"ES256\",\"typ\":\"JWT\"}")
        Err(_) => assert_true(false)
      }
    }
  }
}

// --- Tests for types serialization/deserialization ---

test "JWTHeader JSON structure via decode_header" {
  let payload = "{\"test\":true}"
  let secret = "secret"
  let token = sign(payload, secret)

  // Verify header decodes correctly
  match decode_header(token) {
    Ok(header_json) => {
      assert_eq(header_json, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}")
    }
    Err(_) => assert_true(false)
  }
}

test "JWT payload roundtrip with sign and decode" {
  let original_payload = "{\"iss\":\"issuer\",\"sub\":\"subject\",\"aud\":\"audience\",\"exp\":1000,\"nbf\":100,\"iat\":50,\"jti\":\"id\"}"
  let secret = "secret"

  // Sign the payload
  let token = sign(original_payload, secret)

  // Decode to get payload back
  match decode(token) {
    Ok(decoded_payload) => {
      assert_eq(decoded_payload, original_payload)
    }
    Err(_) => assert_true(false)
  }
}

test "JWT full roundtrip with complex standard claims" {
  let payload = "{\"iss\":\"https://auth.example.com\",\"sub\":\"user-123\",\"aud\":\"api.example.com\",\"exp\":1783928400,\"nbf\":1773928400,\"iat\":1773928400,\"jti\":\"uuid-token-id\"}"
  let secret = "complex-secret-key"

  let token = sign(payload, secret)

  // Verify returns the exact payload
  match verify(token, secret) {
    Ok(verified_payload) => {
      assert_eq(verified_payload, payload)
    }
    Err(_) => assert_true(false)
  }
}

test "JWT header remains constant across different payloads" {
  let payload1 = "{\"data\":\"test1\"}"
  let payload2 = "{\"data\":\"test2\"}"
  let secret = "secret"

  let token1 = sign(payload1, secret)
  let token2 = sign(payload2, secret)

  // Both tokens should have the same HS256 header
  match (decode_header(token1), decode_header(token2)) {
    (Ok(h1), Ok(h2)) => {
      assert_eq(h1, h2)
      assert_eq(h1, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}")
    }
    _ => assert_true(false)
  }
}

test "JWT with minimal claims" {
  let minimal_payload = "{\"sub\":\"user\",\"iat\":1000}"
  let secret = "secret"

  let token = sign(minimal_payload, secret)

  match verify(token, secret) {
    Ok(decoded) => {
      assert_eq(decoded, minimal_payload)
    }
    Err(_) => assert_true(false)
  }
}

test "JWT preserves payload with unicode and special characters" {
  let payload = "{\"iss\":\"https://auth.example.com/path?query=1\",\"sub\":\"user@domain.com\",\"name\":\"John Doe\"}"
  let secret = "secret"

  let token = sign(payload, secret)

  match decode(token) {
    Ok(decoded_payload) => {
      assert_eq(decoded_payload, payload)
    }
    Err(_) => assert_true(false)
  }
}

test "ES256 header is different from HS256" {
  let private_key = hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let payload = "{\"test\":true}"

  match sign_es256(payload, private_key) {
    Err(_) => assert_true(false)
    Ok(token) => {
      match decode_header(token) {
        Ok(header) => {
          assert_eq(header, "{\"alg\":\"ES256\",\"typ\":\"JWT\"}")
        }
        Err(_) => assert_true(false)
      }
    }
  }
}

// --- Direct Type Validation for JWT Structures ---

test "Direct Type Validation for JWT Structures" {
  
  let header = new_jwt_header("HS256", "JWT")
  assert_eq(header.alg, "HS256")
  assert_eq(header.typ, "JWT")

  let payload = new_jwt_payload(
    Some("auth.sustech.edu.cn"),
    Some("copernicus_123"),
    None,              
    Some(1783928400L), 
    None,
    Some(1773928400L),
    None,
  )

  
  assert_true(payload.iss == Some("auth.sustech.edu.cn"))
  assert_true(payload.sub == Some("copernicus_123"))
  assert_true(payload.aud == None)
  assert_true(payload.exp == Some(1783928400L))


  let jwt_obj = new_jwt(header, payload, "mock_signature_string")

 
  assert_eq(jwt_obj.header.alg, "HS256")
  assert_eq(jwt_obj.header.typ, "JWT")
  assert_true(jwt_obj.payload.sub == Some("copernicus_123"))
  assert_eq(jwt_obj.signature, "mock_signature_string")
}

test "JWT constructor with minimal claims" {
  let header = new_jwt_header("ES256", "JWT")
  let payload = new_jwt_payload(
    None,
    Some("minimal-user"),
    None,
    None,
    None,
    Some(1000L),
    None,
  )
  let jwt_obj = new_jwt(header, payload, "es256_signature")

  assert_eq(jwt_obj.header.alg, "ES256")
  assert_true(jwt_obj.payload.sub == Some("minimal-user"))
  assert_true(jwt_obj.payload.iss == None)
}

// --- JWT Claims Validation Tests ---

test "JWT Claims validation - expiration and timing flags" {
  
  let payload = new_jwt_payload(
    Some("auth.sustech.edu.cn"),
    Some("user_123"),
    None,
    Some(1767225600L), // exp: 2026-01-01
    Some(1735689600L), // nbf: 2025-01-01
    None,
    None,
  )

  let valid_res = validate_claims(payload, 1750000000L, None, None)
  assert_true(valid_res is Ok(_))

  let expired_res = validate_claims(payload, 1800000000L, None, None)
  match expired_res {
    Err(ValidationError::TokenExpired(curr, exp)) => {
      assert_eq(curr, 1800000000L)
      assert_eq(exp, 1767225600L)
    }
    _ => assert_true(false)
  }

  let premature_res = validate_claims(payload, 1700000000L, None, None)
  match premature_res {
    Err(ValidationError::TokenNotYetValid(curr, nbf)) => {
      assert_eq(curr, 1700000000L)
      assert_eq(nbf, 1735689600L)
    }
    _ => assert_true(false)
  }
}

test "JWT Claims validation - metadata mismatch" {
  let payload = new_jwt_payload(
    Some("trusted-issuer"),
    Some("user"),
    Some("expected-audience"),
    None,
    None,
    None,
    None,
  )

  // Issuer mismatch
  let iss_res = validate_claims(payload, 0L, Some("hacker-issuer"), None)
  match iss_res {
    Err(ValidationError::InvalidIssuer(name)) => assert_eq(name, "trusted-issuer")
    _ => assert_true(false)
  }

  // Audience mismatch
  let aud_res = validate_claims(payload, 0L, None, Some("wrong-audience"))
  match aud_res {
    Err(ValidationError::InvalidAudience(name)) => assert_eq(name, "expected-audience")
    _ => assert_true(false)
  }
}

test "JWT HS256 Sign and Verify Success" {
  let secret = "my_super_secret_key_123"
  let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}"
  
  let token = sign(payload, secret)
  let result = verify(token, secret)
  
  match result {
  Ok(p) => assert_eq(p, payload)
  Err(e) => fail("Expected Ok, but got Err: \{e}")
}
}

test "Benchmark JWT HS256 verification speed" {
  let secret = "production_secure_channel_secret_key_2026"
  let payload = "{\"sub\":\"user_999\",\"role\":\"admin\",\"iss\":\"stream_gateway\"}"
  let token = sign(payload, secret)

  for i = 0; i < 10000; i = i + 1 {
    let _ = verify(token, secret)
  }
}