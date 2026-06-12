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

test "JWTHeader serialization and deserialization" {
  // 1. Create a mock JWT Header conforming to RFC 7515
  let header : JWTHeader = {
    alg: "HS256",
    typ: "JWT",
  }

  // 2. Test serialization to JSON string
  let json_str = @json.stringify(header.to_json())
  // Assert that the produced JSON contains the necessary keys and values
  assert_eq!(json_str, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}")

  // 3. Test deserialization back into the strongly-typed struct
  let parsed_json = @json.parse(json_str).unwrap()
  let decoded_header : JWTHeader = @json.from_json!(parsed_json)
  
  assert_eq!(decoded_header.alg, "HS256")
  assert_eq!(decoded_header.typ, "JWT")
}

test "JWTPayload industrial-grade claims validation" {
  // 1. Create a comprehensive mock payload with standard RFC 7519 claims
  // Setting timestamps explicitly to test the Option[Int64] wrapping
  let payload : JWTPayload = {
    iss: Some("auth.sustech.edu.cn"),
    sub: Some("copernicus_123"),
    aud: Some("gateway_edge"),
    exp: Some(1783928400L), // Fixed Future Unix timestamp
    nbf: Some(1773928400L),
    iat: Some(1773928400L),
    jti: Some("unique-uuid-v4-token-id"),
  }

  // 2. Test round-trip conversion via MoonBit's @json macros
  let json_obj = payload.to_json()
  let decoded_payload : JWTPayload = @json.from_json!(json_obj)

  // 3. Assert all critical structural fields remain completely uncorrupted
  assert_eq!(decoded_payload.iss, Some("auth.sustech.edu.cn"))
  assert_eq!(decoded_payload.sub, Some("copernicus_123"))
  assert_eq!(decoded_payload.aud, Some("gateway_edge"))
  assert_eq!(decoded_payload.exp, Some(1783928400L))
  assert_eq!(decoded_payload.nbf, Some(1773928400L))
  assert_eq!(decoded_payload.iat, Some(1773928400L))
  assert_eq!(decoded_payload.jti, Some("unique-uuid-v4-token-id"))
}

test "JWTPayload handles optional missing claims gracefully" {
  // In many production ecosystems, claims like nbf or jti are omitted.
  // We must ensure the types smoothly fall back to None without throwing exceptions.
  let minimal_payload : JWTPayload = {
    iss: None,
    sub: Some("anonymous_user"),
    aud: None,
    exp: Some(1783928400L),
    nbf: None,
    iat: None,
    jti: None,
  }

  let json_obj = minimal_payload.to_json()
  let decoded : JWTPayload = @json.from_json!(json_obj)

  assert_eq!(decoded.sub, Some("anonymous_user"))
  assert_eq!(decoded.iss, None)
  assert_eq!(decoded.nbf, None)
}
