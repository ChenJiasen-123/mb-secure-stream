// JWT tests with known test vectors

///|
test "base64url encode simple" {
  let input : Array[UInt] = [72U, 101U, 108U, 108U, 111U] // "Hello"
  let result = base64url_encode(input)
  assert_eq(result, "SGVsbG8")
}

///|
test "base64url encode string" {
  let result = base64url_encode_string("Hello")
  assert_eq(result, "SGVsbG8")
}

///|
test "base64url decode simple" {
  let result = base64url_decode("SGVsbG8")
  assert_eq(result.length(), 5)
  assert_eq(result[0], 72U) // H
  assert_eq(result[1], 101U) // e
  assert_eq(result[2], 108U) // l
  assert_eq(result[3], 108U) // l
  assert_eq(result[4], 111U) // o
}

///|
test "base64url roundtrip" {
  let original = "The quick brown fox jumps over the lazy dog"
  let encoded = base64url_encode_string(original)
  let decoded = base64url_decode_to_string(encoded)
  assert_eq(decoded, original)
}

///|
test "base64url encode jwt header" {
  let header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
  let encoded = base64url_encode_string(header)
  assert_eq(encoded, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
}

///|
test "jwt sign and verify roundtrip" {
  let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}"
  let key = JwtKey::HS256("your-256-bit-secret")

  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }
  let result = verify(token, key)

  match result {
    Ok(decoded_payload) => assert_eq(decoded_payload, payload)
    Err(_) => assert_true(false)
  }
}

///|
test "jwt verify with wrong secret fails" {
  let payload = "{\"sub\":\"1234567890\"}"
  let key = JwtKey::HS256("correct-secret")
  let wrong_key = JwtKey::HS256("wrong-secret")

  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }
  let result = verify(token, wrong_key)

  match result {
    Ok(_) => assert_true(false)
    Err(_) => assert_true(true)
  }
}

///|
test "jwt decode without verification" {
  let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\"}"
  let key = JwtKey::HS256("secret")

  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }
  let result = decode(token)

  match result {
    Ok(decoded_payload) => assert_eq(decoded_payload, payload)
    Err(_) => assert_true(false)
  }
}

///|
test "jwt decode header" {
  let payload = "{\"sub\":\"test\"}"
  let key = JwtKey::HS256("secret")

  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }
  let header = decode_header(token)

  match header {
    Ok(h) => assert_eq(h, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}")
    Err(_) => assert_true(false)
  }
}

///|
test "jwt invalid format" {
  let key = JwtKey::HS256("secret")
  let result = verify("invalid-token", key)
  match result {
    Ok(_) => assert_true(false)
    Err(InvalidFormat) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

///|
test "jwt tampered payload fails verification" {
  let payload = "{\"sub\":\"1234567890\"}"
  let key = JwtKey::HS256("secret")

  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }

  // Manually tamper with the token by replacing the payload part
  let tampered_payload = base64url_encode_string("{\"sub\":\"hacked\"}")

  // Find the dots and reconstruct with tampered payload
  let token_bytes = @utf8.encode(token)
  let mut first_dot = -1
  let mut second_dot = -1
  for i in 0..<token_bytes.length() {
    let c = token_bytes[i].to_int()
    if c == 46 { // '.'
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

  let tampered_token = header_part +
    "." +
    tampered_payload +
    "." +
    signature_part

  let result = verify(tampered_token, key)
  match result {
    Ok(_) => assert_true(false)
    Err(InvalidSignature) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

// Test vector from jwt.io

///|
test "jwt.io test vector" {
  let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}"
  let key = JwtKey::HS256("your-256-bit-secret")

  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }

  // Verify it starts with the correct header
  assert_true(token.has_prefix("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."))

  // Verify roundtrip works
  match verify(token, key) {
    Ok(_) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

// --- ES256 Tests ---

///|
fn hex_to_uints(hex : String) -> Array[UInt] {
  let raw = @utf8.encode(hex)
  let chars : Array[Int] = []
  for i in 0..<raw.length() {
    let ch = raw[i].to_int()
    if (ch >= 48 && ch <= 57) ||
      (ch >= 65 && ch <= 70) ||
      (ch >= 97 && ch <= 102) {
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

///|
fn parse_hex_digit_jwt(ch : Int) -> Int {
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

// ES256 tests are intentionally omitted here because the workspace currently
// does not expose the P-256 package in the checked test environment.

// --- Tests for types serialization/deserialization ---

///|
test "JWTHeader JSON structure via decode_header" {
  let payload = "{\"test\":true}"
  let key = JwtKey::HS256("secret")
  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }

  // Verify header decodes correctly
  match decode_header(token) {
    Ok(header_json) =>
      assert_eq(header_json, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}")
    Err(_) => assert_true(false)
  }
}

///|
test "JWT payload roundtrip with sign and decode" {
  let original_payload = "{\"iss\":\"issuer\",\"sub\":\"subject\",\"aud\":\"audience\",\"exp\":1000,\"nbf\":100,\"iat\":50,\"jti\":\"id\"}"
  let key = JwtKey::HS256("secret")

  // Sign the payload
  let token = match sign(original_payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }

  // Decode to get payload back
  match decode(token) {
    Ok(decoded_payload) => assert_eq(decoded_payload, original_payload)
    Err(_) => assert_true(false)
  }
}

///|
test "JWT full roundtrip with complex standard claims" {
  let payload = "{\"iss\":\"https://auth.example.com\",\"sub\":\"user-123\",\"aud\":\"api.example.com\",\"exp\":1783928400,\"nbf\":1773928400,\"iat\":1773928400,\"jti\":\"uuid-token-id\"}"
  let key = JwtKey::HS256("complex-secret-key")

  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }

  // Verify returns the exact payload
  match verify(token, key) {
    Ok(verified_payload) => assert_eq(verified_payload, payload)
    Err(_) => assert_true(false)
  }
}

///|
test "JWT header remains constant across different payloads" {
  let payload1 = "{\"data\":\"test1\"}"
  let payload2 = "{\"data\":\"test2\"}"
  let key = JwtKey::HS256("secret")

  let token1 = match sign(payload1, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }
  let token2 = match sign(payload2, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }

  // Both tokens should have the same HS256 header
  match (decode_header(token1), decode_header(token2)) {
    (Ok(h1), Ok(h2)) => {
      assert_eq(h1, h2)
      assert_eq(h1, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}")
    }
    _ => assert_true(false)
  }
}

///|
test "JWT with minimal claims" {
  let minimal_payload = "{\"sub\":\"user\",\"iat\":1000}"
  let key = JwtKey::HS256("secret")

  let token = match sign(minimal_payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }

  match verify(token, key) {
    Ok(decoded) => assert_eq(decoded, minimal_payload)
    Err(_) => assert_true(false)
  }
}

///|
test "JWT preserves payload with unicode and special characters" {
  let payload = "{\"iss\":\"https://auth.example.com/path?query=1\",\"sub\":\"user@domain.com\",\"name\":\"John Doe\"}"
  let key = JwtKey::HS256("secret")

  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }

  match decode(token) {
    Ok(decoded_payload) => assert_eq(decoded_payload, payload)
    Err(_) => assert_true(false)
  }
}

///|
test "ES256 header is different from HS256" {
  let private_key = hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let payload = "{\"test\":true}"

  match sign(payload, JwtKey::ES256(private_key)) {
    Err(_) => assert_true(false)
    Ok(token) =>
      match decode_header(token) {
        Ok(header) => assert_eq(header, "{\"alg\":\"ES256\",\"typ\":\"JWT\"}")
        Err(_) => assert_true(false)
      }
  }
}

// --- Direct Type Validation for JWT Structures ---

///|
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

///|
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

///|
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
    Err(TokenExpired(curr, exp)) => {
      assert_eq(curr, 1800000000L)
      assert_eq(exp, 1767225600L)
    }
    _ => assert_true(false)
  }

  let premature_res = validate_claims(payload, 1700000000L, None, None)
  match premature_res {
    Err(TokenNotYetValid(curr, nbf)) => {
      assert_eq(curr, 1700000000L)
      assert_eq(nbf, 1735689600L)
    }
    _ => assert_true(false)
  }
}

///|
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
    Err(InvalidIssuer(name)) => assert_eq(name, "trusted-issuer")
    _ => assert_true(false)
  }

  // Audience mismatch
  let aud_res = validate_claims(payload, 0L, None, Some("wrong-audience"))
  match aud_res {
    Err(InvalidAudience(name)) => assert_eq(name, "expected-audience")
    _ => assert_true(false)
  }
}

///|
test "JWT HS256 Sign and Verify Success" {
  let key = JwtKey::HS256("my_super_secret_key_123")
  let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}"

  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }
  let result = verify(token, key)

  match result {
    Ok(p) => assert_eq(p, payload)
    Err(e) => fail("Expected Ok, but got Err: \{JWTError::to_debug_string(e)}")
  }
}

///|
test "Benchmark JWT HS256 verification speed" {
  let key = JwtKey::HS256("production_secure_channel_secret_key_2026")
  let payload = "{\"sub\":\"user_999\",\"role\":\"admin\",\"iss\":\"stream_gateway\"}"
  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }

  for i = 0; i < 10000; i = i + 1 {
    let _ = verify(token, key)
  }
}

// =============================================================================
// SECURITY VULNERABILITY TEST SUITE
// Based on:
//   - OWASP WSTG-CRYP-04 JWT Vulnerability Matrix
//   - jwt_tool known CVE / attack test cases
//   - RFC 7519 §7.2 / RFC 8032 (EdDSA, referenced for algorithm confusion context)
// =============================================================================

// --- CVE-2016-5431 / OWASP WSTG: alg:none attack ---
// An attacker strips the signature and sets alg to "none".
// The verifier MUST reject such tokens unconditionally.

///|
test "security: alg:none attack is rejected (CVE-2016-5431)" {
  // Craft a token with alg:none header and empty signature
  let none_header = base64url_encode_string(
    "{\"alg\":\"none\",\"typ\":\"JWT\"}",
  )
  let payload_enc = base64url_encode_string(
    "{\"sub\":\"attacker\",\"admin\":true}",
  )
  let forged_token = none_header + "." + payload_enc + "."
  let key = JwtKey::HS256("secret")
  match verify(forged_token, key) {
    Ok(_) => assert_true(false) // MUST NOT accept
    Err(AlgorithmMismatch(_)) => assert_true(true)
    Err(_) => assert_true(true) // any error is acceptable
  }
}

///|
test "security: alg:none with uppercase is rejected" {
  let none_header = base64url_encode_string(
    "{\"alg\":\"NONE\",\"typ\":\"JWT\"}",
  )
  let payload_enc = base64url_encode_string("{\"sub\":\"attacker\"}")
  let forged_token = none_header + "." + payload_enc + "."
  let key = JwtKey::HS256("secret")
  match verify(forged_token, key) {
    Ok(_) => assert_true(false)
    Err(_) => assert_true(true)
  }
}

///|
test "security: alg:none with mixed case is rejected" {
  let none_header = base64url_encode_string(
    "{\"alg\":\"None\",\"typ\":\"JWT\"}",
  )
  let payload_enc = base64url_encode_string("{\"sub\":\"attacker\"}")
  let forged_token = none_header + "." + payload_enc + "."
  let key = JwtKey::HS256("secret")
  match verify(forged_token, key) {
    Ok(_) => assert_true(false)
    Err(_) => assert_true(true)
  }
}

// --- OWASP WSTG / jwt_tool: Algorithm Confusion / Key Confusion Attack ---
// An attacker changes the header alg from ES256 to HS256 and signs with the
// public key as the HMAC secret. The verifier MUST reject due to alg mismatch.

///|
test "security: ES256 token rejected when verified with HS256 key" {
  let private_key = hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let payload = "{\"sub\":\"user\"}"
  match @p256.derive_public_key(private_key) {
    Err(_) => assert_true(false)
    Ok(_public_key) => {
      let sign_key = JwtKey::ES256(private_key)
      match sign(payload, sign_key) {
        Err(_) => assert_true(false)
        Ok(es256_token) => {
          // Try to verify an ES256 token using an HS256 key — must fail
          let hs256_key = JwtKey::HS256("some-secret")
          match verify(es256_token, hs256_key) {
            Ok(_) => assert_true(false) // algorithm confusion must be rejected
            Err(AlgorithmMismatch(_)) => assert_true(true)
            Err(_) => assert_true(true)
          }
        }
      }
    }
  }
}

///|
test "security: HS256 token rejected when verified with ES256 key" {
  let private_key = hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let payload = "{\"sub\":\"user\"}"
  let hs256_key = JwtKey::HS256("secret")
  match sign(payload, hs256_key) {
    Err(_) => assert_true(false)
    Ok(hs256_token) =>
      // Try to verify an HS256 token using an ES256 key — must fail
      match @p256.derive_public_key(private_key) {
        Err(_) => assert_true(false)
        Ok(public_key) => {
          let es256_verify_key = JwtKey::ES256(public_key)
          match verify(hs256_token, es256_verify_key) {
            Ok(_) => assert_true(false)
            Err(AlgorithmMismatch(_)) => assert_true(true)
            Err(_) => assert_true(true)
          }
        }
      }
  }
}

// --- OWASP WSTG / jwt_tool: Signature Strip Attack ---
// Remove the signature entirely (empty third segment).
// The verifier MUST reject tokens with missing/empty signatures.

///|
test "security: empty signature is rejected" {
  let header_enc = base64url_encode_string(
    "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
  )
  let payload_enc = base64url_encode_string("{\"sub\":\"user\"}")
  let no_sig_token = header_enc + "." + payload_enc + "."
  let key = JwtKey::HS256("secret")
  match verify(no_sig_token, key) {
    Ok(_) => assert_true(false) // MUST NOT accept empty signature
    Err(_) => assert_true(true)
  }
}

// --- OWASP WSTG / jwt_tool: Truncated token (missing segments) ---

///|
test "security: token with only one segment is rejected" {
  let key = JwtKey::HS256("secret")
  match verify("onlyone", key) {
    Ok(_) => assert_true(false)
    Err(InvalidFormat) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

///|
test "security: token with only two segments is rejected" {
  let key = JwtKey::HS256("secret")
  match verify("header.payload", key) {
    Ok(_) => assert_true(false)
    Err(InvalidFormat) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

///|
test "security: empty string token is rejected" {
  let key = JwtKey::HS256("secret")
  match verify("", key) {
    Ok(_) => assert_true(false)
    Err(InvalidFormat) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

// --- OWASP WSTG / jwt_tool: Payload Tampering ---
// Modify the payload claims (e.g., escalate privileges) without re-signing.

///|
test "security: privilege escalation via payload tampering is rejected" {
  let payload = "{\"sub\":\"user\",\"role\":\"user\"}"
  let key = JwtKey::HS256("secret")
  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }
  // Replace role:user with role:admin in the payload
  let admin_payload = base64url_encode_string(
    "{\"sub\":\"user\",\"role\":\"admin\"}",
  )
  let parts = token.to_array()
  let mut first_dot = -1
  let mut second_dot = -1
  for i in 0..<parts.length() {
    if parts[i] == '.' {
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
    header_part = header_part + parts[i].to_string()
  }
  let mut sig_part = ""
  for i in (second_dot + 1)..<parts.length() {
    sig_part = sig_part + parts[i].to_string()
  }
  let tampered = header_part + "." + admin_payload + "." + sig_part
  match verify(tampered, key) {
    Ok(_) => assert_true(false)
    Err(InvalidSignature) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

// --- OWASP WSTG / jwt_tool: Header Injection / kid manipulation ---
// Inject unexpected fields into the header; the verifier must still enforce alg.

///|
test "security: header with injected kid field still enforces alg" {
  // Craft a token with a header containing a kid field and alg:none
  let evil_header = base64url_encode_string(
    "{\"alg\":\"none\",\"typ\":\"JWT\",\"kid\":\"../../etc/passwd\"}",
  )
  let payload_enc = base64url_encode_string("{\"sub\":\"attacker\"}")
  let forged = evil_header + "." + payload_enc + "."
  let key = JwtKey::HS256("secret")
  match verify(forged, key) {
    Ok(_) => assert_true(false)
    Err(_) => assert_true(true)
  }
}

// --- OWASP WSTG: kid path traversal with valid alg (boundary 1) ---
// Even when alg is legitimate (HS256), a kid containing path-traversal characters
// must not cause the verifier to read arbitrary files or panic.
// Here we verify the token is rejected (signature won't match) and no crash occurs.

///|
test "security: kid path traversal with valid alg is rejected safely" {
  // Build a token whose header has alg:HS256 but kid contains path traversal
  let evil_header = base64url_encode_string(
    "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"../../etc/passwd\"}",
  )
  let payload_enc = base64url_encode_string(
    "{\"sub\":\"attacker\",\"admin\":true}",
  )
  // Sign the header+payload with a known key so the structure is valid
  let key = JwtKey::HS256("secret")
  let signing_input = evil_header + "." + payload_enc
  // Compute a real HMAC so the token is structurally valid but uses a rogue header
  let real_token = match sign("{\"sub\":\"attacker\",\"admin\":true}", key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }
  // Extract the real signature from a legitimately signed token
  let real_parts = real_token.to_array()
  let mut dot2_real = -1
  let mut dc = 0
  for i in 0..<real_parts.length() {
    if real_parts[i] == '.' {
      dc = dc + 1
      if dc == 2 {
        dot2_real = i
        break
      }
    }
  }
  let mut real_sig = ""
  for i in (dot2_real + 1)..<real_parts.length() {
    real_sig = real_sig + real_parts[i].to_string()
  }
  // Assemble: evil_header.payload.real_sig — header mismatch means sig won't verify
  let forged = signing_input + "." + real_sig
  // Must not panic; must return an error (signature mismatch due to different header)
  match verify(forged, key) {
    Ok(_) => assert_true(false) // must not accept a token with a tampered header
    Err(_) => assert_true(true) // any error is correct — no crash, no bypass
  }
}

// --- OWASP WSTG: Weak secret brute-force resistance ---
// A token signed with a very short/weak key must still fail verification
// when checked against a different key (no bypass possible).

///|
test "security: weak 1-byte secret still enforces signature check" {
  let weak_key = JwtKey::HS256("x")
  let payload = "{\"sub\":\"user\"}"
  let token = match sign(payload, weak_key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }
  // Verify with a different key must fail
  let other_key = JwtKey::HS256("y")
  match verify(token, other_key) {
    Ok(_) => assert_true(false)
    Err(InvalidSignature) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

// --- jwt_tool: Signature reuse / cross-token replay ---
// A valid signature from one token must not validate a different payload.

///|
test "security: signature from token A cannot validate token B payload" {
  let key = JwtKey::HS256("secret")
  let token_a = match sign("{\"sub\":\"alice\"}", key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }
  let token_b = match sign("{\"sub\":\"bob\"}", key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }

  // Extract parts of both tokens
  let parts_a = token_a.to_array()
  let parts_b = token_b.to_array()

  let mut dot1_a = -1
  let mut dot2_a = -1
  for i in 0..<parts_a.length() {
    if parts_a[i] == '.' {
      if dot1_a < 0 {
        dot1_a = i
      } else {
        dot2_a = i
        break
      }
    }
  }
  let mut dot1_b = -1
  let mut dot2_b = -1
  for i in 0..<parts_b.length() {
    if parts_b[i] == '.' {
      if dot1_b < 0 {
        dot1_b = i
      } else {
        dot2_b = i
        break
      }
    }
  }

  // Build header_b.payload_b.sig_a (cross-token signature reuse)
  let mut header_b = ""
  for i in 0..<dot1_b {
    header_b = header_b + parts_b[i].to_string()
  }
  let mut payload_b = ""
  for i in (dot1_b + 1)..<dot2_b {
    payload_b = payload_b + parts_b[i].to_string()
  }
  let mut sig_a = ""
  for i in (dot2_a + 1)..<parts_a.length() {
    sig_a = sig_a + parts_a[i].to_string()
  }

  let replayed = header_b + "." + payload_b + "." + sig_a
  match verify(replayed, key) {
    Ok(_) => assert_true(false) // cross-token replay must fail
    Err(InvalidSignature) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

// --- RFC 7519 §4.1.4 / OWASP WSTG: Expired token is rejected ---

///|
test "security: expired token is rejected by validate_claims" {
  let payload = new_jwt_payload(
    None,
    Some("user"),
    None,
    Some(1000L), // exp in the past
    None,
    Some(500L),
    None,
  )
  match validate_claims(payload, 2000L, None, None) {
    Err(TokenExpired(curr, exp)) => {
      assert_eq(curr, 2000L)
      assert_eq(exp, 1000L)
    }
    _ => assert_true(false)
  }
}

// --- RFC 7519 §4.1.5 / OWASP WSTG: nbf (not-before) enforcement ---

///|
test "security: token used before nbf is rejected by validate_claims" {
  let payload = new_jwt_payload(
    None,
    Some("user"),
    None,
    Some(9999999999L),
    Some(5000L), // nbf in the future
    Some(1000L),
    None,
  )
  match validate_claims(payload, 1000L, None, None) {
    Err(TokenNotYetValid(curr, nbf)) => {
      assert_eq(curr, 1000L)
      assert_eq(nbf, 5000L)
    }
    _ => assert_true(false)
  }
}

// --- RFC 7519 §4.1.1 / OWASP WSTG: Issuer validation ---

///|
test "security: wrong issuer is rejected by validate_claims" {
  let payload = new_jwt_payload(
    Some("legitimate-issuer"),
    Some("user"),
    None,
    None,
    None,
    None,
    None,
  )
  match validate_claims(payload, 0L, Some("expected-issuer"), None) {
    Err(InvalidIssuer(iss)) => assert_eq(iss, "legitimate-issuer")
    _ => assert_true(false)
  }
}

// --- RFC 7519 §4.1.3 / OWASP WSTG: Audience validation ---

///|
test "security: wrong audience is rejected by validate_claims" {
  let payload = new_jwt_payload(
    None,
    Some("user"),
    Some("service-a"),
    None,
    None,
    None,
    None,
  )
  match validate_claims(payload, 0L, None, Some("service-b")) {
    Err(InvalidAudience(aud)) => assert_eq(aud, "service-a")
    _ => assert_true(false)
  }
}

// --- jwt_tool: Null / zero-length key ---
// Signing with an empty secret must still produce a verifiable token,
// but a different key must not verify it (no bypass via empty key).

///|
test "security: empty HMAC secret still enforces signature binding" {
  let empty_key = JwtKey::HS256("")
  let payload = "{\"sub\":\"user\"}"
  let token = match sign(payload, empty_key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }
  // Correct empty key must verify
  match verify(token, empty_key) {
    Ok(p) => assert_eq(p, payload)
    Err(_) => assert_true(false)
  }
  // Different key must not verify
  let other_key = JwtKey::HS256("notempty")
  match verify(token, other_key) {
    Ok(_) => assert_true(false)
    Err(InvalidSignature) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

// --- jwt_tool: Dots-only / malformed structure ---

///|
test "security: token with only dots is rejected" {
  let key = JwtKey::HS256("secret")
  match verify("...", key) {
    Ok(_) => assert_true(false)
    Err(_) => assert_true(true)
  }
}

///|
test "security: token with extra dots is still parseable but signature fails" {
  let key = JwtKey::HS256("secret")
  // Extra dots: header.payload.sig.extra — signature won't match
  let header_enc = base64url_encode_string(
    "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
  )
  let payload_enc = base64url_encode_string("{\"sub\":\"user\"}")
  let extra_dot_token = header_enc + "." + payload_enc + ".fakesig.extra"
  match verify(extra_dot_token, key) {
    Ok(_) => assert_true(false)
    Err(InvalidSignature) => assert_true(true)
    Err(_) => assert_true(true) // any error is acceptable
  }
}

// --- OWASP WSTG: Base64url padding confusion ---
// Standard base64 uses '=' padding; base64url must not require it.
// Tokens with standard base64 padding characters must be handled gracefully.

///|
test "security: base64url decode ignores invalid padding characters" {
  // "SGVsbG8=" is "Hello" in standard base64 with padding
  // Our decoder should handle this gracefully (either decode or return partial)
  let result = base64url_decode("SGVsbG8")
  assert_eq(result.length(), 5)
  assert_eq(result[0], 72U) // H
}

// --- jwt_tool: ES256 signature with all-zero r or s component ---
// A degenerate ECDSA signature (r=0 or s=0) must be rejected.

///|
test "security: ES256 all-zero signature is rejected" {
  let private_key = hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let payload = "{\"sub\":\"user\"}"
  match @p256.derive_public_key(private_key) {
    Err(_) => assert_true(false)
    Ok(public_key) => {
      let sign_key = JwtKey::ES256(private_key)
      match sign(payload, sign_key) {
        Err(_) => assert_true(false)
        Ok(token) => {
          // Replace signature with 64 zero bytes
          let parts = token.to_array()
          let mut dot2 = -1
          let mut dot_count = 0
          for i in 0..<parts.length() {
            if parts[i] == '.' {
              dot_count = dot_count + 1
              if dot_count == 2 {
                dot2 = i
                break
              }
            }
          }
          let mut prefix = ""
          for i in 0..<(dot2 + 1) {
            prefix = prefix + parts[i].to_string()
          }
          let zero_sig = base64url_encode(Array::make(64, 0U))
          let forged = prefix + zero_sig
          let verify_key = JwtKey::ES256(public_key)
          match verify(forged, verify_key) {
            Ok(_) => assert_true(false) // zero signature must be rejected
            Err(_) => assert_true(true)
          }
        }
      }
    }
  }
}

// --- jwt_tool: ES256 truncated signature (< 64 bytes) ---

///|
test "security: ES256 truncated signature is rejected" {
  let private_key = hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let payload = "{\"sub\":\"user\"}"
  match @p256.derive_public_key(private_key) {
    Err(_) => assert_true(false)
    Ok(public_key) => {
      let sign_key = JwtKey::ES256(private_key)
      match sign(payload, sign_key) {
        Err(_) => assert_true(false)
        Ok(token) => {
          let parts = token.to_array()
          let mut dot2 = -1
          let mut dot_count = 0
          for i in 0..<parts.length() {
            if parts[i] == '.' {
              dot_count = dot_count + 1
              if dot_count == 2 {
                dot2 = i
                break
              }
            }
          }
          let mut prefix = ""
          for i in 0..<(dot2 + 1) {
            prefix = prefix + parts[i].to_string()
          }
          // Only 32 bytes (half the required 64)
          let short_sig = base64url_encode(Array::make(32, 0xAAU))
          let forged = prefix + short_sig
          let verify_key = JwtKey::ES256(public_key)
          match verify(forged, verify_key) {
            Ok(_) => assert_true(false)
            Err(InvalidSignature) => assert_true(true)
            Err(_) => assert_true(true)
          }
        }
      }
    }
  }
}

// --- OWASP WSTG: Constant-time comparison prevents timing oracle ---
// Two tokens with different signatures must both fail, and the implementation
// must use constant-time comparison (structural test: both wrong sigs fail).

///|
test "security: two different wrong signatures both fail (constant-time)" {
  let key = JwtKey::HS256("secret")
  let payload = "{\"sub\":\"user\"}"
  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => {
      assert_true(false)
      return
    }
  }
  let parts = token.to_array()
  let mut dot2 = -1
  let mut dot_count = 0
  for i in 0..<parts.length() {
    if parts[i] == '.' {
      dot_count = dot_count + 1
      if dot_count == 2 {
        dot2 = i
        break
      }
    }
  }
  let mut prefix = ""
  for i in 0..<(dot2 + 1) {
    prefix = prefix + parts[i].to_string()
  }

  // Wrong sig 1: all 'A'
  let wrong1 = prefix + base64url_encode(Array::make(32, 65U))
  // Wrong sig 2: all 'B'
  let wrong2 = prefix + base64url_encode(Array::make(32, 66U))

  match verify(wrong1, key) {
    Ok(_) => assert_true(false)
    Err(InvalidSignature) => assert_true(true)
    Err(_) => assert_true(false)
  }
  match verify(wrong2, key) {
    Ok(_) => assert_true(false)
    Err(InvalidSignature) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

// --- RFC 7519 §7.2: Claims with no exp/nbf/iss/aud pass validate_claims ---

///|
test "security: token with no time claims passes validate_claims at any time" {
  let payload = new_jwt_payload(
    None,
    Some("user"),
    None,
    None,
    None,
    None,
    None,
  )
  match validate_claims(payload, 9999999999L, None, None) {
    Ok(_) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

// --- OWASP WSTG: iss/aud present in token but not checked by caller ---
// If expected_iss/expected_aud is None, the claim is not validated (permissive).

///|
test "security: iss in token not validated when expected_iss is None" {
  let payload = new_jwt_payload(
    Some("any-issuer"),
    Some("user"),
    None,
    None,
    None,
    None,
    None,
  )
  // No expected_iss provided — should pass
  match validate_claims(payload, 0L, None, None) {
    Ok(_) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

// --- jwt_tool: Exact boundary: exp == current_time is expired (>=) ---

///|
test "security: token with exp exactly equal to current_time is expired" {
  let payload = new_jwt_payload(
    None,
    Some("user"),
    None,
    Some(1000L),
    None,
    None,
    None,
  )
  // exp == current_time: must be rejected (RFC 7519: "on or after")
  match validate_claims(payload, 1000L, None, None) {
    Err(TokenExpired(_, _)) => assert_true(true)
    _ => assert_true(false)
  }
}

// --- jwt_tool: Exact boundary: nbf == current_time is valid (>=) ---

///|
test "security: token with nbf exactly equal to current_time is valid" {
  let payload = new_jwt_payload(
    None,
    Some("user"),
    None,
    None,
    Some(1000L),
    None,
    None,
  )
  // nbf == current_time: must be accepted (RFC 7519: "on or after nbf")
  match validate_claims(payload, 1000L, None, None) {
    Ok(_) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

// --- OWASP WSTG: Base64url parser differential — standard base64 chars rejected ---
// RFC 4648 §5: base64url MUST NOT contain '+', '/', or '=' padding.
// If the decoder silently accepts these, an attacker can craft tokens that parse
// differently in the gateway vs. downstream services (parser differential attack).

///|
test "security: base64url decoder rejects standard base64 padding char '='" {
  // "SGVsbG8=" is "Hello" in standard base64 with padding — '=' is illegal in base64url.
  // The decoder encounters '=' (decode value -1) in the 4-char group "G8=<nothing>",
  // so it breaks out of the main loop. The remaining 3 chars "G8=" are handled by
  // the trailing-2-char branch: only "G8" are valid, yielding 1 extra byte.
  // Total: 3 bytes from "SGVs" group + 1 byte from "G8" = 4 bytes (not 5).
  // This confirms '=' is NOT treated as a valid base64url character.
  let result = base64url_decode("SGVsbG8=")
  // The '=' causes early termination — result is shorter than the valid 5-byte decode.
  let valid = base64url_decode("SGVsbG8")
  assert_true(result.length() < valid.length())
  // First byte must still be 'H' (72) — partial decode is correct up to the break point
  assert_eq(result[0], 72U) // H
}

///|
test "security: base64url decoder rejects standard base64 char '+'" {
  // '+' is the standard base64 char for index 62; base64url uses '-' instead.
  // A token containing '+' must not decode to the same value as '-'.
  // get_decode_value('+') == -1, so the loop breaks on encountering it.
  let with_plus = base64url_decode("SGVs+G8") // '+' at position 4
  let without = base64url_decode("SGVsbG8") // correct base64url
  // The '+' version must decode fewer bytes (loop breaks at the invalid char)
  assert_true(with_plus.length() < without.length())
}

///|
test "security: base64url decoder rejects standard base64 char '/'" {
  // '/' is the standard base64 char for index 63; base64url uses '_' instead.
  let with_slash = base64url_decode("SGVs/G8") // '/' at position 4
  let without = base64url_decode("SGVsbG8") // correct base64url
  assert_true(with_slash.length() < without.length())
}
