// JWT (JSON Web Tokens) implementation with HS256 and ES256 signing
// RFC 7519: https://tools.ietf.org/html/rfc7519
// RFC 7518 Section 3.4: ES256 (ECDSA P-256 + SHA-256)
//
// SECURITY FEATURES:
// - Rejects "alg:none" to prevent signature bypass attacks (CVE-2016-5431)
// - JwtKey enum prevents algorithm/key-type confusion at compile time
// - Constant-time signature comparison prevents timing attacks
// - verify() dispatches to correct algorithm based on key variant

///|
let jwt_header_hs256 : String = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"

///|
let jwt_header_es256 : String = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"

// Both HMAC and ECDSA returns a fixed-size array of UInt, which we convert to Array[UInt] for encoding.

///|
fn fixed_to_array(fixed : FixedArray[UInt]) -> Array[UInt] {
  let arr : Array[UInt] = []
  for i in 0..<fixed.length() {
    arr.push(fixed[i])
  }
  arr
}

///|
/// Constant-time comparison to prevent timing attacks.
/// Even when lengths differ, it compares up to the minimum length
/// to avoid leaking length information via early return.
fn constant_time_eq(a : Array[UInt], b : Array[UInt]) -> Bool {
  let min_len = if a.length() < b.length() { a.length() } else { b.length() }
  let mut diff : UInt = 0U
  for i in 0..<min_len {
    diff = diff | (a[i] ^ b[i])
  }
  // Also accumulate length difference to make it constant-time
  diff = diff |
    (a.length().reinterpret_as_uint() ^ b.length().reinterpret_as_uint())
  diff == 0U
}

///|
/// Token part positions in the original token string.
/// Uses indices to avoid creating intermediate substring allocations.
priv struct TokenParts {
  header_start : Int
  header_end : Int // exclusive, position of first '.'
  payload_start : Int
  payload_end : Int // exclusive, position of second '.'
  signature_start : Int
  signature_end : Int // exclusive, end of string
}

///|
/// Zero-copy token splitter: finds the two '.' positions
/// and returns index ranges without allocating substrings.
fn split_token_indices(token : String) -> Result[TokenParts, JWTError] {
  let len = token.length()
  let mut first_dot = -1
  let mut second_dot = -1

  for i in 0..<len {
    if token[i] == '.' {
      if first_dot < 0 {
        first_dot = i
      } else {
        second_dot = i
        break
      }
    }
  }

  if first_dot < 0 || second_dot < 0 {
    return Err(InvalidFormat)
  }

  Ok({
    header_start: 0,
    header_end: first_dot,
    payload_start: first_dot + 1,
    payload_end: second_dot,
    signature_start: second_dot + 1,
    signature_end: len,
  })
}

///|
/// Validates the header to reject `alg: none` and other insecure algorithms.
fn validate_header_algorithm(
  header_json : String,
  expected_alg : String,
) -> Result[Unit, JWTError] {
  let buf = StringBuilder::new()
  for ch in header_json.to_lower().iter() {
    match ch {
      ' ' | '\n' | '\r' | '\t' => ()
      _ => buf.write_char(ch)
    }
  }
  let cleaned = buf.to_string()

  if cleaned.contains("\"alg\":\"none\"") {
    return Err(AlgorithmMismatch("alg:none is not permitted (CVE-2016-5431)"))
  }

  let expected_pattern = "\"alg\":\"\{expected_alg.to_lower()}\""
  if !cleaned.contains(expected_pattern) {
    return Err(AlgorithmMismatch(expected_alg))
  }

  Ok(())
}

///|
fn string_to_uints(s : String) -> Array[UInt] {
  let raw = @utf8.encode(s)
  let uints : Array[UInt] = []
  for i in 0..<raw.length() {
    uints.push(raw[i].to_int().reinterpret_as_uint())
  }
  uints
}

///|
/// Signs a JSON payload using the algorithm and key material encoded in `JwtKey`.
/// - `JwtKey::HS256(secret)` → HMAC-SHA256
/// - `JwtKey::ES256(private_key)` → ECDSA P-256 + SHA-256
pub fn sign(payload : String, key : JwtKey) -> Result[String, JWTError] {
  match key {
    HS256(secret) => {
      let header_encoded = base64url_encode_string(jwt_header_hs256)
      let payload_encoded = base64url_encode_string(payload)
      let signing_input = header_encoded + "." + payload_encoded
      let signature = @hmac.hmac_sha256_string(signing_input, secret)
      let signature_encoded = base64url_encode(fixed_to_array(signature))
      Ok(signing_input + "." + signature_encoded)
    }
    ES256(private_key_bytes) => {
      let header_encoded = base64url_encode_string(jwt_header_es256)
      let payload_encoded = base64url_encode_string(payload)
      let signing_input = header_encoded + "." + payload_encoded
      let input_uints = string_to_uints(signing_input)
      match @p256.ecdsa_sign_message(private_key_bytes, input_uints) {
        Err(e) => Err(CryptoError(e))
        Ok(sig) => {
          let sig_bytes : Array[UInt] = []
          for v in sig.r {
            sig_bytes.push(v)
          }
          for v in sig.s {
            sig_bytes.push(v)
          }
          let signature_encoded = base64url_encode(sig_bytes)
          Ok(signing_input + "." + signature_encoded)
        }
      }
    }
  }
}

///|
/// Verifies a JWT token against the given key.
/// - `JwtKey::HS256(secret)` → HMAC-SHA256
/// - `JwtKey::ES256(public_key)` → ECDSA P-256 + SHA-256
pub fn verify(token : String, key : JwtKey) -> Result[String, JWTError] {
  let parts = match split_token_indices(token) {
    Ok(p) => p
    Err(e) => return Err(e)
  }

  let header_json = base64url_decode_range_to_string(
    token,
    parts.header_start,
    parts.header_end,
  )

  // 根据密钥类型动态决定预期算法名
  let expected_alg = match key {
    HS256(_) => "HS256"
    ES256(_) => "ES256"
  }

  // 传入正确算法进行严格审计
  match validate_header_algorithm(header_json, expected_alg) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }

  // 根据 key 变体进行多态分发
  match key {
    HS256(secret) => {
      let signing_input = token[:parts.payload_end].to_owned()
      let expected_signature = @hmac.hmac_sha256_string(signing_input, secret)
      let actual_signature = base64url_decode_range(
        token,
        parts.signature_start,
        parts.signature_end,
      )

      if !constant_time_eq(fixed_to_array(expected_signature), actual_signature) {
        return Err(InvalidSignature)
      }

      let payload_json = base64url_decode_range_to_string(
        token,
        parts.payload_start,
        parts.payload_end,
      )
      Ok(payload_json)
    }
    ES256(public_key) => {
      let signing_input = token[:parts.payload_end].to_owned()
      let input_uints = string_to_uints(signing_input)

      let sig_raw = base64url_decode_range(
        token,
        parts.signature_start,
        parts.signature_end,
      )
      if sig_raw.length() != 64 {
        return Err(InvalidSignature)
      }

      let r : Array[UInt] = []
      let s : Array[UInt] = []
      for i in 0..<32 {
        r.push(sig_raw[i])
      }
      for i in 32..<64 {
        s.push(sig_raw[i])
      }
      let sig = @p256.ECDSASignature::{ r, s }

      match @p256.ecdsa_verify_message(public_key, input_uints, sig) {
        Err(e) => Err(CryptoError(e))
        Ok(valid) =>
          if valid {
            let payload_json = base64url_decode_range_to_string(
              token,
              parts.payload_start,
              parts.payload_end,
            )
            Ok(payload_json)
          } else {
            Err(InvalidSignature)
          }
      }
    }
  }
}

///|
/// Decodes a JWT token without verifying the signature.
pub fn decode(token : String) -> Result[String, JWTError] {
  let parts = match split_token_indices(token) {
    Ok(p) => p
    Err(e) => return Err(e)
  }
  let payload_json = base64url_decode_range_to_string(
    token,
    parts.payload_start,
    parts.payload_end,
  )
  Ok(payload_json)
}

///|
/// Decodes the header of a JWT token without verification.
pub fn decode_header(token : String) -> Result[String, JWTError] {
  let parts = match split_token_indices(token) {
    Ok(p) => p
    Err(e) => return Err(e)
  }
  let header_json = base64url_decode_range_to_string(
    token,
    parts.header_start,
    parts.header_end,
  )
  Ok(header_json)
}

///|
/// Validates standard JWT claims against the current time and expected metadata.
pub fn validate_claims(
  payload : JWTPayload,
  current_time : Int64,
  expected_iss : String?,
  expected_aud : String?,
) -> Result[Unit, JWTError] {
  // Expiration Time
  match payload.exp {
    Some(exp_time) =>
      if current_time >= exp_time {
        return Err(TokenExpired(current_time, exp_time))
      }
    None => ()
  }

  // Not Before
  match payload.nbf {
    Some(nbf_time) =>
      if current_time < nbf_time {
        return Err(TokenNotYetValid(current_time, nbf_time))
      }
    None => ()
  }

  // Issuer
  match (payload.iss, expected_iss) {
    (Some(actual), Some(expected)) =>
      if actual != expected {
        return Err(InvalidIssuer(actual))
      }
    _ => ()
  }

  // Audience
  match (payload.aud, expected_aud) {
    (Some(actual), Some(expected)) =>
      if actual != expected {
        return Err(InvalidAudience(actual))
      }
    _ => ()
  }

  Ok(())
}
