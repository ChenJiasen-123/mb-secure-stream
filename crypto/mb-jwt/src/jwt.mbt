// JWT (JSON Web Tokens) implementation with HS256 and ES256 signing
// RFC 7519: https://tools.ietf.org/html/rfc7519
// RFC 7518 Section 3.4: ES256 (ECDSA P-256 + SHA-256)
//
// SECURITY FEATURES:
// - Rejects "alg:none" to prevent signature bypass attacks (CVE-2016-5431)
// - Header algorithm validation enforces algorithm consistency
// - Constant-time signature comparison prevents timing attacks
// - Both verify() and verify_es256() perform header validation

let jwt_header_hs256 : String = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"

let jwt_header_es256 : String = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"

fn fixed_to_array(fixed: FixedArray[UInt]) -> Array[UInt] {
  let arr : Array[UInt] = []
  for i in 0..<fixed.length() {
    arr.push(fixed[i])
  }
  arr
}

/// Constant-time comparison to prevent timing attacks.
/// Even when lengths differ, it compares up to the minimum length
/// to avoid leaking length information via early return.
fn constant_time_eq(a: Array[UInt], b: Array[UInt]) -> Bool {
  let min_len = if a.length() < b.length() { a.length() } else { b.length() }
  let mut diff : UInt = 0U
  for i in 0..<min_len {
    diff = diff | (a[i] ^ b[i])
  }
  // Also accumulate length difference to make it constant-time
  diff = diff | (a.length().reinterpret_as_uint() ^ b.length().reinterpret_as_uint())
  diff == 0U
}

fn string_to_bytes_filtered_jwt(s: String) -> Array[Int] {
  let raw = @utf8.encode(s)
  let result : Array[Int] = []
  for i in 0..<raw.length() {
    result.push(raw[i].to_int())
  }
  result
}

/// Token part positions in the original token string.
/// Uses indices to avoid creating intermediate substring allocations.
priv struct TokenParts {
  header_start : Int
  header_end : Int   // exclusive, position of first '.'
  payload_start : Int
  payload_end : Int  // exclusive, position of second '.'
  signature_start : Int
  signature_end : Int // exclusive, end of string
}

/// Zero-copy token splitter: finds the two '.' positions
/// and returns index ranges without allocating substrings.
fn split_token_indices(token: String) -> Result[TokenParts, String] {
  let chars = token.to_array()
  let len = chars.length()
  let mut first_dot = -1
  let mut second_dot = -1

  for i in 0..<len {
    if chars[i] == '.' {
      if first_dot < 0 {
        first_dot = i
      } else {
        second_dot = i
        break
      }
    }
  }

  if first_dot < 0 || second_dot < 0 {
    return Err("Invalid JWT format: expected 3 parts separated by dots")
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

/// Validates the header to reject `alg: none` and other insecure algorithms.
fn validate_header_algorithm(header_json: String, expected_alg: String) -> Result[Unit, String] {
  if header_json.contains("\"alg\":\"none\"") || header_json.contains("\"alg\":\"NONE\"") ||
     header_json.contains("\"alg\": \"none\"") || header_json.contains("\"alg\": \"NONE\"") {
    return Err("Security breach: alg:none is not permitted")
  }
  
  let expected_pattern_1 = "\"alg\":\"\{expected_alg}\""
  let expected_pattern_2 = "\"alg\": \"\{expected_alg}\""
  if !header_json.contains(expected_pattern_1) && !header_json.contains(expected_pattern_2) {
    return Err("Algorithm mismatch: expected \{expected_alg} but found different algorithm")
  }
  
  Ok(())
}

/// Signs a JSON payload and returns a JWT token string.
pub fn sign(payload: String, secret: String) -> String {
  let header_encoded = base64url_encode_string(jwt_header_hs256)
  let payload_encoded = base64url_encode_string(payload)

  let signing_input = header_encoded + "." + payload_encoded

  let signature = @hmac.hmac_sha256_string(signing_input, secret)
  let signature_encoded = base64url_encode(fixed_to_array(signature))

  signing_input + "." + signature_encoded
}

pub fn verify(token: String, secret: String) -> Result[String, String] {
  let parts = match split_token_indices(token) {
    Ok(p) => p
    Err(e) => return Err(e)
  }

  let header_json = base64url_decode_range_to_string(token, parts.header_start, parts.header_end)

  match validate_header_algorithm(header_json, "HS256") {
    Ok(_) => ()
    Err(e) => return Err(e)
  }

  let signing_input = token[:parts.payload_end].to_owned()
  let expected_signature = @hmac.hmac_sha256_string(signing_input, secret)
  let actual_signature = base64url_decode_range(token, parts.signature_start, parts.signature_end)

  if !(constant_time_eq(fixed_to_array(expected_signature), actual_signature)) {
    return Err("Invalid signature")
  }

  let payload_json = base64url_decode_range_to_string(token, parts.payload_start, parts.payload_end)
  Ok(payload_json)
}

/// Decodes a JWT token without verifying the signature.
pub fn decode(token: String) -> Result[String, String] {
  let parts = match split_token_indices(token) {
    Ok(p) => p
    Err(e) => return Err(e)
  }
  let payload_json = base64url_decode_range_to_string(token, parts.payload_start, parts.payload_end)
  Ok(payload_json)
}

/// Decodes the header of a JWT token without verification.
pub fn decode_header(token: String) -> Result[String, String] {
  let parts = match split_token_indices(token) {
    Ok(p) => p
    Err(e) => return Err(e)
  }
  let header_json = base64url_decode_range_to_string(token, parts.header_start, parts.header_end)
  Ok(header_json)
}

// --- ES256 (ECDSA P-256 + SHA-256) ---

/// Signs a JSON payload using ES256 (ECDSA P-256 + SHA-256).
pub fn sign_es256(payload : String, private_key : Array[UInt]) -> Result[String, String] {
  let header_encoded = base64url_encode_string(jwt_header_es256)
  let payload_encoded = base64url_encode_string(payload)
  let signing_input = header_encoded + "." + payload_encoded

  let input_bytes = string_to_bytes_filtered_jwt(signing_input)
  let input_uints : Array[UInt] = []
  for b in input_bytes {
    input_uints.push(b.reinterpret_as_uint())
  }

  match @p256.ecdsa_sign_message(private_key, input_uints) {
    Err(e) => Err(e)
    Ok(sig) => {
      let sig_bytes : Array[UInt] = []
      for v in sig.r { sig_bytes.push(v) }
      for v in sig.s { sig_bytes.push(v) }
      let signature_encoded = base64url_encode(sig_bytes)
      Ok(signing_input + "." + signature_encoded)
    }
  }
}

pub fn verify_es256(
  token : String,
  public_key : Array[UInt],
) -> Result[String, String] {
  let parts = match split_token_indices(token) {
    Ok(p) => p
    Err(e) => return Err(e)
  }

  let header_json = base64url_decode_range_to_string(token, parts.header_start, parts.header_end)

  match validate_header_algorithm(header_json, "ES256") {
    Ok(_) => ()
    Err(e) => return Err(e)
  }

  let signing_input = token[:parts.payload_end].to_owned()
  let input_bytes = string_to_bytes_filtered_jwt(signing_input)
  let input_uints : Array[UInt] = []
  for b in input_bytes {
    input_uints.push(b.reinterpret_as_uint())
  }

  let sig_raw = base64url_decode_range(token, parts.signature_start, parts.signature_end)
  if sig_raw.length() != 64 {
    return Err("Invalid ES256 signature length")
  }
  
  let r : Array[UInt] = []
  let s : Array[UInt] = []
  for i in 0..<32 { r.push(sig_raw[i]) }
  for i in 32..<64 { s.push(sig_raw[i]) }
  let sig = @p256.ECDSASignature::{ r, s }

  match @p256.ecdsa_verify_message(public_key, input_uints, sig) {
    Err(e) => Err(e)
    Ok(valid) =>
      if valid {
        let payload_json = base64url_decode_range_to_string(token, parts.payload_start, parts.payload_end)
        Ok(payload_json)
      } else {
        Err("Invalid signature")
      }
  }
}

///| Validates standard JWT claims against the current time and expected metadata.
pub fn validate_claims(
  payload : JWTPayload,
  current_time : Int64,
  expected_iss : Option[String],
  expected_aud : Option[String],
) -> Result[Unit, ValidationError] {
  // Expiration Time
  match payload.exp {
    Some(exp_time) =>
      if current_time >= exp_time {
        return Err(ValidationError::TokenExpired(current_time, exp_time))
      }
    None => ()
  }

  // Not Before
  match payload.nbf {
    Some(nbf_time) =>
      if current_time < nbf_time {
        return Err(ValidationError::TokenNotYetValid(current_time, nbf_time))
      }
    None => ()
  }

  // Issuer
  match (payload.iss, expected_iss) {
    (Some(actual), Some(expected)) =>
      if actual != expected {
        return Err(ValidationError::InvalidIssuer(actual))
      }
    _ => ()
  }

  // Audience
  match (payload.aud, expected_aud) {
    (Some(actual), Some(expected)) =>
      if actual != expected {
        return Err(ValidationError::InvalidAudience(actual))
      }
    _ => ()
  }

  Ok(())
}