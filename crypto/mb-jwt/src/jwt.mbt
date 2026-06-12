// JWT (JSON Web Tokens) implementation with HS256 and ES256 signing
// RFC 7519: https://tools.ietf.org/html/rfc7519
// RFC 7518 Section 3.4: ES256 (ECDSA P-256 + SHA-256)

let jwt_header_hs256 : String = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"

let jwt_header_es256 : String = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"

fn fixed_to_array(fixed: FixedArray[UInt]) -> Array[UInt] {
  let arr : Array[UInt] = []
  for i in 0..<fixed.length() {
    arr.push(fixed[i])
  }
  arr
}

fn constant_time_eq(a: Array[UInt], b: Array[UInt]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff : UInt = 0U
  for i in 0..<a.length() {
    diff = diff | (a[i] ^ b[i])
  }
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

fn split_token(token: String) -> Result[Array[String], String] {
  let chars = string_to_bytes_filtered_jwt(token)
  let parts : Array[String] = []
  let mut current = ""

  for c in chars {
    if c == 46 {  // '.'
      parts.push(current)
      current = ""
    } else {
      current = current + c.unsafe_to_char().to_string()
    }
  }
  parts.push(current)

  if parts.length() != 3 {
    return Err("Invalid JWT format: expected 3 parts separated by dots")
  }
  Ok(parts)
}

/// Signs a JSON payload and returns a JWT token string.
/// The payload should be a valid JSON string.
///
/// Example:
/// ```
/// let token = sign("{\"sub\":\"1234567890\",\"name\":\"John\"}", "secret")
/// ```
pub fn sign(payload: String, secret: String) -> String {
  let header_encoded = base64url_encode_string(jwt_header_hs256)
  let payload_encoded = base64url_encode_string(payload)

  let signing_input = header_encoded + "." + payload_encoded

  let signature = @hmac.hmac_sha256_string(signing_input, secret)
  let signature_encoded = base64url_encode(fixed_to_array(signature))

  signing_input + "." + signature_encoded
}

/// Verifies a JWT token and returns the decoded payload if valid.
/// Returns an error if the signature is invalid or the token is malformed.
pub fn verify(token: String, secret: String) -> Result[String, String] {
  match split_token(token) {
    Err(e) => Err(e)
    Ok(parts) => {
      let header_encoded = parts[0]
      let payload_encoded = parts[1]
      let signature_encoded = parts[2]

      let signing_input = header_encoded + "." + payload_encoded
      let expected_signature = @hmac.hmac_sha256_string(signing_input, secret)
      let actual_signature = base64url_decode(signature_encoded)

      if !(constant_time_eq(fixed_to_array(expected_signature), actual_signature)) {
        return Err("Invalid signature")
      }

      Ok(base64url_decode_to_string(payload_encoded))
    }
  }
}

/// Decodes a JWT token without verifying the signature.
/// Use this only when you need to inspect the payload without verification.
/// WARNING: Never trust the contents of an unverified token.
pub fn decode(token: String) -> Result[String, String] {
  match split_token(token) {
    Err(e) => Err(e)
    Ok(parts) => {
      let payload_encoded = parts[1]
      Ok(base64url_decode_to_string(payload_encoded))
    }
  }
}

/// Decodes the header of a JWT token without verification.
pub fn decode_header(token: String) -> Result[String, String] {
  match split_token(token) {
    Err(e) => Err(e)
    Ok(parts) => {
      let header_encoded = parts[0]
      Ok(base64url_decode_to_string(header_encoded))
    }
  }
}

// --- ES256 (ECDSA P-256 + SHA-256) ---

/// Signs a JSON payload using ES256 (ECDSA P-256 + SHA-256).
/// private_key: 32-byte ECDSA private key as Array[UInt].
/// Returns a JWT token string.
pub fn sign_es256(payload : String, private_key : Array[UInt]) -> Result[String, String] {
  let header_encoded = base64url_encode_string(jwt_header_es256)
  let payload_encoded = base64url_encode_string(payload)
  let signing_input = header_encoded + "." + payload_encoded

  // Convert signing input to bytes for ECDSA
  let input_bytes = string_to_bytes_filtered_jwt(signing_input)
  let input_uints : Array[UInt] = []
  for b in input_bytes {
    input_uints.push(b.reinterpret_as_uint())
  }

  match @p256.ecdsa_sign_message(private_key, input_uints) {
    Err(e) => Err(e)
    Ok(sig) => {
      // JWS signature format for ES256: r (32 bytes) || s (32 bytes) = 64 bytes
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

/// Verifies an ES256 JWT token and returns the decoded payload if valid.
/// public_key: 65-byte uncompressed public key (0x04 || x || y) as Array[UInt].
pub fn verify_es256(
  token : String,
  public_key : Array[UInt],
) -> Result[String, String] {
  match split_token(token) {
    Err(e) => Err(e)
    Ok(parts) => {
      let header_encoded = parts[0]
      let payload_encoded = parts[1]
      let signature_encoded = parts[2]

      let signing_input = header_encoded + "." + payload_encoded
      let input_bytes = string_to_bytes_filtered_jwt(signing_input)
      let input_uints : Array[UInt] = []
      for b in input_bytes {
        input_uints.push(b.reinterpret_as_uint())
      }

      // Decode signature: 64 bytes = r (32) || s (32)
      let sig_raw = base64url_decode(signature_encoded)
      if sig_raw.length() != 64 {
        return Err("Invalid ES256 signature length")
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
        Err(e) => Err(e)
        Ok(valid) =>
          if valid {
            Ok(base64url_decode_to_string(payload_encoded))
          } else {
            Err("Invalid signature")
          }
      }
    }
  }
}
