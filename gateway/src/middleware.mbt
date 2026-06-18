pub struct StreamContext {
  token : String
  mut is_allowed : Bool
  mut error_message : String
  mut user_role : String
}

pub fn new_stream_context(token : String) -> StreamContext {
  { token, is_allowed: false, error_message: "", user_role: "" }
}

/// Security filter that verifies a JWT and validates its claims.
///
/// Fixes
/// =====
///  1. Propagates `JWTError` detail (InvalidSignature, TokenExpired, etc.)
///     instead of swallowing all with `Err(_)` — enables IP-fencing on
///     tamper events and seamless token-refresh on expiration.
///  2. Delegates nbf/exp validation to the library's `@mb_jwt.validate_claims`,
///     eliminating hand-rolled clock checks.
///  3. Accepts `JwtKey` (not just HS256) so the filter works with ES256
///     (ECDSA P-256) out of the box when a public-key channel is deployed.
pub fn execute_security_filter(
  ctx : StreamContext,
  key : @mb_jwt.JwtKey,
  current_time : Int64,
) -> Unit {
  // ── Step 1: verify signature → get raw payload JSON ──
  let payload_json = match @mb_jwt.verify(ctx.token, key) {
    Err(e) => {
      ctx.is_allowed = false
      // verify() only ever returns crypto-level errors (Format, Signature, Algorithm, Crypto).
      // Business-rule errors (Expired, NotYetValid, Issuer, Audience) are thrown exclusively
      // by validate_claims() in Step 3, so they are not matched here.
      ctx.error_message = match e {
        @mb_jwt.InvalidSignature => "Crypto Blocked: Invalid signature"
        @mb_jwt.InvalidFormat => "Crypto Blocked: Malformed token format"
        @mb_jwt.AlgorithmMismatch(_) => "Crypto Blocked: Algorithm mismatch"
        @mb_jwt.CryptoError(msg) => "Crypto Blocked: \{msg}"
        // validate_claims() handles these; they are never returned by verify()
        _ => "Crypto Blocked: Verification failed"
      }
      return
    }
    Ok(json) => json
  }

  // ── Step 2: parse gateway claims ──
  let claims = match parse_gateway_claims(payload_json) {
    Err(err) => {
      ctx.is_allowed = false
      ctx.error_message = err
      return
    }
    Ok(c) => c
  }

  // ── Step 3: build JWTPayload and delegate to library validate_claims ──
  let jwt_payload = @mb_jwt.new_jwt_payload(
    claims.iss,
    Some(claims.sub),
    None,
    Some(claims.exp),
    claims.nbf,
    None,
    None,
  )

  match @mb_jwt.validate_claims(jwt_payload, current_time, None, None) {
    Err(e) => {
      ctx.is_allowed = false
      ctx.error_message = match e {
        @mb_jwt.TokenExpired(_, _) => "Gateway Blocked: Token has expired"
        @mb_jwt.TokenNotYetValid(_, _) => "Gateway Blocked: Token is not yet valid (nbf)"
        @mb_jwt.InvalidIssuer(_) => "Gateway Blocked: Invalid issuer"
        @mb_jwt.InvalidAudience(_) => "Gateway Blocked: Invalid audience"
        _ => "Gateway Blocked: Claims validation failed"
      }
    }
    Ok(_) => {
      ctx.is_allowed = true
      ctx.user_role = match claims.role {
        Some(r) => r
        None => "guest"
      }
    }
  }
}