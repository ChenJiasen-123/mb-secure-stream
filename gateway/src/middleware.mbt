///|
pub struct StreamContext {
  token : String
  mut is_allowed : Bool
  mut error_message : String
  mut user_role : String
}

///|
/// Creates a new stream security context for a given token.
pub fn new_stream_context(token : String) -> StreamContext {
  { token, is_allowed: false, error_message: "", user_role: "" }
}

///|
/// Executes the security filter on the given stream context.
/// Validates the JWT token against the provided key and current time,
/// and populates the context's `is_allowed`, `user_role`, and `error_message` fields.
pub fn execute_security_filter(
  ctx : StreamContext,
  key : @mb_jwt.JwtKey,
  current_time : Int64,
) -> Unit {
  let payload_json = match @mb_jwt.verify(ctx.token, key) {
    Err(e) => {
      ctx.is_allowed = false
      ctx.error_message = match e {
        @mb_jwt.InvalidSignature => "Crypto Blocked: Invalid signature"
        @mb_jwt.InvalidFormat => "Crypto Blocked: Malformed token format"
        @mb_jwt.AlgorithmMismatch(_) => "Crypto Blocked: Algorithm mismatch"
        @mb_jwt.CryptoError(msg) => "Crypto Blocked: \{msg}"
        _ => "Crypto Blocked: Verification failed"
      }
      return
    }
    Ok(json) => json
  }

  let claims = match parse_gateway_claims(payload_json) {
    Err(err) => {
      ctx.is_allowed = false
      ctx.error_message = err
      return
    }
    Ok(c) => c
  }

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
        @mb_jwt.TokenNotYetValid(_, _) =>
          "Gateway Blocked: Token is not yet valid (nbf)"
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
