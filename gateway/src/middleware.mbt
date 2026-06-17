pub struct StreamContext {
  token : String
  mut is_allowed : Bool
  mut error_message : String
  mut user_role : String
}

pub fn new_stream_context(token : String) -> StreamContext {
  { token, is_allowed: false, error_message: "", user_role: "" }
}

pub fn execute_security_filter(ctx : StreamContext, secret : String, current_time : Int64) -> Unit {
  let key = @mb_jwt.JwtKey::HS256(secret)

  match @mb_jwt.verify(ctx.token, key) {
    Err(_) => {
      ctx.is_allowed = false
      ctx.error_message = "Crypto Blocked: Invalid signature or malformed token"
    }
    Ok(payload_json) => {

      match parse_gateway_claims(payload_json) {
        Err(parse_err) => {
          ctx.is_allowed = false
          ctx.error_message = parse_err
        }
        Ok(claims) => {

          // nbf check: current_time must be >= nbf (token must be not-before this time)
          // nbf == 0L means "not set" — skip check
          if claims.nbf > 0L && current_time < claims.nbf {
            ctx.is_allowed = false
            ctx.error_message = "Gateway Blocked: Token is not yet valid (nbf)"
          } else if current_time >= claims.exp {
            ctx.is_allowed = false
            ctx.error_message = "Gateway Blocked: Token has expired"
          } else {
            ctx.is_allowed = true
            ctx.user_role = claims.role
          }
        }
      }
    }
  }
}