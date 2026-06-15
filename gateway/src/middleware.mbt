
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

  match @mb_jwt.verify(ctx.token, secret) {
    Err(crypto_err) => {
      ctx.is_allowed = false
      ctx.error_message = "Crypto Blocked: " + crypto_err
    }
    Ok(payload_json) => {

      match parse_gateway_claims(payload_json) {
        Err(parse_err) => {
          ctx.is_allowed = false
          ctx.error_message = parse_err
        }
        Ok(claims) => {

          if current_time >= claims.exp {
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