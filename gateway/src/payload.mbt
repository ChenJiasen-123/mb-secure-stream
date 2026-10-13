///|
/// Gateway-specific claims extending standard JWT with a `role` field.
pub struct GatewayClaims {
  sub : String
  exp : Int64
  nbf : Int64?
  iss : String?
  aud : String?
  role : String?
}

///|
/// Manual JSON deserialization for GatewayClaims.
pub fn parse_gateway_claims(json_str : String) -> Result[GatewayClaims, String] {
  let parsed = @json.parse(json_str) catch {
    _ => return Err("Gateway Error: Failed to parse payload JSON")
  }
  let obj = match parsed {
    Object(m) => m
    _ => return Err("Gateway Error: Expected JSON object")
  }

  let sub = match obj.get("sub") {
    Some(String(s)) => s
    _ => return Err("Gateway Error: Missing or invalid 'sub' claim")
  }
  let exp = match obj.get("exp") {
    Some(Number(n, ..)) =>
      match gateway_numeric_date(n) {
        Ok(value) => value
        Err(_) => return Err("Gateway Error: Invalid exp NumericDate")
      }
    _ => return Err("Gateway Error: Missing or invalid 'exp' claim")
  }
  let nbf = match obj.get("nbf") {
    Some(Number(n, ..)) =>
      match gateway_numeric_date(n) {
        Ok(value) => Some(value)
        Err(_) => return Err("Gateway Error: Invalid nbf NumericDate")
      }
    None => None
    _ => return Err("Gateway Error: Invalid nbf claim type")
  }
  let iss = match obj.get("iss") {
    Some(String(s)) => Some(s)
    None => None
    _ => return Err("Gateway Error: Invalid iss claim type")
  }
  let aud = match obj.get("aud") {
    Some(String(s)) => Some(s)
    None => None
    _ => return Err("Gateway Error: aud must be a string; arrays unsupported")
  }
  let role = match obj.get("role") {
    Some(String(s)) => Some(s)
    None => None
    _ => return Err("Gateway Error: Invalid role claim type")
  }

  Ok({ sub, exp, nbf, iss, aud, role, })
}

///|
// This gateway accepts integral NumericDate values representable exactly by JSON Double.
fn gateway_numeric_date(value : Double) -> Result[Int64, String] {
  if value < -9007199254740991.0 || value > 9007199254740991.0 {
    return Err("NumericDate outside exact integer range")
  }
  let integer = value.to_int64()
  if integer.to_double() != value {
    return Err("Fractional NumericDate unsupported")
  }
  Ok(integer)
}
