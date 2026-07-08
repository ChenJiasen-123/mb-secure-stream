/// Gateway-specific claims extending standard JWT with a `role` field.
pub struct GatewayClaims {
  sub : String
  exp : Int64
  nbf : Option[Int64]
  iss : Option[String]
  role : Option[String]
}

/// Manual JSON deserialization for GatewayClaims.
pub fn parse_gateway_claims(json_str : String) -> Result[GatewayClaims, String] {
  let parsed = try @json.parse(json_str) catch {
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
    Some(Number(n, ..)) => n.to_int64()
    _ => return Err("Gateway Error: Missing or invalid 'exp' claim")
  }
  let nbf = match obj.get("nbf") {
    Some(Number(n, ..)) => Some(n.to_int64())
    _ => None
  }
  let iss = match obj.get("iss") {
    Some(String(s)) => Some(s)
    _ => None
  }
  let role = match obj.get("role") {
    Some(String(s)) => Some(s)
    _ => None
  }

  Ok({ sub, exp, nbf, iss, role })
}