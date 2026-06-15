pub struct GatewayClaims {
  sub : String        
  exp : Int64         
  nbf : Int64         
  iss : String        
  role : String       
}

pub fn parse_gateway_claims(json_str : String) -> Result[GatewayClaims, String] {

  let json_obj = try @json.parse(json_str) catch {
    _ => return Err("Gateway Error: Failed to parse payload JSON")
  }

  let obj = match json_obj {
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
    Some(Number(n, ..)) => n.to_int64()
    _ => 0L  // 0 means "not set" — no nbf restriction
  }
  let iss = match obj.get("iss") {
    Some(String(s)) => s
    _ => "" 
  }
  let role = match obj.get("role") {
    Some(String(s)) => s
    _ => "guest" 
  }

  Ok({ sub, exp, nbf, iss, role })
}