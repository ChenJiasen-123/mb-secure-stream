
pub struct GatewayClaims {
  sub : String        
  exp : Int64         
  iss : String        
  role : String       
}


pub fn parse_gateway_claims(json_str : String) -> Result[GatewayClaims, String] {

  match @json.parse(json_str) {
    Err(_) => Err("Gateway Error: Failed to parse payload JSON")
    Ok(json_obj) => {

      let sub = match json_obj.get("sub") {
        Some(String(s)) => s
        _ => return Err("Gateway Error: Missing or invalid 'sub' claim")
      }
      let exp = match json_obj.get("exp") {
        Some(Number(n)) => n.to_int64()
        _ => return Err("Gateway Error: Missing or invalid 'exp' claim")
      }
      let iss = match json_obj.get("iss") {
        Some(String(s)) => s
        _ => "" 
      }
      let role = match json_obj.get("role") {
        Some(String(s)) => s
        _ => "guest" 
      }
      
      Ok({ sub, exp, iss, role })
    }
  }
}