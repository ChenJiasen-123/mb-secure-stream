// ECDH key exchange for P-256.
// Shared secret = x-coordinate of (private_key * peer_public_key).

/// Compute ECDH shared secret (32 bytes, x-coordinate of the shared point).
pub fn ecdh(
  private_key : Array[UInt],
  peer_public_key : Array[UInt],
) -> Result[Array[UInt], String] {
  if private_key.length() != 32 {
    return Err("Private key must be 32 bytes")
  }

  let d = sc_from_bytes(private_key)
  if !sc_is_valid(d) {
    return Err("Private key out of range")
  }

  let peer = match parse_public_key(peer_public_key) {
    Err(e) => return Err(e)
    Ok(p) => p
  }

  // shared_point = d * peer_public_key
  let shared = point_mul(d, peer)
  let shared_affine = point_to_affine(shared)
  if shared_affine.infinity {
    return Err("ECDH produced identity point")
  }

  // Return x-coordinate as 32 bytes (big-endian)
  Ok(fe_to_bytes(shared_affine.x))
}

/// Compute ECDH shared secret (Bytes API).
pub fn ecdh_bytes(
  private_key : Bytes,
  peer_public_key : Bytes,
) -> Result[Bytes, String] {
  match ecdh(bytes_to_uint_array(private_key), bytes_to_uint_array(peer_public_key)) {
    Err(e) => Err(e)
    Ok(shared) => Ok(uints_to_bytes(shared))
  }
}

/// Derive public key from private key (32 bytes -> 65 bytes uncompressed).
pub fn derive_public_key(private_key : Array[UInt]) -> Result[Array[UInt], String] {
  if private_key.length() != 32 {
    return Err("Private key must be 32 bytes")
  }
  let d = sc_from_bytes(private_key)
  if !sc_is_valid(d) {
    return Err("Private key out of range")
  }
  let q = point_mul(d, point_generator())
  let q_affine = point_to_affine(q)
  if q_affine.infinity {
    return Err("Invalid private key")
  }
  let pub_key : Array[UInt] = []
  pub_key.push(0x04U)
  for v in fe_to_bytes(q_affine.x) {
    pub_key.push(v)
  }
  for v in fe_to_bytes(q_affine.y) {
    pub_key.push(v)
  }
  Ok(pub_key)
}
