fn fixed_to_array(fa : FixedArray[UInt]) -> Array[UInt] {
  let arr : Array[UInt] = Array::make(fa.length(), 0U)
  for i in 0..<fa.length() {
    arr[i] = fa[i]
  }
  arr
}

fn bytes_to_uints(bytes : Bytes) -> Array[UInt] {
  let arr : Array[UInt] = []
  for i in 0..<bytes.length() {
    arr.push(bytes[i].to_int().reinterpret_as_uint())
  }
  arr
}

fn uints_to_bytes(arr : Array[UInt]) -> Bytes {
  let buf : Array[Byte] = []
  for value in arr {
    buf.push((value & 0xFFU).to_byte())
  }
  Bytes::from_array(buf)
}

// --- SHA-256 variants (hash length = 32) ---

///| HKDF-Extract using HMAC-SHA256 (RFC 5869 Section 2.2).
/// If salt is empty, a 32-byte zero salt is used.
pub fn hkdf_extract_sha256(salt : Array[UInt], ikm : Array[UInt]) -> Array[UInt] {
  let actual_salt = if salt.length() == 0 {
    Array::make(32, 0U)
  } else {
    salt
  }
  let prk = @hmac.hmac_sha256(ikm, actual_salt)
  fixed_to_array(prk)
}

///| HKDF-Expand using HMAC-SHA256 (RFC 5869 Section 2.3).
/// Length must be <= 255 * 32 = 8160.
pub fn hkdf_expand_sha256(
  prk : Array[UInt],
  info : Array[UInt],
  length : Int
) -> Result[Array[UInt], String] {
  let hash_len = 32
  if length <= 0 {
    return Err("HKDF-Expand: length must be > 0")
  }
  if length > 255 * hash_len {
    return Err("HKDF-Expand: length exceeds maximum (8160)")
  }
  let n = (length + hash_len - 1) / hash_len
  let okm : Array[UInt] = []
  let mut prev : Array[UInt] = []
  for i in 1..=n {
    let input : Array[UInt] = []
    for j in 0..<prev.length() {
      input.push(prev[j])
    }
    for j in 0..<info.length() {
      input.push(info[j])
    }
    input.push(i.reinterpret_as_uint() & 0xFFU)
    let block = @hmac.hmac_sha256(input, prk)
    prev = fixed_to_array(block)
    for j in 0..<prev.length() {
      okm.push(prev[j])
    }
  }
  let result : Array[UInt] = []
  for i in 0..<length {
    result.push(okm[i])
  }
  Ok(result)
}

///| Combined HKDF using HMAC-SHA256 (RFC 5869).
pub fn hkdf_sha256(
  salt : Array[UInt],
  ikm : Array[UInt],
  info : Array[UInt],
  length : Int
) -> Result[Array[UInt], String] {
  let prk = hkdf_extract_sha256(salt, ikm)
  hkdf_expand_sha256(prk, info, length)
}

// --- SHA-512 variants (hash length = 64) ---

///| HKDF-Extract using HMAC-SHA512 (RFC 5869 Section 2.2).
/// If salt is empty, a 64-byte zero salt is used.
pub fn hkdf_extract_sha512(salt : Array[UInt], ikm : Array[UInt]) -> Array[UInt] {
  let actual_salt = if salt.length() == 0 {
    Array::make(64, 0U)
  } else {
    salt
  }
  let prk = @hmac.hmac_sha512(ikm, actual_salt)
  fixed_to_array(prk)
}

///| HKDF-Expand using HMAC-SHA512 (RFC 5869 Section 2.3).
/// Length must be <= 255 * 64 = 16320.
pub fn hkdf_expand_sha512(
  prk : Array[UInt],
  info : Array[UInt],
  length : Int
) -> Result[Array[UInt], String] {
  let hash_len = 64
  if length <= 0 {
    return Err("HKDF-Expand: length must be > 0")
  }
  if length > 255 * hash_len {
    return Err("HKDF-Expand: length exceeds maximum (16320)")
  }
  let n = (length + hash_len - 1) / hash_len
  let okm : Array[UInt] = []
  let mut prev : Array[UInt] = []
  for i in 1..=n {
    let input : Array[UInt] = []
    for j in 0..<prev.length() {
      input.push(prev[j])
    }
    for j in 0..<info.length() {
      input.push(info[j])
    }
    input.push(i.reinterpret_as_uint() & 0xFFU)
    let block = @hmac.hmac_sha512(input, prk)
    prev = fixed_to_array(block)
    for j in 0..<prev.length() {
      okm.push(prev[j])
    }
  }
  let result : Array[UInt] = []
  for i in 0..<length {
    result.push(okm[i])
  }
  Ok(result)
}

///| Combined HKDF using HMAC-SHA512 (RFC 5869).
pub fn hkdf_sha512(
  salt : Array[UInt],
  ikm : Array[UInt],
  info : Array[UInt],
  length : Int
) -> Result[Array[UInt], String] {
  let prk = hkdf_extract_sha512(salt, ikm)
  hkdf_expand_sha512(prk, info, length)
}

// --- Bytes convenience wrappers ---

///| HKDF-Extract using HMAC-SHA256 with Bytes inputs.
pub fn hkdf_extract_sha256_bytes(salt : Bytes, ikm : Bytes) -> Bytes {
  let result = hkdf_extract_sha256(bytes_to_uints(salt), bytes_to_uints(ikm))
  uints_to_bytes(result)
}

///| HKDF-Expand using HMAC-SHA256 with Bytes inputs.
pub fn hkdf_expand_sha256_bytes(
  prk : Bytes,
  info : Bytes,
  length : Int
) -> Result[Bytes, String] {
  match hkdf_expand_sha256(bytes_to_uints(prk), bytes_to_uints(info), length) {
    Ok(result) => Ok(uints_to_bytes(result))
    Err(e) => Err(e)
  }
}

///| Combined HKDF using HMAC-SHA256 with Bytes inputs.
pub fn hkdf_sha256_bytes(
  salt : Bytes,
  ikm : Bytes,
  info : Bytes,
  length : Int
) -> Result[Bytes, String] {
  match hkdf_sha256(
    bytes_to_uints(salt),
    bytes_to_uints(ikm),
    bytes_to_uints(info),
    length,
  ) {
    Ok(result) => Ok(uints_to_bytes(result))
    Err(e) => Err(e)
  }
}

///| HKDF-Extract using HMAC-SHA512 with Bytes inputs.
pub fn hkdf_extract_sha512_bytes(salt : Bytes, ikm : Bytes) -> Bytes {
  let result = hkdf_extract_sha512(bytes_to_uints(salt), bytes_to_uints(ikm))
  uints_to_bytes(result)
}

///| HKDF-Expand using HMAC-SHA512 with Bytes inputs.
pub fn hkdf_expand_sha512_bytes(
  prk : Bytes,
  info : Bytes,
  length : Int
) -> Result[Bytes, String] {
  match hkdf_expand_sha512(bytes_to_uints(prk), bytes_to_uints(info), length) {
    Ok(result) => Ok(uints_to_bytes(result))
    Err(e) => Err(e)
  }
}

///| Combined HKDF using HMAC-SHA512 with Bytes inputs.
pub fn hkdf_sha512_bytes(
  salt : Bytes,
  ikm : Bytes,
  info : Bytes,
  length : Int
) -> Result[Bytes, String] {
  match hkdf_sha512(
    bytes_to_uints(salt),
    bytes_to_uints(ikm),
    bytes_to_uints(info),
    length,
  ) {
    Ok(result) => Ok(uints_to_bytes(result))
    Err(e) => Err(e)
  }
}
