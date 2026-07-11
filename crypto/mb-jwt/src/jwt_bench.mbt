// JWT Performance Benchmarks
// Run with: moon bench --target wasm-gc

// --- HS256 Benchmarks ---

///|
test (b : @bench.T) {
  let key = JwtKey::HS256("benchmark_secret_key_for_testing_performance")
  let payload = "{\"sub\":\"user123\",\"name\":\"John Doe\",\"role\":\"admin\",\"iat\":1516239022}"
  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => return
  }
  b.bench(name="jwt_hs256_verify", fn() { b.keep(verify(token, key)) })
}

///|
test (b : @bench.T) {
  let key = JwtKey::HS256("benchmark_secret_key_for_testing_performance")
  let payload = "{\"sub\":\"user123\",\"name\":\"John Doe\",\"role\":\"admin\",\"iat\":1516239022}"
  b.bench(name="jwt_hs256_sign", fn() { b.keep(sign(payload, key)) })
}

///|
test (b : @bench.T) {
  let key = JwtKey::HS256("benchmark_secret_key_for_testing_performance")
  let payload = "{\"sub\":\"user123\",\"name\":\"John Doe\",\"role\":\"admin\",\"iat\":1516239022}"
  let token = match sign(payload, key) {
    Ok(t) => t
    Err(_) => return
  }
  b.bench(name="jwt_decode", fn() { b.keep(decode(token)) })
}

// --- ES256 Benchmarks ---

///|
fn es256_bench_hex_to_uints(hex : String) -> Array[UInt] {
  let raw = @utf8.encode(hex)
  let chars : Array[Int] = []
  for i in 0..<raw.length() {
    let ch = raw[i].to_int()
    if (ch >= 48 && ch <= 57) ||
      (ch >= 65 && ch <= 70) ||
      (ch >= 97 && ch <= 102) {
      chars.push(ch)
    }
  }
  let result : Array[UInt] = []
  let mut i = 0
  while i + 1 < chars.length() {
    let hi = es256_parse_hex(chars[i])
    let lo = es256_parse_hex(chars[i + 1])
    result.push(((hi << 4) | lo).reinterpret_as_uint())
    i = i + 2
  }
  result
}

///|
fn es256_parse_hex(ch : Int) -> Int {
  if ch >= 48 && ch <= 57 {
    ch - 48
  } else if ch >= 97 && ch <= 102 {
    ch - 87
  } else if ch >= 65 && ch <= 70 {
    ch - 55
  } else {
    0
  }
}

///|
test (b : @bench.T) {
  let private_key = es256_bench_hex_to_uints(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let payload = "{\"sub\":\"user123\",\"name\":\"John Doe\",\"iat\":1516239022}"
  let token = match sign(payload, JwtKey::ES256(private_key)) {
    Ok(t) => t
    Err(_) => return
  }
  // Derive public key for verification
  let public_key = match @p256.derive_public_key(private_key) {
    Ok(pk) => pk
    Err(_) => return
  }
  let verify_key = JwtKey::ES256(public_key)
  b.bench(name="jwt_es256_sign", fn() {
    b.keep(sign(payload, JwtKey::ES256(private_key)))
  })
  b.bench(name="jwt_es256_verify", fn() { b.keep(verify(token, verify_key)) })
}

// --- Base64url Benchmarks ---

///|
test (b : @bench.T) {
  let data : Array[UInt] = [
    72U, 101U, 108U, 108U, 111U, 32U, 87U, 111U, 114U, 108U, 100U,
  ]
  b.bench(name="base64url_encode", fn() { b.keep(base64url_encode(data)) })
}

///|
test (b : @bench.T) {
  let encoded = "SGVsbG8gV29ybGQ"
  b.bench(name="base64url_decode", fn() { b.keep(base64url_decode(encoded)) })
}
