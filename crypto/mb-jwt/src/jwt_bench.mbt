// JWT Performance Benchmarks
// Run with: moon bench --target wasm-gc

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

///|
test (b : @bench.T) {
  let data : Array[UInt] = [72U, 101U, 108U, 108U, 111U, 32U, 87U, 111U, 114U, 108U, 100U]
  b.bench(name="base64url_encode", fn() { b.keep(base64url_encode(data)) })
}

///|
test (b : @bench.T) {
  let encoded = "SGVsbG8gV29ybGQ"
  b.bench(name="base64url_decode", fn() { b.keep(base64url_decode(encoded)) })
}