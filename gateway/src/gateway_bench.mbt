// Gateway Performance Benchmarks
// Run with: moon bench --target wasm-gc

///|
test (b : @bench.T) {
  let rl = new_rate_limiter(1000L, 100L)
  b.bench(name="rate_limiter_try_consume", fn() { b.keep(rl.try_consume(0L)) })
}

///|
test (b : @bench.T) {
  let rp = new_replay_protector(60L)
  b.bench(name="replay_protector_check_nonce", fn() {
    b.keep(rp.check_nonce("test-nonce", 1000L))
  })
}

///|
test (b : @bench.T) {
  let fq = new_fair_queue()
  fq.enqueue("sess-1", Normal, 100L, 0L)
  fq.enqueue("sess-2", Critical, 50L, 1L)
  fq.enqueue("sess-3", Low, 200L, 2L)
  b.bench(name="fair_queue_dequeue", fn() { b.keep(fq.dequeue()) })
}

///|
test (b : @bench.T) {
  let bo = new_backoff(100L, 5000L)
  b.bench(name="backoff_next_delay", fn() { b.keep(bo.next_delay()) })
}

///|
test (b : @bench.T) {
  let cb = new_circuit_breaker(3L, 1000L)
  b.bench(name="circuit_breaker_allow_request", fn() {
    b.keep(cb.allow_request(0L))
  })
}

///|
test (b : @bench.T) {
  let bw = new_bandwidth_shaper(100L, 200L)
  b.bench(name="bandwidth_shaper_try_consume", fn() {
    b.keep(bw.try_consume(50L, 0L))
  })
}

///|
test (b : @bench.T) {
  let pool = new_connection_pool(5L)
  b.bench(name="connection_pool_acquire", fn() {
    b.keep(pool.acquire("localhost", 8080L, 0L))
  })
}

///|
test (b : @bench.T) {
  let sm = new_stream_metrics(100)
  b.bench(name="stream_metrics_record_request", fn() {
    b.keep(sm.record_request(100L, 200L, 50L))
  })
}

///|
test (b : @bench.T) {
  let ctx = new_stream_context(
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJhZG1pbiIsImV4cCI6MjAwMDAwMDAwMH0.signature",
  )
  let key = @mb_jwt.JwtKey::HS256("secret")
  b.bench(name="security_filter_execute", fn() {
    b.keep(execute_security_filter(ctx, key, 1000000L))
  })
}
