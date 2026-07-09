test "rate_limiter_basic" {
  let rl = new_rate_limiter(10L, 1L)
  // Consume all tokens at time 0 (no refill yet)
  let mut allowed = 0L
  let mut i = 0L
  while i < 12L {
    if rl.try_consume(0L) {
      allowed = allowed + 1L
    }
    i = i + 1L
  }
  assert_eq(allowed, 10L)  // 10 allowed (burst), 2 blocked
}

test "rate_limiter_refill" {
  let rl = new_rate_limiter(10L, 5L)
  // Consume 10 tokens at time 0
  let mut i = 0L
  while i < 10L {
    let _ = rl.try_consume(0L)
    i = i + 1L
  }
  // Try at time 2: should have refilled 2*5=10 tokens
  assert_true(rl.try_consume(2L))
}

test "replay_protector_basic" {
  let rp = new_replay_protector(60L)
  assert_true(rp.check_nonce("nonce-1", 1000L))
  assert_false(rp.check_nonce("nonce-1", 1001L))  // replay
}

test "replay_protector_expiry" {
  let rp = new_replay_protector(60L)
  assert_true(rp.check_nonce("nonce-1", 1000L))
  rp.evict_expired(2000L)
  assert_true(rp.check_nonce("nonce-1", 2000L))  // expired, fresh again
}

test "stream_session_basic" {
  let sess = new_stream_session("sess-1", "user-1", "admin", 0L)
  assert_true(sess.is_active)
  assert_false(sess.is_expired(100L, 50L))
  assert_true(sess.is_expired(100L, 200L))
}

test "stream_session_record" {
  let sess = new_stream_session("sess-1", "user-1", "admin", 0L)
  sess.record_packet(100L, 10L)
  sess.record_packet(200L, 20L)
  assert_eq(sess.packet_count, 2L)
  assert_eq(sess.byte_count, 300L)
}

test "fair_queue_enqueue_dequeue" {
  let fq = new_fair_queue()
  fq.enqueue("sess-1", Normal, 100L, 0L)
  fq.enqueue("sess-2", Critical, 50L, 1L)
  fq.enqueue("sess-3", Low, 200L, 2L)

  let first = fq.dequeue()
  assert_true(match first { Some(entry) => entry.session_id == "sess-2"; None => false })  // Critical first
  let second = fq.dequeue()
  assert_true(match second { Some(entry) => entry.session_id == "sess-1"; None => false })  // Normal next
}

test "fair_queue_empty" {
  let fq = new_fair_queue()
  assert_true(fq.dequeue() is None)
}

test "exponential_backoff" {
  let bo = new_backoff(100L, 5000L)
  let _ = bo.next_delay()  // initial 100
  let _ = bo.next_delay()  // 200
  let _ = bo.next_delay()  // 400
  bo.reset()
  let d1 = bo.next_delay()
  assert_eq(d1, 100L)  // reset
}

test "backoff_max_cap" {
  let bo = new_backoff(1000L, 2500L)
  let _ = bo.next_delay()  // 1000
  let _ = bo.next_delay()  // 2000
  let d3 = bo.next_delay()
  assert_eq(d3, 2500L)  // capped at 2500
}

test "circuit_breaker_closed" {
  let cb = new_circuit_breaker(3L, 1000L)
  assert_true(cb.allow_request(0L))
}

test "circuit_breaker_opens" {
  let cb = new_circuit_breaker(3L, 1000L)
  cb.record_failure(0L)
  cb.record_failure(1L)
  cb.record_failure(2L)
  assert_false(cb.allow_request(3L))  // circuit open
}

test "circuit_breaker_half_open" {
  let cb = new_circuit_breaker(3L, 1000L)
  cb.record_failure(0L)
  cb.record_failure(1L)
  cb.record_failure(2L)
  // After recovery timeout (1000ms), should allow probe
  assert_true(cb.allow_request(2000L))
}

test "circuit_breaker_recovery" {
  let cb = new_circuit_breaker(3L, 1000L)
  cb.record_failure(0L)
  // Record success resets
  cb.record_success()
  assert_true(cb.allow_request(1L))
}

test "bandwidth_shaper_basic" {
  let bw = new_bandwidth_shaper(100L, 200L)  // 100 bps, burst 200
  assert_true(bw.try_consume(50L, 0L))
  assert_true(bw.try_consume(50L, 0L))
  assert_true(bw.try_consume(50L, 0L))
  assert_true(bw.try_consume(50L, 0L))  // 200 total (burst)
  assert_false(bw.try_consume(50L, 0L))  // exceeded
}

test "bandwidth_shaper_refill" {
  let bw = new_bandwidth_shaper(100L, 200L)
  let _ = bw.try_consume(200L, 0L)  // use all burst
  assert_false(bw.try_consume(1L, 0L))  // empty
  // At time 1, refilled 100 bytes
  assert_true(bw.try_consume(50L, 1L))
}

test "connection_pool_basic" {
  let pool = new_connection_pool(5L)
  assert_true(pool.acquire("localhost", 8080L, 0L))
  assert_true(pool.acquire("localhost", 8080L, 1L))
  assert_eq(pool.total_active, 2L)
}

test "connection_pool_release" {
  let pool = new_connection_pool(5L)
  let _ = pool.acquire("localhost", 8080L, 0L)
  pool.release("localhost", 8080L)
  assert_eq(pool.total_active, 0L)
}

test "stream_metrics_basic" {
  let sm = new_stream_metrics(100)
  sm.record_request(100L, 200L, 50L)
  sm.record_request(200L, 400L, 150L)
  assert_eq(sm.total_requests, 2L)
  assert_eq(sm.total_bytes_in, 300L)
  assert_eq(sm.total_bytes_out, 600L)
}

test "stream_metrics_errors" {
  let sm = new_stream_metrics(100)
  sm.record_error()
  sm.record_error()
  sm.record_rate_limited()
  sm.record_auth_failure()
  assert_eq(sm.total_errors, 2L)
  assert_eq(sm.total_rate_limited, 1L)
  assert_eq(sm.total_auth_failures, 1L)
}

test "stream_metrics_average" {
  let sm = new_stream_metrics(100)
  sm.record_request(100L, 200L, 50L)
  sm.record_request(200L, 400L, 150L)
  assert_eq(sm.avg_duration_ms(), 100L)
}

test "stream_metrics_peak" {
  let sm = new_stream_metrics(100)
  sm.update_peak(5L)
  sm.update_peak(10L)
  sm.update_peak(3L)
  assert_eq(sm.peak_concurrent, 10L)
}

test "security_filter_rejects_bad_token" {
  let ctx = new_stream_context("bad.token.here")
  let key = @mb_jwt.JwtKey::HS256("secret")
  execute_security_filter(ctx, key, 1000L)
  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message != "")
}

test "security_filter_rejects_malformed" {
  let ctx = new_stream_context("not-a-jwt")
  let key = @mb_jwt.JwtKey::HS256("secret")
  execute_security_filter(ctx, key, 1000L)
  assert_false(ctx.is_allowed)
}

test "gateway_claims_parse_valid" {
  let json = "{\"sub\":\"user1\",\"exp\":2000000000}"
  let result = parse_gateway_claims(json)
  assert_true(match result { Ok(claims) => claims.sub == "user1"; _ => false })
}

test "gateway_claims_parse_invalid" {
  let result = parse_gateway_claims("invalid json")
  assert_true(match result { Err(_) => true; _ => false })
}

test "gateway_claims_parse_missing_sub" {
  let result = parse_gateway_claims("{\"exp\":2000000000}")
  assert_true(match result { Err(msg) => msg.contains("sub"); _ => false })
}