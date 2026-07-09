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

test "gateway_claims_parse_non_object_json" {
  let result = parse_gateway_claims("\"string\"")
  assert_true(match result { Err(msg) => msg.contains("object"); _ => false })
}

test "gateway_claims_parse_missing_exp" {
  let result = parse_gateway_claims("{\"sub\":\"user1\",\"iss\":\"issuer\"}")
  assert_true(match result { Err(msg) => msg.contains("exp"); _ => false })
}

test "gateway_claims_parse_all_optional_fields" {
  let json = "{\"sub\":\"user1\",\"exp\":2000000000,\"nbf\":1000000000,\"iss\":\"my-issuer\",\"role\":\"admin\"}"
  let result = parse_gateway_claims(json)
  assert_true(match result {
    Ok(claims) => claims.sub == "user1" && claims.exp == 2000000000L
    _ => false
  })
  assert_true(match result {
    Ok(claims) => match claims.nbf { Some(n) => n == 1000000000L; _ => false }
    _ => false
  })
  assert_true(match result {
    Ok(claims) => match claims.iss { Some(i) => i == "my-issuer"; _ => false }
    _ => false
  })
  assert_true(match result {
    Ok(claims) => match claims.role { Some(r) => r == "admin"; _ => false }
    _ => false
  })
}

test "gateway_claims_parse_optional_fields_none" {
  let json = "{\"sub\":\"user1\",\"exp\":2000000000}"
  let result = parse_gateway_claims(json)
  assert_true(match result {
    Ok(claims) => claims.sub == "user1"
    _ => false
  })
  assert_true(match result {
    Ok(claims) => match claims.nbf { None => true; _ => false }
    _ => false
  })
  assert_true(match result {
    Ok(claims) => match claims.iss { None => true; _ => false }
    _ => false
  })
  assert_true(match result {
    Ok(claims) => match claims.role { None => true; _ => false }
    _ => false
  })
}

test "security_filter_valid_token" {
  // Create a valid signed JWT and verify it passes
  let payload = "{\"sub\":\"user1\",\"role\":\"admin\",\"exp\":2000000000}"
  let key = @mb_jwt.JwtKey::HS256("secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(_) => { assert_true(false); return }
  }
  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000000L)
  assert_true(ctx.is_allowed)
  assert_eq(ctx.user_role, "admin")
}

test "security_filter_expired_token" {
  let payload = "{\"sub\":\"user1\",\"exp\":1000}"
  let key = @mb_jwt.JwtKey::HS256("secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(_) => { assert_true(false); return }
  }
  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 2000L)
  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message.contains("expired"))
}

test "security_filter_nbf_token" {
  let payload = "{\"sub\":\"user1\",\"nbf\":5000,\"exp\":10000}"
  let key = @mb_jwt.JwtKey::HS256("secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(_) => { assert_true(false); return }
  }
  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000L)  // before nbf
  assert_false(ctx.is_allowed)
  assert_true(ctx.error_message.contains("nbf"))
}

test "security_filter_guest_role" {
  let payload = "{\"sub\":\"guest-user\",\"exp\":2000000000}"
  let key = @mb_jwt.JwtKey::HS256("secret")
  let token = match @mb_jwt.sign(payload, key) {
    Ok(t) => t
    Err(_) => { assert_true(false); return }
  }
  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000000L)
  assert_true(ctx.is_allowed)
  assert_eq(ctx.user_role, "guest")
}

test "replay_protector_evict_no_expired" {
  let rp = new_replay_protector(60L)
  assert_true(rp.check_nonce("nonce-1", 1000L))
  // Evict at time far before expiry - should still have entry
  rp.evict_expired(500L)
  assert_false(rp.check_nonce("nonce-1", 1001L))  // still fresh
}

test "fair_queue_priority_order" {
  let fq = new_fair_queue()
  // Add in reverse priority order
  fq.enqueue("low-sess", Low, 100L, 0L)
  fq.enqueue("normal-sess", Normal, 100L, 1L)
  fq.enqueue("high-sess", High, 100L, 2L)
  fq.enqueue("critical-sess", Critical, 100L, 3L)

  // Dequeue should return highest priority first
  match fq.dequeue() {
    Some(entry) => assert_eq(entry.session_id, "critical-sess")
    None => assert_true(false)
  }
  match fq.dequeue() {
    Some(entry) => assert_eq(entry.session_id, "high-sess")
    None => assert_true(false)
  }
  match fq.dequeue() {
    Some(entry) => assert_eq(entry.session_id, "normal-sess")
    None => assert_true(false)
  }
  match fq.dequeue() {
    Some(entry) => assert_eq(entry.session_id, "low-sess")
    None => assert_true(false)
  }
}

test "backoff_exponential_growth" {
  let bo = new_backoff(100L, 10000L)
  assert_eq(bo.next_delay(), 100L)
  assert_eq(bo.next_delay(), 200L)
  assert_eq(bo.next_delay(), 400L)
  assert_eq(bo.next_delay(), 800L)
  assert_eq(bo.next_delay(), 1600L)
}

test "circuit_breaker_half_open_to_closed" {
  let cb = new_circuit_breaker(3L, 1000L)
  // Open the circuit
  cb.record_failure(0L)
  cb.record_failure(0L)
  cb.record_failure(0L)
  assert_false(cb.allow_request(500L))  // still open
  // After recovery timeout, enters half-open
  assert_true(cb.allow_request(2000L))
  // Record success should close the circuit
  cb.record_success()
  assert_true(cb.allow_request(3000L))
  assert_eq(cb.failure_count, 0L)
}

test "connection_pool_global_limit" {
  let pool = new_connection_pool(2L)  // only 2 global connections
  assert_true(pool.acquire("host1", 80L, 0L))
  assert_true(pool.acquire("host2", 80L, 1L))
  assert_false(pool.acquire("host3", 80L, 2L))  // exceeded global max
}

test "connection_pool_host_limit" {
  let pool = new_connection_pool(100L)
  // Acquire 12 connections to same host (max per host is 10)
  let mut acquired = 0L
  let mut i = 0L
  while i < 12L {
    if pool.acquire("same-host", 80L, i) {
      acquired = acquired + 1L
    }
    i = i + 1L
  }
  assert_eq(acquired, 10L)  // 10 allowed, 2 blocked by host limit
}

test "stream_metrics_rolling_window" {
  let sm = new_stream_metrics(3)  // only 3 samples
  sm.record_request(100L, 200L, 10L)
  sm.record_request(200L, 400L, 20L)
  sm.record_request(300L, 600L, 30L)
  sm.record_request(400L, 800L, 40L)  // should evict oldest (10ms)
  assert_eq(sm.avg_duration_ms(), 30L)  // (20+30+40)/3
}

test "stream_metrics_no_samples" {
  let sm = new_stream_metrics(100)
  assert_eq(sm.avg_duration_ms(), 0L)
}
