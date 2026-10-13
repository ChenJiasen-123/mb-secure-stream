///|
test "bandwidth rejects negative requests and saturates refill without overflow" {
  let b = new_bandwidth_shaper(0L, 10L)
  assert_false(b.try_consume(-100L, 0L))
  assert_eq(b.tokens, 10L)
  assert_false(b.try_consume(110L, 0L))
  assert_true(b.try_consume(10L, 0L))
  assert_false(b.try_consume(1L, 0L))
  let huge = new_bandwidth_shaper(9223372036854775807L, 9223372036854775807L)
  assert_true(huge.try_consume(9223372036854775807L, 0L))
  assert_true(huge.try_consume(9223372036854775807L, 9223372036854775807L))
  assert_eq(huge.tokens, 0L)
  assert_false(huge.try_consume(1L, -1L))
  assert_false(new_bandwidth_shaper(-1L, 10L).try_consume(1L, 0L))
  assert_false(new_bandwidth_shaper(1L, -10L).try_consume(1L, 0L))
}

///|
test "gateway policy rejects missing and mismatched issuer and audience" {
  let key = @mb_jwt.JwtKey::HS256("synthetic-regression-key")
  let good = "{\"sub\":\"u\",\"exp\":10000,\"iss\":\"issuer\",\"aud\":\"service\"}"
  let ctx = new_stream_context(@mb_jwt.sign(good, key).unwrap())
  execute_security_filter_with_policy(
    ctx,
    key,
    1000L,
    Some("issuer"),
    Some("service"),
  )
  assert_true(ctx.is_allowed)
  execute_security_filter_with_policy(
    ctx,
    key,
    1000L,
    Some("other"),
    Some("service"),
  )
  assert_false(ctx.is_allowed)
  assert_eq(ctx.user_sub, "")
  execute_security_filter_with_policy(
    ctx,
    key,
    1000L,
    Some("issuer"),
    Some("other"),
  )
  assert_false(ctx.is_allowed)
  for
    payload in [
      "{\"sub\":\"u\",\"exp\":10000,\"aud\":\"service\"}", "{\"sub\":\"u\",\"exp\":10000,\"iss\":\"issuer\"}",
    ] {
    let missing = new_stream_context(@mb_jwt.sign(payload, key).unwrap())
    execute_security_filter_with_policy(
      missing,
      key,
      1000L,
      Some("issuer"),
      Some("service"),
    )
    assert_false(missing.is_allowed)
  }
  // Legacy entry point deliberately keeps optional issuer/audience policy.
  execute_security_filter(ctx, key, 1000L)
  assert_true(ctx.is_allowed)
}

///|
test "gateway claim parsing rejects malformed optional claims and inexact dates" {
  for
    value in [
      "\"2000\"", "null", "[]", "{}", "true", "1.5", "9007199254740992", "1e100",
    ] {
    let payload = "{\"sub\":\"u\",\"exp\":10000,\"nbf\":" + value + "}"
    assert_true(parse_gateway_claims(payload) is Err(_))
  }
  for field in ["iss", "aud", "role"] {
    for value in ["null", "[]", "{}", "true", "1"] {
      let payload = "{\"sub\":\"u\",\"exp\":10000,\"" +
        field +
        "\":" +
        value +
        "}"
      assert_true(parse_gateway_claims(payload) is Err(_))
    }
  }
  for value in ["1.5", "9007199254740992", "1e100"] {
    assert_true(
      parse_gateway_claims("{\"sub\":\"u\",\"exp\":" + value + "}") is Err(_),
    )
  }
  let key = @mb_jwt.JwtKey::HS256("synthetic-regression-key")
  let token = @mb_jwt.sign(
    "{\"sub\":\"u\",\"exp\":10000,\"nbf\":\"9000\"}", key,
  ).unwrap()
  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000L)
  assert_false(ctx.is_allowed)
  assert_true(
    parse_gateway_claims("{\"sub\":\"u\",\"exp\":9007199254740991,\"nbf\":-1}")
    is Ok(_),
  )
}

///|
test "half open allows one probe until success failure or reported timeout" {
  let b = new_circuit_breaker(1L, 10L)
  b.record_failure(0L)
  assert_false(b.allow_request(9L))
  assert_true(b.allow_request(10L))
  for _ in 0..<100 {
    assert_false(b.allow_request(10L))
  }
  assert_false(b.allow_request(100L)) // no silent second probe while first is in flight
  b.record_failure(100L) // caller reports a probe timeout
  assert_false(b.allow_request(109L))
  assert_true(b.allow_request(110L))
  b.record_failure(110L)
  assert_false(b.allow_request(119L))
  assert_true(b.allow_request(120L))
  b.record_success()
  assert_true(b.allow_request(120L))
}

///|
test "weighted request round robin gives each class its share and FIFO" {
  let q = new_fair_queue()
  for i in 0..<16 {
    q.enqueue("c" + i.to_string(), Critical, 1L, 0L)
    q.enqueue("h" + i.to_string(), High, 1L, 0L)
    q.enqueue("n" + i.to_string(), Normal, 1L, 0L)
    q.enqueue("l" + i.to_string(), Low, 1L, 0L)
  }
  for round in 0..<2 {
    for i in 0..<8 {
      assert_eq(
        q.dequeue().unwrap().session_id,
        "c" + (round * 8 + i).to_string(),
      )
    }
    for i in 0..<4 {
      assert_eq(
        q.dequeue().unwrap().session_id,
        "h" + (round * 4 + i).to_string(),
      )
    }
    for i in 0..<2 {
      assert_eq(
        q.dequeue().unwrap().session_id,
        "n" + (round * 2 + i).to_string(),
      )
    }
    assert_eq(q.dequeue().unwrap().session_id, "l" + round.to_string())
  }
  let single = new_fair_queue()
  single.enqueue("low", Low, 1L, 0L)
  assert_eq(single.dequeue().unwrap().session_id, "low")
  assert_true(single.dequeue() is None)
}

///|
test "low priority progresses under continuously replenished critical load" {
  let q = new_fair_queue()
  q.enqueue("low", Low, 1L, 0L)
  let mut served = false
  for i in 0..<15 {
    q.enqueue("critical", Critical, 1L, i.to_int64())
    if q.dequeue().unwrap().session_id == "low" {
      served = true
    }
  }
  assert_true(served)
}

///|
test "replay cache expires automatically and fails closed at capacity" {
  let r = new_replay_protector_with_capacity(10L, 2).unwrap()
  assert_true(r.check_nonce("a", 0L))
  assert_true(r.check_nonce("b", 1L))
  assert_false(r.check_nonce("c", 2L))
  assert_false(r.check_nonce("a", 2L)) // no eviction of live evidence
  assert_true(r.check_nonce("c", 10L)) // a expires, capacity recovered
  assert_false(r.check_nonce("b", 10L))
  assert_eq(r.seen_nonces.length(), 2)
  assert_true(r.check_nonce("a", 20L))
  assert_eq(r.seen_nonces.length(), 1)
  let rolling = new_replay_protector_with_capacity(1L, 2).unwrap()
  for i in 0..<1000 {
    assert_true(rolling.check_nonce(i.to_string(), i.to_int64()))
    assert_eq(rolling.seen_nonces.length(), 1)
  }
  assert_true(new_replay_protector_with_capacity(0L, 2) is Err(_))
  assert_true(new_replay_protector_with_capacity(1L, 0) is Err(_))
  assert_false(new_replay_protector(-1L).check_nonce("a", 0L))
  assert_false(r.check_nonce("", 20L))
  assert_false(r.check_nonce("a", -1L))
  assert_false(r.check_nonce("rollback", 19L))
  assert_false(r.check_nonce("overflow", 9223372036854775807L))
  let long_nonce = Array::make(1025, "x").join("")
  assert_false(r.check_nonce(long_nonce, 20L))
  r.evict_expired(30L)
  assert_false(r.check_nonce("after-explicit-evict-rollback", 29L))
}

///|
test "backoff saturates before multiplication and normalizes invalid configuration" {
  let b = new_backoff(4611686018427387904L, 9223372036854775807L)
  assert_eq(b.next_delay(), 4611686018427387904L)
  assert_eq(b.next_delay(), 9223372036854775807L)
  assert_eq(b.next_delay(), 9223372036854775807L)
  b.reset()
  assert_eq(b.next_delay(), 4611686018427387904L)
  let clamped = new_backoff(100L, 10L)
  assert_eq(clamped.next_delay(), 10L)
  clamped.reset()
  assert_eq(clamped.next_delay(), 10L)
  assert_eq(new_backoff(-1L, 10L).next_delay(), 0L)
  assert_eq(new_backoff(10L, -1L).next_delay(), 0L)
}
