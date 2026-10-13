///|
test "request limiter saturates full and empty buckets at Int64 boundaries" {
  let full = new_rate_limiter(9223372036854775807L, 9223372036854775807L)
  assert_true(full.try_consume(1L))
  assert_eq(full.tokens, 9223372036854775806L)
  let empty = new_rate_limiter(1L, 9223372036854775807L)
  assert_true(empty.try_consume(0L))
  assert_true(empty.try_consume(2L))
  assert_eq(empty.tokens, 0L)
  assert_true(empty.try_consume(9223372036854775807L))
  assert_eq(empty.tokens, 0L)
}

///|
test "invalid request limiter configuration disables admission" {
  assert_false(new_rate_limiter(10L, -1L).try_consume(0L))
  assert_false(new_rate_limiter(-1L, 10L).try_consume(0L))
  assert_false(new_rate_limiter(0L, 10L).try_consume(100L))
  let no_refill = new_rate_limiter(1L, 0L)
  assert_true(no_refill.try_consume(0L))
  assert_false(no_refill.try_consume(100L))
}

///|
test "token buckets reject negative and backward time without consuming tokens" {
  let requests = new_rate_limiter(3L, 0L)
  assert_false(requests.try_consume(-1L))
  assert_eq(requests.tokens, 3L)
  assert_true(requests.try_consume(10L))
  assert_false(requests.try_consume(9L))
  assert_eq(requests.tokens, 2L)
  assert_true(requests.try_consume(10L))
  let bytes = new_bandwidth_shaper(0L, 10L)
  assert_true(bytes.try_consume(1L, 10L))
  assert_false(bytes.try_consume(1L, 9L))
  assert_eq(bytes.tokens, 9L)
}

///|
test "request limiter agrees with bounded arithmetic reference model" {
  for capacity in 0..<6 {
    for rate in 0..<6 {
      let limiter = new_rate_limiter(capacity.to_int64(), rate.to_int64())
      let mut available = capacity
      let mut previous = 0
      for step in 0..<50 {
        let now = step / 3
        available = (available + (now - previous) * rate).min(capacity)
        previous = now
        let expected = available > 0
        if expected {
          available = available - 1
        }
        assert_eq(limiter.try_consume(now.to_int64()), expected)
        assert_eq(limiter.tokens, available.to_int64())
      }
    }
  }
}
