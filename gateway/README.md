# Gateway — Stream Security & Flow Control Middleware

Experimental security filter, rate limiting, bandwidth shaping, connection pooling, and request metrics for MoonBit stream processing.

## Status

Experimental implementation. Tests cover selected behavior and vectors; they do not establish production readiness or side-channel resistance.

## Reference standards

- **RFC 7519** — JSON Web Tokens (JWT)
- **RFC 7515** — JSON Web Signature (JWS)
- **RFC 7518** — JSON Web Algorithms (JWA)

## Performance

No reproducible per-operation benchmark is published for this module. See the repository measurement reports for the specific configurations measured.

## Security Considerations

- **JWT verification**: Constant-time signature comparison prevents timing attacks
- **Algorithm enforcement**: Rejects `alg:none` and algorithm confusion (CVE-2016-5431)
- **Claims validation**: Strict exp/nbf/iss/aud checking with current time binding
- **Replay protection**: Nonce-based sliding window prevents token replay

## Architecture

```
Token → verify() → parse_claims() → validate_claims() → StreamContext
                                                              │
                    ┌─────────────────────────────────────────┘
                    ▼
         ┌─────────────────┐
         │   FairQueue     │── Priority-based stream arbitration
         ├─────────────────┤
         │  RateLimiter    │── Token bucket rate limiting
         ├─────────────────┤
         │ BandwidthShaper │── Byte-level bandwidth control
         ├─────────────────┤
         │ ConnectionPool  │── Upstream connection pooling
         ├─────────────────┤
         │ CircuitBreaker  │── Failure isolation
         ├─────────────────┤
         │ ReplayProtector │── Nonce-based replay prevention
         ├─────────────────┤
         │ StreamMetrics   │── Request counters and timings
         └─────────────────┘
```

## Security Pipeline

| Step | Function | Purpose |
|------|----------|---------|
| 1 | `verify(token, key)` | HMAC/ECDSA signature check |
| 2 | `parse_gateway_claims(json)` | Extract sub, exp, nbf, iss, role |
| 3 | `validate_claims(payload, time)` | Check exp, nbf, iss, aud |

## Flow Control Components

### Rate Limiter
Token bucket algorithm for request rate control.

```moonbit
let rl = new_rate_limiter(100L, 10L)  // 100 burst, 10 tokens/sec
if rl.try_consume(current_time) {
  // process request
}
```

### Bandwidth Shaper
Byte-level token bucket for bandwidth management.

```moonbit
let bw = new_bandwidth_shaper(1_000_000L, 10_000_000L)  // 1 MB/s, 10 MB burst
if bw.try_consume(packet_size, current_time) {
  // send data
}
```

### Fair Queue
Priority-based weighted fair queuing for stream arbitration.

```moonbit
let fq = new_fair_queue()
fq.enqueue("sess-1", Critical, 100L, arrival_time)
fq.enqueue("sess-2", Low, 200L, arrival_time)

match fq.dequeue() {
  Some(entry) => // process highest priority first
  None => // queue empty
}
```

### Circuit Breaker
Failure isolation with automatic recovery.

```moonbit
let cb = new_circuit_breaker(5L, 30_000L)  // 5 failures, 30s recovery
if cb.allow_request(current_time) {
  // forward to upstream
  cb.record_success()
} else {
  cb.record_failure(current_time)
  // return cached response
}
```

### Connection Pool
Upstream connection pooling with per-host limits.

```moonbit
let pool = new_connection_pool(100L)  // 100 global max connections
if pool.acquire("upstream.example.com", 443L, current_time) {
  // use connection
  pool.release("upstream.example.com", 443L)
}
```

### Exponential Backoff
Retry logic with capped exponential delay.

```moonbit
let bo = new_backoff(100L, 30_000L)
let delay = bo.next_delay()  // 100, 200, 400, 800, ...
bo.reset()  // after success
```

### Replay Protection
Nonce-based sliding window replay detection.

```moonbit
let rp = new_replay_protector(300L)  // 5 minute window
if rp.check_nonce(nonce, current_time) {
  // fresh request
}
// Periodically evict expired entries
rp.evict_expired(current_time)
```

### Stream Session
Connection tracking with packet/byte accounting.

```moonbit
let sess = new_stream_session("sess-1", "user-1", "admin", 0L)
sess.record_packet(1024L, current_time)
if sess.is_expired(300L, current_time) {  // 5 min timeout
  // session expired
}
```

### Request Metrics
Comprehensive observability for stream operations.

```moonbit
let sm = new_stream_metrics(1000)  // 1000-sample rolling window
sm.record_request(bytes_in, bytes_out, duration_ms)
sm.record_error()
sm.record_rate_limited()
sm.update_peak(concurrent_connections)
let avg_latency = sm.avg_duration_ms()
```

## Usage

```moonbit
let key = @mb_jwt.JwtKey::HS256("secret")
let ctx = new_stream_context(token)
execute_security_filter(ctx, key, current_time)
if ctx.is_allowed {
  println("role: " + ctx.user_role)
}
```

## Tests

```bash
cd gateway && moon test
```

### Test Coverage

- Security filter (valid/invalid/expired/nbf tokens)
- Claims parsing (all fields, optional fields, error cases)
- Rate limiter (basic, refill)
- Fair queue (priority ordering, empty queue)
- Backoff (exponential growth, max cap, reset)
- Circuit breaker (closed/open/half-open/recovery)
- Bandwidth shaper (basic, refill)
- Connection pool (basic, release, global limit, host limit)
- Stream metrics (basic, errors, average, peak, rolling window)
- Replay protector (basic, expiry, eviction)
- Stream session (basic, packet recording, expiry)