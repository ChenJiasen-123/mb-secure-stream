/// Rate limiter configuration for token bucket algorithm.
pub struct RateLimiter {
  max_tokens : Int64
  refill_rate : Int64  // tokens per second
  mut tokens : Int64
  mut last_refill_time : Int64
}

/// Creates a new rate limiter with the given capacity and refill rate.
/// `max_tokens` is the burst capacity, `refill_rate` is the steady-state rate (tokens/second).
pub fn new_rate_limiter(max_tokens : Int64, refill_rate : Int64) -> RateLimiter {
  {
    max_tokens,
    refill_rate,
    tokens: max_tokens,
    last_refill_time: 0L,
  }
}

/// Attempts to consume a token from the rate limiter.
/// Returns `true` if allowed, `false` if rate limited.
pub fn RateLimiter::try_consume(
  self : RateLimiter,
  current_time : Int64,
) -> Bool {
  // Refill tokens based on elapsed time
  let elapsed = current_time - self.last_refill_time
  if elapsed > 0L {
    let refill = elapsed * self.refill_rate
    self.tokens = (self.tokens + refill).min(self.max_tokens)
    self.last_refill_time = current_time
  }
  if self.tokens > 0L {
    self.tokens = self.tokens - 1L
    true
  } else {
    false
  }
}

/// Nonce-based replay protection using a sliding window.
pub struct ReplayProtector {
  seen_nonces : Map[String, Int64]  // nonce -> expiry timestamp
  window_size : Int64  // how long a nonce remains valid (in seconds)
}

/// Creates a new replay protector with the given window size.
/// `window_size` is how long a nonce should be remembered (in seconds).
pub fn new_replay_protector(window_size : Int64) -> ReplayProtector {
  { seen_nonces: Map([], capacity=0), window_size }
}

/// Checks if a nonce has been seen before within the window.
/// Returns `true` if the nonce is fresh (not replayed).
pub fn ReplayProtector::check_nonce(
  self : ReplayProtector,
  nonce : String,
  current_time : Int64,
) -> Bool {
  if self.seen_nonces.contains(nonce) {
    return false  // replay detected
  }
  self.seen_nonces[nonce] = current_time + self.window_size
  true
}

/// Evicts expired nonces from the replay protector.
pub fn ReplayProtector::evict_expired(self : ReplayProtector, current_time : Int64) -> Unit {
  let expired : Array[String] = []
  for key in self.seen_nonces.keys() {
    match self.seen_nonces.get(key) {
      Some(expiry) => if expiry <= current_time { expired.push(key) }
      None => ()
    }
  }
  for key in expired {
    self.seen_nonces.remove(key)
  }
}

/// Stream session metadata for connection tracking.
pub struct StreamSession {
  session_id : String
  user_sub : String
  user_role : String
  created_at : Int64
  mut last_activity : Int64
  mut packet_count : Int64
  mut byte_count : Int64
  is_active : Bool
}

/// Creates a new stream session.
pub fn new_stream_session(
  session_id : String,
  user_sub : String,
  user_role : String,
  created_at : Int64,
) -> StreamSession {
  {
    session_id,
    user_sub,
    user_role,
    created_at,
    last_activity: created_at,
    packet_count: 0L,
    byte_count: 0L,
    is_active: true,
  }
}

/// Records a packet in the session.
pub fn StreamSession::record_packet(self : StreamSession, bytes : Int64, timestamp : Int64) -> Unit {
  self.packet_count = self.packet_count + 1L
  self.byte_count = self.byte_count + bytes
  self.last_activity = timestamp
}

/// Checks if the session has timed out.
/// Returns `true` if the session should be considered expired.
pub fn StreamSession::is_expired(self : StreamSession, timeout_seconds : Int64, current_time : Int64) -> Bool {
  (current_time - self.last_activity) > timeout_seconds
}