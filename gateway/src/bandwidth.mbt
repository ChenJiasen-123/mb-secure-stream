/// Bandwidth shaper with token bucket for byte-level flow control.
pub struct BandwidthShaper {
  rate_bps : Int64  // bytes per second
  burst_bytes : Int64
  mut tokens : Int64
  mut last_refill_time : Int64
}

/// Creates a new bandwidth shaper.
/// `rate_bps` is the sustained rate in bytes/sec, `burst_bytes` is the burst capacity.
pub fn new_bandwidth_shaper(rate_bps : Int64, burst_bytes : Int64) -> BandwidthShaper {
  { rate_bps, burst_bytes, tokens: burst_bytes, last_refill_time: 0L }
}

/// Checks if `byte_count` bytes can be sent within the bandwidth limit.
/// Returns `true` if allowed, `false` if bandwidth exceeded.
pub fn BandwidthShaper::try_consume(self : BandwidthShaper, byte_count : Int64, current_time : Int64) -> Bool {
  // Refill tokens based on elapsed time
  let elapsed = current_time - self.last_refill_time
  if elapsed > 0L {
    let refill = elapsed * self.rate_bps
    self.tokens = (self.tokens + refill).min(self.burst_bytes)
    self.last_refill_time = current_time
  }
  if self.tokens >= byte_count {
    self.tokens = self.tokens - byte_count
    true
  } else {
    false
  }
}

/// Connection pool entry for upstream services.
pub struct PoolEntry {
  host : String
  port : Int64
  mut active_connections : Int64
  max_connections : Int64
  mut total_requests : Int64
  mut last_used : Int64
}

/// Creates a new pool entry.
pub fn new_pool_entry(host : String, port : Int64, max_connections : Int64) -> PoolEntry {
  { host, port, active_connections: 0L, max_connections, total_requests: 0L, last_used: 0L }
}

/// Connection pool for upstream services with connection limits.
pub struct ConnectionPool {
  mut entries : Array[PoolEntry]
  mut total_active : Int64
  global_max : Int64
}

/// Creates a new connection pool with limits.
pub fn new_connection_pool(global_max : Int64) -> ConnectionPool {
  { entries: [], total_active: 0L, global_max }
}

/// Acquires a connection from the pool.
/// Returns `true` if a connection was successfully acquired.
pub fn ConnectionPool::acquire(self : ConnectionPool, host : String, port : Int64, current_time : Int64) -> Bool {
  if self.total_active >= self.global_max {
    return false
  }
  let mut found = false
  let mut i = 0
  while i < self.entries.length() {
    let entry = self.entries[i]
    if entry.host == host && entry.port == port {
      if entry.active_connections < entry.max_connections {
        entry.active_connections = entry.active_connections + 1L
        entry.total_requests = entry.total_requests + 1L
        entry.last_used = current_time
        self.total_active = self.total_active + 1L
        found = true
      }
      break
    }
    i = i + 1
  }
  if !found {
    // Create new pool entry
    let entry = new_pool_entry(host, port, 10L)
    entry.active_connections = 1L
    entry.total_requests = 1L
    entry.last_used = current_time
    self.entries = self.entries + [entry]
    self.total_active = self.total_active + 1L
  }
  true
}

/// Releases a connection back to the pool.
pub fn ConnectionPool::release(self : ConnectionPool, host : String, port : Int64) -> Unit {
  let mut i = 0
  while i < self.entries.length() {
    let entry = self.entries[i]
    if entry.host == host && entry.port == port {
      if entry.active_connections > 0L {
        entry.active_connections = entry.active_connections - 1L
        self.total_active = self.total_active - 1L
      }
      break
    }
    i = i + 1
  }
}

/// Production metrics collector for stream operations.
pub struct StreamMetrics {
  mut total_requests : Int64
  mut total_bytes_in : Int64
  mut total_bytes_out : Int64
  mut total_errors : Int64
  mut total_rate_limited : Int64
  mut total_auth_failures : Int64
  mut request_durations_ms : Array[Int64]  // rolling window
  mut peak_concurrent : Int64
  max_samples : Int
}

/// Creates a new stream metrics collector.
pub fn new_stream_metrics(max_samples : Int) -> StreamMetrics {
  {
    total_requests: 0L,
    total_bytes_in: 0L,
    total_bytes_out: 0L,
    total_errors: 0L,
    total_rate_limited: 0L,
    total_auth_failures: 0L,
    request_durations_ms: [],
    peak_concurrent: 0L,
    max_samples,
  }
}

/// Records a successful request.
pub fn StreamMetrics::record_request(self : StreamMetrics, bytes_in : Int64, bytes_out : Int64, duration_ms : Int64) -> Unit {
  self.total_requests = self.total_requests + 1L
  self.total_bytes_in = self.total_bytes_in + bytes_in
  self.total_bytes_out = self.total_bytes_out + bytes_out
  // Maintain a rolling window of request durations
  let len = self.request_durations_ms.length()
  if len >= self.max_samples {
    // Remove oldest entry by rebuilding the array
    let mut trimmed : Array[Int64] = []
    let mut i = 1
    while i < len {
      trimmed = trimmed + [self.request_durations_ms[i]]
      i = i + 1
    }
    self.request_durations_ms = trimmed
  }
  self.request_durations_ms = self.request_durations_ms + [duration_ms]
}

/// Records an error.
pub fn StreamMetrics::record_error(self : StreamMetrics) -> Unit {
  self.total_errors = self.total_errors + 1L
}

/// Records a rate-limited request.
pub fn StreamMetrics::record_rate_limited(self : StreamMetrics) -> Unit {
  self.total_rate_limited = self.total_rate_limited + 1L
}

/// Records an authentication failure.
pub fn StreamMetrics::record_auth_failure(self : StreamMetrics) -> Unit {
  self.total_auth_failures = self.total_auth_failures + 1L
}

/// Updates peak concurrent connections.
pub fn StreamMetrics::update_peak(self : StreamMetrics, current_concurrent : Int64) -> Unit {
  if current_concurrent > self.peak_concurrent {
    self.peak_concurrent = current_concurrent
  }
}

/// Calculates the average request duration from the rolling window.
pub fn StreamMetrics::avg_duration_ms(self : StreamMetrics) -> Int64 {
  let len = self.request_durations_ms.length()
  if len == 0 {
    return 0L
  }
  let mut sum = 0L
  let mut i = 0
  while i < len {
    sum = sum + self.request_durations_ms[i]
    i = i + 1
  }
  sum / len.to_int64()
}