///|
/// Priority levels for stream flow control.
pub enum Priority {
  Low
  Normal
  High
  Critical
}

// Helper to ensure all Priority variants are recognized as used.

///|
fn _use_all_priorities(p : Priority) -> Priority {
  match p {
    Low => Normal
    Normal => High
    High => Critical
    Critical => Low
  }
}

///|
/// A weighted fair queue entry for stream arbitration.
pub struct QueueEntry {
  session_id : String
  priority : Priority
  byte_size : Int64
  arrival_time : Int64
  weight : Int64
}

///|
/// Fair queuing scheduler for stream arbitration.
/// Uses Array-based queues for each priority level.
pub struct FairQueue {
  mut entries : Array[QueueEntry]
  mut bytes_scheduled : Int64
  priv mut next_slot : Int32
}

///|
/// Creates a new fair queue scheduler.
pub fn new_fair_queue() -> FairQueue {
  { entries: [], bytes_scheduled: 0L, next_slot: 0, }
}

///|
/// Enqueues a stream entry with the given priority.
pub fn FairQueue::enqueue(
  self : FairQueue,
  session_id : String,
  priority : Priority,
  byte_size : Int64,
  arrival_time : Int64,
) -> Unit {
  let weight : Int64 = match priority {
    Low => 1L
    Normal => 2L
    High => 4L
    Critical => 8L
  }
  let entry = { session_id, priority, byte_size, arrival_time, weight, }
  self.entries = self.entries + [entry]
}

///|
/// Dequeue using weighted request round robin: Critical:High:Normal:Low = 8:4:2:1.
/// FIFO within each class. A continuously queued class is visited in at most 15 calls.
pub fn FairQueue::dequeue(self : FairQueue) -> QueueEntry? {
  if self.entries.length() == 0 {
    return None
  }
  for _ in 0..<15 {
    let target_weight = if self.next_slot < 8 {
      8L
    } else if self.next_slot < 12 {
      4L
    } else if self.next_slot < 14 {
      2L
    } else {
      1L
    }
    self.next_slot = (self.next_slot + 1) % 15
    for index in 0..<self.entries.length() {
      let entry = self.entries[index]
      if entry.weight == target_weight {
        let remaining : Array[QueueEntry] = []
        for i in 0..<self.entries.length() {
          if i != index {
            remaining.push(self.entries[i])
          }
        }
        self.entries = remaining
        self.bytes_scheduled = self.bytes_scheduled + entry.byte_size
        return Some(entry)
      }
    }
  }
  None
}

///|
/// Exponential backoff state for retry logic.
pub struct BackoffState {
  initial_delay : Int64 // milliseconds
  max_delay : Int64
  mut attempt : Int64
  mut current_delay : Int64
}

///|
/// Creates a new backoff state.
/// `initial_delay` in ms, `max_delay` in ms.
pub fn new_backoff(initial_delay : Int64, max_delay : Int64) -> BackoffState {
  // Preserve the legacy constructor; normalize to 0 <= initial <= max.
  let max_delay = max_delay.max(0L)
  let initial_delay = initial_delay.max(0L).min(max_delay)
  { initial_delay, max_delay, attempt: 0L, current_delay: initial_delay, }
}

///|
/// Returns the current delay and advances the backoff (deterministic capped exponential; no jitter).
pub fn BackoffState::next_delay(self : BackoffState) -> Int64 {
  let delay = self.current_delay
  if self.attempt < 9223372036854775807L {
    self.attempt = self.attempt + 1L
  }
  // Exponential: double each attempt, cap at max_delay
  let next = if self.current_delay > self.max_delay / 2L {
    self.max_delay
  } else {
    self.current_delay * 2L
  }
  self.current_delay = next
  delay
}

///|
/// Resets the backoff state after a successful operation.
pub fn BackoffState::reset(self : BackoffState) -> Unit {
  self.attempt = 0L
  self.current_delay = self.initial_delay
}

///|
/// Circuit breaker state for upstream protection.
pub enum CircuitState {
  Closed
  Open
  HalfOpen
} derive(Eq)

///|
/// Circuit breaker for upstream service protection.
pub struct CircuitBreaker {
  mut state : CircuitState
  failure_threshold : Int64
  recovery_timeout : Int64 // milliseconds
  mut failure_count : Int64
  mut last_failure_time : Int64
}

///|
/// Creates a new circuit breaker.
pub fn new_circuit_breaker(
  failure_threshold : Int64,
  recovery_timeout : Int64,
) -> CircuitBreaker {
  {
    state: Closed,
    failure_threshold: failure_threshold.max(1L),
    recovery_timeout: recovery_timeout.max(0L),
    failure_count: 0L,
    last_failure_time: 0L,
  }
}

///|
/// Records a success, resetting the failure count.
pub fn CircuitBreaker::record_success(self : CircuitBreaker) -> Unit {
  self.failure_count = 0L
  self.state = Closed
}

///|
/// Records a failure, potentially opening the circuit.
pub fn CircuitBreaker::record_failure(
  self : CircuitBreaker,
  current_time : Int64,
) -> Unit {
  if self.failure_count < self.failure_threshold {
    self.failure_count = self.failure_count + 1L
  }
  self.last_failure_time = current_time
  if self.failure_count >= self.failure_threshold {
    self.state = Open
  }
}

///|
/// Checks if the circuit breaker allows requests.
pub fn CircuitBreaker::allow_request(
  self : CircuitBreaker,
  current_time : Int64,
) -> Bool {
  match self.state {
    Closed => true
    Open =>
      if current_time >= 0L &&
        self.last_failure_time >= 0L &&
        current_time >= self.last_failure_time &&
        current_time - self.last_failure_time >= self.recovery_timeout {
        self.state = HalfOpen
        true
      } else {
        false
      }
    HalfOpen => false // One probe is in flight; caller must report success/failure (including timeout).
  }
}

///|
pub extend CircuitState with Eq::{not_equal, equal}
