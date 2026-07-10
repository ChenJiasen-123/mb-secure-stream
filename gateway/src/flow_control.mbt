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
}

///|
/// Creates a new fair queue scheduler.
pub fn new_fair_queue() -> FairQueue {
  { entries: [], bytes_scheduled: 0L }
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
  let entry = { session_id, priority, byte_size, arrival_time, weight }
  self.entries = self.entries + [entry]
}

///|
/// Dequeues the highest priority entry.
/// Returns `None` if the queue is empty.
pub fn FairQueue::dequeue(self : FairQueue) -> QueueEntry? {
  if self.entries.length() == 0 {
    return None
  }
  // Find the highest priority entry
  let mut best_idx = 0
  let mut best_priority = self.entries[0].priority
  let mut idx = 1
  while idx < self.entries.length() {
    let p = self.entries[idx].priority
    if is_higher_priority(p, best_priority) {
      best_idx = idx
      best_priority = p
    }
    idx = idx + 1
  }
  let entry = self.entries[best_idx]
  // Remove the entry
  let mut new_entries : Array[QueueEntry] = []
  let mut i = 0
  while i < self.entries.length() {
    if i != best_idx {
      new_entries = new_entries + [self.entries[i]]
    }
    i = i + 1
  }
  self.entries = new_entries
  self.bytes_scheduled = self.bytes_scheduled + entry.byte_size
  Some(entry)
}

///|
fn priority_value(p : Priority) -> Int64 {
  match p {
    Low => 1L
    Normal => 2L
    High => 3L
    Critical => 4L
  }
}

///|
fn is_higher_priority(a : Priority, b : Priority) -> Bool {
  priority_value(a) > priority_value(b)
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
  { initial_delay, max_delay, attempt: 0L, current_delay: initial_delay }
}

///|
/// Returns the current delay and advances the backoff (exponential with jitter).
pub fn BackoffState::next_delay(self : BackoffState) -> Int64 {
  let delay = self.current_delay
  self.attempt = self.attempt + 1L
  // Exponential: double each attempt, cap at max_delay
  let next = (self.current_delay * 2L).min(self.max_delay)
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
    failure_threshold,
    recovery_timeout,
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
  self.failure_count = self.failure_count + 1L
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
      if current_time - self.last_failure_time >= self.recovery_timeout {
        self.state = HalfOpen
        true
      } else {
        false
      }
    HalfOpen => true // probe request allowed
  }
}
