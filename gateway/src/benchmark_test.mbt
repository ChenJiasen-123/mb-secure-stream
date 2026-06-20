// ──────────────────────────────────────────────────────────
// Gateway Benchmark Suite: High-Concurrency Throughput Test
// ──────────────────────────────────────────────────────────
//
// Measures:
//   1. Full-path — execute_security_filter end-to-end
//      (signature verify + JSON parse + claims validate)
//   2. Crypto-first-line — just signature verify
//
// 100,000 tokens: 50k valid (HS256), 50k forged
// ──────────────────────────────────────────────────────────

let bench_secret : String = "benchmark-secret-must-be-long-enough-0000"
let bench_key : @mb_jwt.JwtKey = @mb_jwt.JwtKey::HS256(bench_secret)
let bench_exp : Int64 = 2_000_000_000L
let bench_nbf : Int64 = 1_000_000_000L
let bench_current_time : Int64 = 1_500_000_000L

/// Generate `count` signed valid tokens.
fn gen_valid_tokens(count : Int) -> Array[String] {
  let tokens : Array[String] = []
  for i in 0..<count {
    let payload = "{\"sub\":\"user\{i}\",\"exp\":\{bench_exp},\"nbf\":\{bench_nbf},\"role\":\"admin\"}"
    tokens.push(match @mb_jwt.sign(payload, bench_key) {
      Ok(t) => t
      Err(_) => ""
    })
  }
  tokens
}

/// Generate `count` fake tokens:
///   half = random garbage, half = tampered JWT with wrong signature
fn gen_forged_tokens(count : Int) -> Array[String] {
  let tokens : Array[String] = []
  let half = count / 2
  for i in 0..<half {
    tokens.push("garbage_token_data_\{i}_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
  }
  // Build one template tampered token
  let base_payload = "{\"sub\":\"victim\",\"exp\":\{bench_exp}}"
  let base_token = match @mb_jwt.sign(base_payload, bench_key) {
    Ok(t) => t
    Err(_) => "a.b.c"
  }
  let chars = base_token.to_array()
  let mut first_dot = -1
  let mut second_dot = -1
  for j in 0..<chars.length() {
    if chars[j] == '.' {
      if first_dot < 0 { first_dot = j } else { second_dot = j; break }
    }
  }
  let mut header_part = ""
  for j in 0..<first_dot { header_part = header_part + chars[j].to_string() }
  let mut sig_part = ""
  for j in (second_dot + 1)..<chars.length() { sig_part = sig_part + chars[j].to_string() }

  for i in half..<count {
    let fake_payload = "{\"sub\":\"hacker\{i}\",\"exp\":\{bench_exp}}"
    let fake_b64 = @mb_jwt.base64url_encode_string(fake_payload)
    tokens.push(header_part + "." + fake_b64 + "." + sig_part)
  }
  tokens
}

/// Full-path benchmark: execute_security_filter on all tokens
fn run_full_path(tokens : Array[String]) -> Unit {
  for i in 0..<tokens.length() {
    let ctx = new_stream_context(tokens[i])
    execute_security_filter(ctx, bench_key, bench_current_time)
  }
}

/// Crypto-only benchmark: @mb_jwt.verify only (Step 1 fast path)
fn run_crypto_only(tokens : Array[String]) -> Unit {
  for i in 0..<tokens.length() {
    let _ = @mb_jwt.verify(tokens[i], bench_key)
  }
}

/// Print a formatted result header
fn print_header(title : String) -> Unit {
  let line = "═══════════════════════════════════════════════"
  println("\n\{line}")   
  println("  \{title}")
  println(line)
}

/// Print a single benchmark sub-result
fn print_sub(label : String, count : Int) -> Unit {
  println("    \{label}: \{count} tokens")
}

// ──────────────────────────────────────────────────────────
// Test 1: Valid tokens
// ──────────────────────────────────────────────────────────

test "BENCHMARK: Full path — 50000 valid tokens" {
  print_header("Full-path Benchmark: 50,000 valid HS256 tokens")

  let tokens = gen_valid_tokens(50_000)
  print_sub("verify + parse + validate", tokens.length())

  run_full_path(tokens)

  assert_true(tokens.length() == 50_000)
}

test "BENCHMARK: Crypto-only — 50000 valid tokens" {
  print_header("Crypto-only Benchmark: 50,000 valid HS256 tokens")

  let tokens = gen_valid_tokens(50_000)
  print_sub("signature verify only", tokens.length())

  run_crypto_only(tokens)

  assert_true(tokens.length() == 50_000)
}

// ──────────────────────────────────────────────────────────
// Test 2: Forged tokens
// ──────────────────────────────────────────────────────────

test "BENCHMARK: Full path — 50000 forged tokens" {
  print_header("Full-path Benchmark: 50,000 forged tokens")

  let tokens = gen_forged_tokens(50_000)
  print_sub("verify + parse + validate", tokens.length())

  run_full_path(tokens)

  assert_true(tokens.length() == 50_000)
}

test "BENCHMARK: Crypto-only — 50000 forged tokens" {
  print_header("Crypto-only Benchmark: 50,000 forged tokens")

  let tokens = gen_forged_tokens(50_000)
  print_sub("signature verify only", tokens.length())

  run_crypto_only(tokens)

  assert_true(tokens.length() == 50_000)
}

// ──────────────────────────────────────────────────────────
// Test 3: Mixed workload (alternating valid + forged)
// ──────────────────────────────────────────────────────────

test "BENCHMARK: Full path — 100000 mixed tokens" {
  print_header("Full-path Benchmark: 100,000 mixed (50% valid, 50% forged)")

  let valid = gen_valid_tokens(50_000)
  let forged = gen_forged_tokens(50_000)
  let mixed : Array[String] = []
  for i in 0..<50_000 {
    mixed.push(valid[i])
    mixed.push(forged[i])
  }
  print_sub("verify + parse + validate", mixed.length())

  run_full_path(mixed)

  assert_true(mixed.length() == 100_000)
}

test "BENCHMARK: Crypto-only — 100000 mixed tokens" {
  print_header("Crypto-only Benchmark: 100,000 mixed (50% valid, 50% forged)")

  let valid = gen_valid_tokens(50_000)
  let forged = gen_forged_tokens(50_000)
  let mixed : Array[String] = []
  for i in 0..<50_000 {
    mixed.push(valid[i])
    mixed.push(forged[i])
  }
  print_sub("signature verify only", mixed.length())

  run_crypto_only(mixed)

  assert_true(mixed.length() == 100_000)
}

// ──────────────────────────────────────────────────────────
// Test 4: Large loop — 100k full path to simulate sustained load
// ──────────────────────────────────────────────────────────

test "BENCHMARK: Sustained load — 100000 tokens rapid fire" {
  print_header("Sustained Load: 100,000 tokens in tight loop")

  let valid = gen_valid_tokens(50_000)
  let forged = gen_forged_tokens(50_000)

  println("    Phase 1/2: Full-path on valid tokens...")
  for i in 0..<valid.length() {
    let ctx = new_stream_context(valid[i])
    execute_security_filter(ctx, bench_key, bench_current_time)
  }

  println("    Phase 2/2: Full-path on forged tokens...")
  for i in 0..<forged.length() {
    let ctx = new_stream_context(forged[i])
    execute_security_filter(ctx, bench_key, bench_current_time)
  }

  println("    Done — 100,000 tokens processed.")
  assert_true(valid.length() == 50_000)
  assert_true(forged.length() == 50_000)
}