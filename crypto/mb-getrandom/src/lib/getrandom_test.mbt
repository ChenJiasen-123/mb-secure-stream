// Success: returns Ok with exact length and not all zeros
test {
  let lens : Array[Int] = []
  lens.push(1)
  lens.push(2)
  lens.push(16)
  lens.push(32)
  lens.push(64)
  
  let mut idx = 0
  while idx < lens.length() {
    let len = lens[idx]
    let res = getrandom(len)
    assert_true(res is Ok(_))
    match res {
      Ok(bytes) => {
        assert_true(bytes.length() == len)
        // sanity: not all zeros
        assert_true(!all_zero(bytes))
      }
      Err(_) => assert_true(false)
    }
    idx = idx + 1
  }
}

// Error: zero and negative length
test {
  match getrandom(0) {
    Ok(_) => assert_true(false)
    Err(msg) => assert_true(msg == "Length must be positive")
  }
  match getrandom(-8) {
    Ok(_) => assert_true(false)
    Err(msg) => assert_true(msg == "Length must be positive")
  }
}

// Randomness sanity: two independent calls likely differ
test {
  let a = getrandom(32)
  let b = getrandom(32)
  match (a, b) {
    (Ok(x), Ok(y)) => {
      assert_true(x.length() == 32 && y.length() == 32)
      // It is astronomically unlikely that two 32-byte buffers are identical
      assert_true(!bytes_equal(x, y))
    }
    _ => assert_true(false)
  }
}

// Larger buffer check (kept modest for test speed)
test {
  match getrandom(256) {
    Ok(bytes) => {
      assert_true(bytes.length() == 256)
      assert_true(!all_zero(bytes))
    }
    Err(_) => assert_true(false)
  }
}

fn all_zero(b: Bytes) -> Bool {
  let n = b.length()
  let mut i = 0
  while i < n {
    if b[i] != b'\x00' { return false }
    i = i + 1
  }
  true
}

fn bytes_equal(a: Bytes, b: Bytes) -> Bool {
  if a.length() != b.length() { return false }
  let n = a.length()
  let mut i = 0
  while i < n {
    if a[i] != b[i] { return false }
    i = i + 1
  }
  true
}