///|
test "random lengths cross Web Crypto quota boundary" {
  for length in [65535, 65536, 65537, 131073] {
    assert_eq(@lib.getrandom(length).unwrap().length(), length)
  }
  assert_true(@lib.getrandom(0) is Err(_))
  assert_true(@lib.getrandom(-1) is Err(_))
}
