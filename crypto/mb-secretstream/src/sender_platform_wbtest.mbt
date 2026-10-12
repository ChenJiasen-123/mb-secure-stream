///|
test "random sender roundtrip and independent headers" {
  let key = to_bytes(
    fixture_hex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ),
  )
  let writer = init_push(key).unwrap()
  let other = init_push(key).unwrap()
  assert_true(writer.header() != other.header())
  let header = writer.header()
  let reader = init_pull_bytes(key, header).unwrap()
  let frame = writer.push(b"example", b"metadata", 3U).unwrap()
  assert_eq(reader.pull_bytes(frame, b"metadata").unwrap(), (b"example", 3U))
  assert_eq(reader.finish(), Ok(()))
  assert_true(writer.push(b"", b"", 0U) is Err(_))
  assert_true(init_push(b"short") is Err(_))
}
