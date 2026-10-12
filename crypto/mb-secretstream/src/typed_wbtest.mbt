///|
test "typed reader errors are recoverable and FINAL is terminal" {
  let key = Bytes::make(32, b'\x42')
  let header = Bytes::make(24, b'\x24')
  // Fixed header is confined to white-box tests; no public fixed-header sender.
  let writer : StreamWriter = {
    writer: {
      state: init_pull_bytes(key, header).unwrap(),
      stream_header: header,
    },
  }
  let reader = new_reader(key, header).unwrap()
  assert_true(new_reader(b"short", header) is Err(InvalidKey))
  assert_true(new_reader(key, b"short") is Err(InvalidHeader))
  for tag in [Message, Push, Rekey, Final] {
    assert_eq(reader.finish(), Err(MissingFinal))
    let frame = writer.write(b"typed payload", b"context", tag).unwrap()
    assert_true(reader.read(b"short", b"context") is Err(TruncatedFrame))
    assert_true(reader.read(frame, b"other") is Err(AuthenticationFailed))
    let damaged = Bytes::makei(frame.length(), i =>
      if i == frame.length() - 1 { frame[i] ^ b'\x01' } else { frame[i] },
    )
    assert_true(reader.read(damaged, b"context") is Err(AuthenticationFailed))
    assert_eq(reader.read(frame, b"context"), Ok((b"typed payload", tag)))
  }
  assert_eq(reader.finish(), Ok(()))
  assert_true(reader.read(b"", b"") is Err(Finalized))
  assert_true(writer.write(b"", b"", Message) is Err(Finalized))
}

///|
test "typed oversized input and legacy error compatibility" {
  let key = Bytes::make(32, b'\x42')
  let header = Bytes::make(24, b'\x24')
  let state = init_pull_bytes(key, header).unwrap()
  let reader = new_reader(key, header).unwrap()
  let oversized = Bytes::make(1048594, b'\x00')
  assert_true(reader.read(oversized, b"") is Err(FrameTooLarge))
  assert_eq(state.pull_bytes(oversized, b""), Err("Frame exceeds limit"))
  assert_eq(state.pull_bytes(b"", b""), Err("Truncated frame"))
  assert_eq(state.finish(), Err("Missing FINAL frame"))
  let writer : StreamWriter = {
    writer: {
      state: init_pull_bytes(key, header).unwrap(),
      stream_header: header,
    },
  }
  assert_true(writer.write(oversized, b"", Message) is Err(FrameTooLarge))
  assert_true(writer.write(b"", oversized, Message) is Err(FrameTooLarge))
  assert_true(reader.read(b"", oversized) is Err(FrameTooLarge))
  let frame = writer.write(b"valid", b"", Final).unwrap()
  assert_eq(reader.read(frame, b""), Ok((b"valid", Final)))
  assert_eq(reader.finish(), Ok(()))
}
