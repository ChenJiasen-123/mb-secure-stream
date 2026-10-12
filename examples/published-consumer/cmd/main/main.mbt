///|
/// Entry point for the CLI or runnable program in this template.
/// Keep main focused; move logic into the library package.
/// Run with `moon run cmd/main` from the project root.
fn main {
  let key = Bytes::make(32, b'\x42') // Synthetic test key only.
  let writer = @stream.init_push(key).unwrap()
  let reader = @stream.init_pull_bytes(key, writer.header()).unwrap()
  for tag in [0U, 1U, 2U, 3U] {
    let frame = writer.push(b"installed package", b"metadata", tag).unwrap()
    if reader.pull_bytes(frame, b"wrong metadata") is Ok(_) {
      abort("Wrong AAD accepted")
    }
    let (message, actual_tag) = reader.pull_bytes(frame, b"metadata").unwrap()
    if message != b"installed package" || actual_tag != tag {
      abort("Published package mismatch")
    }
  }
  reader.finish().unwrap()
  if writer.push(b"", b"", 0U) is Ok(_) {
    abort("Frame accepted after FINAL")
  }
  println("PASS: published secretstream package consumer")
}
