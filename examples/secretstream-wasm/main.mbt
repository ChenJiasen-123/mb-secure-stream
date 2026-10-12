///|
fn main {
  // Synthetic demonstration key only. The sender header still uses host CSPRNG.
  let key = Bytes::make(32, b'\x42')
  let writer = @stream.init_push(key).unwrap()
  let other = @stream.init_push(key).unwrap()
  if writer.header() == other.header() {
    abort("Headers unexpectedly equal")
  }
  let reader = @stream.init_pull_bytes(key, writer.header()).unwrap()
  for tag in [0U, 1U, 2U, 2U, 3U] {
    let frame = writer.push(b"wasm host example", b"metadata", tag).unwrap()
    let (message, received_tag) = reader.pull_bytes(frame, b"metadata").unwrap()
    if message != b"wasm host example" || received_tag != tag {
      abort("Roundtrip mismatch")
    }
  }
  reader.finish().unwrap()
  if writer.push(b"", b"", 0U) is Ok(_) {
    abort("Writer accepted frame after FINAL")
  }
  println("PASS: wasm-gc secretstream host integration")
}
