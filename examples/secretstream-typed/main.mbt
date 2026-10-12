///|
fn main {
  let key = Bytes::make(32, b'\x42') // Synthetic example key only.
  let writer = @stream.new_writer(key).unwrap()
  let reader = @stream.new_reader(key, writer.header()).unwrap()
  for tag in [@stream.Message, @stream.Push, @stream.Rekey, @stream.Final] {
    let frame = writer.write(b"typed stream example", b"metadata", tag).unwrap()
    match reader.read(frame, b"wrong metadata") {
      Err(@stream.AuthenticationFailed) => ()
      _ => abort("Expected recoverable authentication failure")
    }
    let (message, received_tag) = reader.read(frame, b"metadata").unwrap()
    if message != b"typed stream example" || received_tag != tag {
      abort("Typed stream mismatch")
    }
  }
  reader.finish().unwrap()
  match writer.write(b"", b"", @stream.Message) {
    Err(@stream.Finalized) => ()
    _ => abort("Expected terminal FINAL")
  }
  println("PASS: public typed stream API and recoverable errors")
}
