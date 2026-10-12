///|
pub fn writer_new(key : Bytes) -> @stream.SecretStreamWriter {
  @stream.init_push(key).unwrap()
}

///|
pub fn writer_header(writer : @stream.SecretStreamWriter) -> Bytes {
  writer.header()
}

///|
pub fn writer_push(
  writer : @stream.SecretStreamWriter,
  message : Bytes,
  is_final : Bool,
) -> Bytes {
  writer.push(message, b"", if is_final { 3U } else { 0U }).unwrap()
}

///|
pub fn reader_new(key : Bytes, header : Bytes) -> @stream.SecretStream {
  @stream.init_pull_bytes(key, header).unwrap()
}

///|
pub fn reader_pull(reader : @stream.SecretStream, frame : Bytes) -> Bytes {
  let (message, _) = reader.pull_bytes(frame, b"").unwrap()
  message
}

///|
pub fn reader_finish(reader : @stream.SecretStream) -> Unit {
  reader.finish().unwrap()
}

///|
/// Record-level bridge for differential tests, including AAD and protocol tags.
pub fn writer_push_record(
  writer : @stream.SecretStreamWriter,
  message : Bytes,
  aad : Bytes,
  tag : UInt32,
) -> Bytes {
  writer.push(message, aad, tag).unwrap()
}

///|
pub fn reader_pull_record(
  reader : @stream.SecretStream,
  frame : Bytes,
  aad : Bytes,
) -> (Bytes, UInt32) {
  reader.pull_bytes(frame, aad).unwrap()
}
