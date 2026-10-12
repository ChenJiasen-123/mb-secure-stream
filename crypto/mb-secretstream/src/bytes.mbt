///|
fn to_uints(bytes : Bytes) -> Array[UInt] {
  Array::makei(bytes.length(), i => bytes[i].to_int().reinterpret_as_uint())
}

///|
fn to_bytes(data : Array[UInt]) -> Bytes {
  Bytes::from_array(data.map(b => b.to_byte()))
}

///|
pub struct SecretStreamWriter {
  priv state : SecretStream
  priv stream_header : Bytes
}

///|
pub fn SecretStreamWriter::header(self : SecretStreamWriter) -> Bytes {
  to_bytes(to_uints(self.stream_header))
}

///|
pub fn SecretStreamWriter::push(
  self : SecretStreamWriter,
  message : Bytes,
  aad : Bytes,
  tag : UInt,
) -> Result[Bytes, String] {
  // Check lengths before allocating converted arrays.
  if message.length() > 1048576 || aad.length() > 1048576 {
    return Err("Frame exceeds limit")
  }
  match push(self.state, to_uints(message), to_uints(aad), tag) {
    Ok(frame) => Ok(to_bytes(frame))
    Err(e) => Err(e)
  }
}

///|
pub fn init_pull_bytes(
  key : Bytes,
  header : Bytes,
) -> Result[SecretStream, String] {
  if key.length() != 32 || header.length() != 24 {
    return Err("Invalid key or header")
  }
  init_pull(to_uints(key), to_uints(header))
}

///|
pub fn SecretStream::pull_bytes(
  self : SecretStream,
  frame : Bytes,
  aad : Bytes,
) -> Result[(Bytes, UInt), String] {
  if frame.length() > 1048593 || aad.length() > 1048576 {
    return Err("Frame exceeds limit")
  }
  match self.pull(to_uints(frame), to_uints(aad)) {
    Ok((message, tag)) => Ok((to_bytes(message), tag))
    Err(e) => Err(e)
  }
}
