///|
pub(all) enum StreamTag {
  Message
  Push
  Rekey
  Final
} derive(Eq, Debug)

///|
pub extend StreamTag with Eq::{equal, not_equal}

///|
pub extend StreamTag with Debug::{to_repr}

///|
pub(all) enum StreamError {
  InvalidKey
  InvalidHeader
  InvalidInput
  FrameTooLarge
  TruncatedFrame
  AuthenticationFailed
  UnsupportedTag
  Finalized
  MissingFinal
  EntropyUnavailable(String)
} derive(Eq, Debug)

///|
pub extend StreamError with Eq::{equal, not_equal}

///|
pub extend StreamError with Debug::{to_repr}

///|
fn legacy_error(error : StreamError) -> String {
  match error {
    InvalidKey => "Invalid key length"
    InvalidHeader => "Invalid key or header"
    InvalidInput => "Invalid bytes or frame exceeds prototype limit"
    FrameTooLarge => "Message exceeds prototype limit"
    TruncatedFrame => "Truncated frame"
    AuthenticationFailed => "Authentication failed"
    UnsupportedTag => "Unsupported tag"
    Finalized => "Stream already finalized"
    MissingFinal => "Missing FINAL frame"
    EntropyUnavailable(detail) => detail
  }
}

///|
pub struct StreamWriter {
  priv writer : SecretStreamWriter
}

///|
pub struct StreamReader {
  priv state : SecretStream
}

///|
/// Obtain a random header; host exceptions can still trap on Wasm hosts.
pub fn new_writer(key : Bytes) -> Result[StreamWriter, StreamError] {
  if key.length() != 32 {
    return Err(InvalidKey)
  }
  let header = match @random.getrandom(24) {
    Ok(bytes) => bytes
    Err(detail) => return Err(EntropyUnavailable(detail))
  }
  if header.length() != 24 {
    return Err(InvalidHeader)
  }
  let state = init_pull_bytes(key, header).unwrap()
  Ok({ writer: { state, stream_header: header } })
}

///|
pub fn new_reader(key : Bytes, header : Bytes) -> Result[StreamReader, StreamError] {
  if key.length() != 32 {
    return Err(InvalidKey)
  }
  if header.length() != 24 {
    return Err(InvalidHeader)
  }
  Ok({ state: init_pull_bytes(key, header).unwrap() })
}

///|
pub fn StreamWriter::header(self : StreamWriter) -> Bytes {
  self.writer.header()
}

///|
pub fn StreamWriter::write(
  self : StreamWriter,
  message : Bytes,
  aad : Bytes,
  tag : StreamTag,
) -> Result[Bytes, StreamError] {
  if message.length() > 1048576 || aad.length() > 1048576 {
    return Err(FrameTooLarge)
  }
  let code = match tag {
    Message => 0U
    Push => 1U
    Rekey => 2U
    Final => 3U
  }
  match push(self.writer.state, to_uints(message), to_uints(aad), code) {
    Ok(frame) => Ok(to_bytes(frame))
    Err(error) => Err(error)
  }
}

///|
pub fn StreamReader::read(
  self : StreamReader,
  frame : Bytes,
  aad : Bytes,
) -> Result[(Bytes, StreamTag), StreamError] {
  if frame.length() > 1048593 || aad.length() > 1048576 {
    return Err(FrameTooLarge)
  }
  match pull_checked(self.state, to_uints(frame), to_uints(aad)) {
    Err(error) => Err(error)
    Ok((message, code)) => {
      let tag = match code {
        0U => Message
        1U => Push
        2U => Rekey
        _ => Final // pull_checked authenticates and rejects codes greater than 3.
      }
      Ok((to_bytes(message), tag))
    }
  }
}

///|
/// Call at EOF. MissingFinal must prevent publishing a complete output.
pub fn StreamReader::finish(self : StreamReader) -> Result[Unit, StreamError] {
  if self.state.finished { Ok(()) } else { Err(MissingFinal) }
}
