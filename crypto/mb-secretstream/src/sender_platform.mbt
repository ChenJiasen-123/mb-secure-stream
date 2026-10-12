///|
/// Sender with a fresh header from the backend's host/OS CSPRNG.
/// Entropy failure is an error; there is no deterministic fallback.
/// Wasm requires the crypto imports documented by mb-getrandom. A host
/// exception traps the call before a writer is returned.
pub fn init_push(key : Bytes) -> Result[SecretStreamWriter, String] {
  if key.length() != 32 {
    return Err("Invalid key length")
  }
  let header = match @random.getrandom(24) {
    Ok(bytes) => bytes
    Err(e) => return Err(e)
  }
  match init_pull_bytes(key, header) {
    Ok(state) => Ok({ state, stream_header: header, })
    Err(e) => Err(e)
  }
}
