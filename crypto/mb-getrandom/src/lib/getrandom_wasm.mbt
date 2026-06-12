// getrandom_wasm.mbt - WASM/WASM-GC backend using host-provided crypto

// Host must provide these imports under the "crypto" module:
//   crypto.getRandomValues(buf: externref) -> void
//   crypto.newUint8Array(len: i32) -> externref
//   crypto.readByte(buf: externref, idx: i32) -> i32
//
// Example JavaScript host setup:
//   const importObject = {
//     crypto: {
//       getRandomValues: (buf) => { globalThis.crypto.getRandomValues(buf); },
//       newUint8Array: (len) => new Uint8Array(len),
//       readByte: (buf, idx) => buf[idx],
//     }
//   };

#external
priv type JsUint8Array

fn js_new_uint8array(len : Int) -> JsUint8Array = "crypto" "newUint8Array"

fn js_get_random_values(buf : JsUint8Array) -> Unit = "crypto" "getRandomValues"

fn js_read_byte(buf : JsUint8Array, idx : Int) -> Int = "crypto" "readByte"

pub fn getrandom(len : Int) -> Result[Bytes, String] {
  if len <= 0 {
    return Err("Length must be positive")
  }
  let buf = js_new_uint8array(len)
  js_get_random_values(buf)
  let bytes_arr : Array[Byte] = []
  let mut i = 0
  while i < len {
    bytes_arr.push(js_read_byte(buf, i).to_byte())
    i = i + 1
  }
  Ok(Bytes::from_array(bytes_arr))
}
