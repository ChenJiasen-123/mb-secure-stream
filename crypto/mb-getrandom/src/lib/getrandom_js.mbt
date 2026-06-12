// getrandom.js.mbt - JavaScript backend implementation

extern "js" fn js_crypto_get_random_values(buf : Bytes, len : Int) -> Int =
  #| (buf, len) => {
  #|   try {
  #|     if (typeof globalThis !== 'undefined' && globalThis.crypto) {
  #|       const view = new Uint8Array(buf.buffer, buf.byteOffset, len);
  #|       globalThis.crypto.getRandomValues(view);
  #|       return 0;
  #|     } else if (typeof require !== 'undefined') {
  #|       const crypto = require('crypto');
  #|       const bytes = crypto.randomBytes(len);
  #|       const view = new Uint8Array(buf.buffer, buf.byteOffset, len);
  #|       view.set(bytes);
  #|       return 0;
  #|     }
  #|     return -1;
  #|   } catch (e) {
  #|     return -1;
  #|   }
  #| }

pub fn getrandom(len: Int) -> Result[Bytes, String] {
  if len <= 0 {
    return Err("Length must be positive")
  }
  
  // Create a zero-filled byte array
  let zeros : Array[Byte] = []
  let mut i = 0
  while i < len {
    zeros.push(b'\x00')
    i = i + 1
  }
  let dest = Bytes::from_array(zeros)
  
  let result = js_crypto_get_random_values(dest, len)
  if result != 0 {
    return Err("Failed to get random bytes from JavaScript runtime")
  }
  Ok(dest)
}