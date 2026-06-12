// getrandom.native.mbt - Native backend implementation

#borrow(buf)
extern "C" fn _mb_os_random(buf: Bytes, len: Int) -> Int = "mb_os_random"

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
  
  let result = _mb_os_random(dest, len)
  if result != 0 {
    return Err("Failed to get random bytes from OS")
  }
  Ok(dest)
}