// Base64URL encoding/decoding (RFC 4648)
// URL-safe alphabet: A-Za-z0-9-_ (no padding)

let base64url_chars : FixedArray[Int] = [
  65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77,  // A-M
  78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,  // N-Z
  97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,  // a-m
  110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,  // n-z
  48, 49, 50, 51, 52, 53, 54, 55, 56, 57,  // 0-9
  45, 95  // - _
]

fn get_encode_char(index: Int) -> String {
  index.unsafe_to_char().to_string()
}

fn get_decode_value(ch: Int) -> Int {
  if ch >= 65 && ch <= 90 {
    // A-Z -> 0-25
    ch - 65
  } else if ch >= 97 && ch <= 122 {
    // a-z -> 26-51
    ch - 97 + 26
  } else if ch >= 48 && ch <= 57 {
    // 0-9 -> 52-61
    ch - 48 + 52
  } else if ch == 45 {
    // '-' -> 62
    62
  } else if ch == 95 {
    // '_' -> 63
    63
  } else {
    -1
  }
}

fn string_to_bytes_filtered(s: String) -> Array[Int] {
  let raw = @utf8.encode(s)
  let result : Array[Int] = []
  for i in 0..<raw.length() {
    result.push(raw[i].to_int())
  }
  result
}

pub fn base64url_encode(data: Array[UInt]) -> String {
  let mut result = ""
  let len = data.length()
  let mut i = 0

  while i + 2 < len {
    let b0 = data[i].reinterpret_as_int()
    let b1 = data[i + 1].reinterpret_as_int()
    let b2 = data[i + 2].reinterpret_as_int()

    let c0 = (b0 >> 2) & 0x3F
    let c1 = ((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)
    let c2 = ((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)
    let c3 = b2 & 0x3F

    result = result + get_encode_char(base64url_chars[c0])
    result = result + get_encode_char(base64url_chars[c1])
    result = result + get_encode_char(base64url_chars[c2])
    result = result + get_encode_char(base64url_chars[c3])

    i = i + 3
  }

  let remaining = len - i
  if remaining == 2 {
    let b0 = data[i].reinterpret_as_int()
    let b1 = data[i + 1].reinterpret_as_int()

    let c0 = (b0 >> 2) & 0x3F
    let c1 = ((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)
    let c2 = (b1 & 0x0F) << 2

    result = result + get_encode_char(base64url_chars[c0])
    result = result + get_encode_char(base64url_chars[c1])
    result = result + get_encode_char(base64url_chars[c2])
  } else if remaining == 1 {
    let b0 = data[i].reinterpret_as_int()

    let c0 = (b0 >> 2) & 0x3F
    let c1 = (b0 & 0x03) << 4

    result = result + get_encode_char(base64url_chars[c0])
    result = result + get_encode_char(base64url_chars[c1])
  }

  result
}

pub fn base64url_encode_string(s: String) -> String {
  let bytes = string_to_bytes_filtered(s)
  let uints : Array[UInt] = []
  for b in bytes {
    uints.push(b.reinterpret_as_uint())
  }
  base64url_encode(uints)
}

pub fn base64url_decode(encoded: String) -> Array[UInt] {
  let chars = string_to_bytes_filtered(encoded)
  let result : Array[UInt] = []
  let len = chars.length()
  let mut i = 0

  while i + 3 < len {
    let c0 = get_decode_value(chars[i])
    let c1 = get_decode_value(chars[i + 1])
    let c2 = get_decode_value(chars[i + 2])
    let c3 = get_decode_value(chars[i + 3])

    if c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0 {
      break
    }

    let b0 = ((c0 << 2) | (c1 >> 4)) & 0xFF
    let b1 = ((c1 << 4) | (c2 >> 2)) & 0xFF
    let b2 = ((c2 << 6) | c3) & 0xFF

    result.push(b0.reinterpret_as_uint())
    result.push(b1.reinterpret_as_uint())
    result.push(b2.reinterpret_as_uint())

    i = i + 4
  }

  let remaining = len - i
  if remaining == 3 {
    let c0 = get_decode_value(chars[i])
    let c1 = get_decode_value(chars[i + 1])
    let c2 = get_decode_value(chars[i + 2])

    if c0 >= 0 && c1 >= 0 && c2 >= 0 {
      let b0 = ((c0 << 2) | (c1 >> 4)) & 0xFF
      let b1 = ((c1 << 4) | (c2 >> 2)) & 0xFF
      result.push(b0.reinterpret_as_uint())
      result.push(b1.reinterpret_as_uint())
    }
  } else if remaining == 2 {
    let c0 = get_decode_value(chars[i])
    let c1 = get_decode_value(chars[i + 1])

    if c0 >= 0 && c1 >= 0 {
      let b0 = ((c0 << 2) | (c1 >> 4)) & 0xFF
      result.push(b0.reinterpret_as_uint())
    }
  }

  result
}

pub fn base64url_decode_to_string(encoded: String) -> String {
  let bytes = base64url_decode(encoded)
  let mut result = ""
  for b in bytes {
    result = result + b.reinterpret_as_int().unsafe_to_char().to_string()
  }
  result
}
