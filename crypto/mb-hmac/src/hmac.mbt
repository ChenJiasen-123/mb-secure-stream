const IPAD : UInt = 0x36U
const OPAD : UInt = 0x5cU

fn bytes_to_uints(bytes: Bytes) -> Array[UInt] {
  let arr : Array[UInt] = []
  for i in 0..<bytes.length() {
    arr.push(bytes[i].to_int().reinterpret_as_uint())
  }
  arr
}

fn string_to_uints(value: String) -> Array[UInt] {
  let bytes = @utf8.encode(value)
  let arr : Array[UInt] = []
  for i in 0..<bytes.length() {
    arr.push(bytes[i].to_int().reinterpret_as_uint())
  }
  arr
}

fn sha512_words_to_bytes(words: FixedArray[UInt64]) -> Array[UInt] {
  let result = Array::make(64, 0U)
  for i in 0..<8 {
    let w = words[i]
    let base = i * 8
    result[base] = ((w >> 56) & 0xFFUL).to_uint()
    result[base + 1] = ((w >> 48) & 0xFFUL).to_uint()
    result[base + 2] = ((w >> 40) & 0xFFUL).to_uint()
    result[base + 3] = ((w >> 32) & 0xFFUL).to_uint()
    result[base + 4] = ((w >> 24) & 0xFFUL).to_uint()
    result[base + 5] = ((w >> 16) & 0xFFUL).to_uint()
    result[base + 6] = ((w >> 8) & 0xFFUL).to_uint()
    result[base + 7] = (w & 0xFFUL).to_uint()
  }
  result
}

fn sha512_words_to_fixed_bytes(words: FixedArray[UInt64]) -> FixedArray[UInt] {
  let result = FixedArray::make(64, 0U)
  for i in 0..<8 {
    let w = words[i]
    let base = i * 8
    result[base] = ((w >> 56) & 0xFFUL).to_uint()
    result[base + 1] = ((w >> 48) & 0xFFUL).to_uint()
    result[base + 2] = ((w >> 40) & 0xFFUL).to_uint()
    result[base + 3] = ((w >> 32) & 0xFFUL).to_uint()
    result[base + 4] = ((w >> 24) & 0xFFUL).to_uint()
    result[base + 5] = ((w >> 16) & 0xFFUL).to_uint()
    result[base + 6] = ((w >> 8) & 0xFFUL).to_uint()
    result[base + 7] = (w & 0xFFUL).to_uint()
  }
  result
}

fn constant_time_eq_bytes(left: FixedArray[UInt], right: Array[UInt]) -> Bool {
  if right.length() != left.length() {
    return false
  }
  let mut diff : UInt = 0U
  for i in 0..<left.length() {
    diff = diff | (left[i] ^ right[i])
  }
  diff == 0U
}

fn prepare_key_block_sha256(key: Array[UInt]) -> Array[UInt] {
  let block_size = 64
  let block = Array::make(block_size, 0U)
  if key.length() > block_size {
    let key_hash = @sha2.Sha256::digest(key)
    for i in 0..<key_hash.length() {
      block[i] = key_hash[i]
    }
  } else {
    for i in 0..<key.length() {
      block[i] = key[i]
    }
  }
  block
}

fn prepare_key_block_sha512(key: Array[UInt]) -> Array[UInt] {
  let block_size = 128
  let block = Array::make(block_size, 0U)
  if key.length() > block_size {
    let key_hash = @sha2.Sha512::digest(key)
    let key_bytes = sha512_words_to_bytes(key_hash)
    for i in 0..<key_bytes.length() {
      block[i] = key_bytes[i]
    }
  } else {
    for i in 0..<key.length() {
      block[i] = key[i]
    }
  }
  block
}

fn build_pad(block: Array[UInt], pad_value: UInt) -> Array[UInt] {
  let pad = Array::make(block.length(), 0U)
  for i in 0..<block.length() {
    pad[i] = block[i] ^ pad_value
  }
  pad
}

pub fn hmac_sha256(message: Array[UInt], key: Array[UInt]) -> FixedArray[UInt] {
  let key_block = prepare_key_block_sha256(key)
  let inner_pad = build_pad(key_block, IPAD)
  let outer_pad = build_pad(key_block, OPAD)

  let inner_data : Array[UInt] = []
  for i in 0..<inner_pad.length() { inner_data.push(inner_pad[i]) }
  for i in 0..<message.length() { inner_data.push(message[i]) }

  let inner_hash = @sha2.Sha256::digest(inner_data)

  let outer_data : Array[UInt] = []
  for i in 0..<outer_pad.length() { outer_data.push(outer_pad[i]) }
  for i in 0..<inner_hash.length() { outer_data.push(inner_hash[i]) }

  @sha2.Sha256::digest(outer_data)
}

pub fn hmac_sha256_bytes(message: Bytes, key: Bytes) -> FixedArray[UInt] {
  hmac_sha256(bytes_to_uints(message), bytes_to_uints(key))
}

pub fn hmac_sha256_string(message: String, key: String) -> FixedArray[UInt] {
  hmac_sha256(string_to_uints(message), string_to_uints(key))
}

pub fn verify_hmac_sha256(message: Array[UInt], key: Array[UInt], mac: Array[UInt]) -> Bool {
  let expected = hmac_sha256(message, key)
  constant_time_eq_bytes(expected, mac)
}

pub fn verify_hmac_sha256_bytes(message: Bytes, key: Bytes, mac: Array[UInt]) -> Bool {
  verify_hmac_sha256(bytes_to_uints(message), bytes_to_uints(key), mac)
}

pub fn hmac_sha512(message: Array[UInt], key: Array[UInt]) -> FixedArray[UInt] {
  let key_block = prepare_key_block_sha512(key)
  let inner_pad = build_pad(key_block, IPAD)
  let outer_pad = build_pad(key_block, OPAD)

  let inner_data : Array[UInt] = []
  for i in 0..<inner_pad.length() { inner_data.push(inner_pad[i]) }
  for i in 0..<message.length() { inner_data.push(message[i]) }

  let inner_hash_words = @sha2.Sha512::digest(inner_data)
  let inner_hash_bytes = sha512_words_to_bytes(inner_hash_words)

  let outer_data : Array[UInt] = []
  for i in 0..<outer_pad.length() { outer_data.push(outer_pad[i]) }
  for i in 0..<inner_hash_bytes.length() { outer_data.push(inner_hash_bytes[i]) }

  let final_words = @sha2.Sha512::digest(outer_data)
  sha512_words_to_fixed_bytes(final_words)
}

pub fn hmac_sha512_bytes(message: Bytes, key: Bytes) -> FixedArray[UInt] {
  hmac_sha512(bytes_to_uints(message), bytes_to_uints(key))
}

pub fn hmac_sha512_string(message: String, key: String) -> FixedArray[UInt] {
  hmac_sha512(string_to_uints(message), string_to_uints(key))
}

pub fn verify_hmac_sha512(message: Array[UInt], key: Array[UInt], mac: Array[UInt]) -> Bool {
  let expected = hmac_sha512(message, key)
  constant_time_eq_bytes(expected, mac)
}

pub fn verify_hmac_sha512_bytes(message: Bytes, key: Bytes, mac: Array[UInt]) -> Bool {
  verify_hmac_sha512(bytes_to_uints(message), bytes_to_uints(key), mac)
}

pub fn generateMAC(message: Array[UInt], key: Array[UInt]) -> FixedArray[UInt] {
  hmac_sha256(message, key)
}

pub fn generateMAC_bytes(message: Bytes, key: Bytes) -> FixedArray[UInt] {
  hmac_sha256_bytes(message, key)
}

pub fn generateMAC_string(message: String, key: String) -> FixedArray[UInt] {
  hmac_sha256_string(message, key)
}

pub fn verifyMAC(message: Array[UInt], key: Array[UInt], mac: Array[UInt]) -> Bool {
  verify_hmac_sha256(message, key, mac)
}

pub fn verifyMAC_bytes(message: Bytes, key: Bytes, mac: Array[UInt]) -> Bool {
  verify_hmac_sha256_bytes(message, key, mac)
}

pub fn verifyMAC_string(message: String, key: String, mac: Array[UInt]) -> Bool {
  verify_hmac_sha256(string_to_uints(message), string_to_uints(key), mac)
}
