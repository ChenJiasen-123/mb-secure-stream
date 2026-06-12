// P-256 field arithmetic (mod p) using Montgomery form with 8x32-bit limbs.
//
// p = 2^224(2^32 - 1) + 2^192 + 2^96 - 1
//   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
//
// Elements stored in Montgomery form: a_mont = a * R mod p, where R = 2^256.
// The Montgomery parameter p' = 1, which simplifies reduction.

// Field modulus p (little-endian limbs)
let field_p : FixedArray[UInt] = [
  0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U,
  0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU,
]

// R^2 mod p (for converting to Montgomery form)
let field_r2 : FixedArray[UInt] = [
  0x00000003U, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFBU,
  0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFDU, 0x00000004U,
]

// Montgomery form of 1: R mod p
let field_one : FixedArray[UInt] = [
  0x00000001U, 0x00000000U, 0x00000000U, 0xFFFFFFFFU,
  0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU, 0x00000000U,
]

// Zero element
let field_zero : FixedArray[UInt] = [
  0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U,
  0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U,
]

/// Create a new field element (8 limbs, little-endian).
fn fe_new() -> FixedArray[UInt] {
  FixedArray::make(8, 0U)
}

/// Copy a field element.
fn fe_copy(a : FixedArray[UInt]) -> FixedArray[UInt] {
  let r = fe_new()
  for i in 0..<8 {
    r[i] = a[i]
  }
  r
}

/// Widening multiply-add: a * b + c + carry -> (lo, hi)
fn carrying_mul_add(a : UInt, b : UInt, c : UInt, carry : UInt) -> (UInt, UInt) {
  let wide = a.to_uint64() * b.to_uint64() + c.to_uint64() + carry.to_uint64()
  let lo = (wide & 0xFFFFFFFFUL).to_uint()
  let hi = ((wide >> 32) & 0xFFFFFFFFUL).to_uint()
  (lo, hi)
}

/// Add with carry: a + b + carry -> (sum, carry_out)
fn carrying_add(a : UInt, b : UInt, carry : UInt) -> (UInt, UInt) {
  let wide = a.to_uint64() + b.to_uint64() + carry.to_uint64()
  let lo = (wide & 0xFFFFFFFFUL).to_uint()
  let hi = ((wide >> 32) & 0xFFFFFFFFUL).to_uint()
  (lo, hi)
}

/// Subtract with borrow: a - b - borrow -> (diff, borrow_out)
fn carrying_sub(a : UInt, b : UInt, borrow : UInt) -> (UInt, UInt) {
  let wide = a.to_uint64().reinterpret_as_int64() - b.to_uint64().reinterpret_as_int64() - borrow.to_uint64().reinterpret_as_int64()
  let lo = (wide.reinterpret_as_uint64() & 0xFFFFFFFFUL).to_uint()
  let borrow_out = if wide < 0L { 1U } else { 0U }
  (lo, borrow_out)
}

/// Field addition: r = a + b mod p
fn fe_add(a : FixedArray[UInt], b : FixedArray[UInt]) -> FixedArray[UInt] {
  let r = fe_new()
  let mut carry = 0U
  for i in 0..<8 {
    let (sum, c) = carrying_add(a[i], b[i], carry)
    r[i] = sum
    carry = c
  }
  // Subtract p if needed (constant-time)
  fe_sub_p_if_needed(r, carry)
}

/// Conditionally subtract p: if carry != 0 or r >= p, subtract p.
fn fe_sub_p_if_needed(r : FixedArray[UInt], carry : UInt) -> FixedArray[UInt] {
  let result = fe_new()
  let mut borrow = 0U
  for i in 0..<8 {
    let (d, b) = carrying_sub(r[i], field_p[i], borrow)
    result[i] = d
    borrow = b
  }
  // If carry == 0 and borrow == 1, the subtraction underflowed -> use original r
  // If carry == 1 or borrow == 0, use the subtracted result
  let use_original = if carry == 0U && borrow == 1U { 0xFFFFFFFFU } else { 0U }
  let out = fe_new()
  for i in 0..<8 {
    out[i] = (r[i] & use_original) | (result[i] & use_original.lnot())
  }
  out
}

/// Field subtraction: r = a - b mod p
fn fe_sub(a : FixedArray[UInt], b : FixedArray[UInt]) -> FixedArray[UInt] {
  let r = fe_new()
  let mut borrow = 0U
  for i in 0..<8 {
    let (d, b2) = carrying_sub(a[i], b[i], borrow)
    r[i] = d
    borrow = b2
  }
  // If borrow, add p (constant-time)
  let mask = if borrow != 0U { 0xFFFFFFFFU } else { 0U }
  let mut carry = 0U
  let out = fe_new()
  for i in 0..<8 {
    let (sum, c) = carrying_add(r[i], field_p[i] & mask, carry)
    out[i] = sum
    carry = c
  }
  out
}

/// Field negation: r = -a mod p
fn fe_neg(a : FixedArray[UInt]) -> FixedArray[UInt] {
  fe_sub(field_zero, a)
}

/// Montgomery multiplication: r = a * b * R^{-1} mod p
/// Uses the special structure of p where p' = 1.
fn fe_mul(a : FixedArray[UInt], b : FixedArray[UInt]) -> FixedArray[UInt] {
  // Schoolbook multiply: 256x256 -> 512-bit product
  let t = FixedArray::make(16, 0U)

  for i in 0..<8 {
    let mut carry = 0U
    for j in 0..<8 {
      let (lo, hi) = carrying_mul_add(a[i], b[j], t[i + j], carry)
      t[i + j] = lo
      carry = hi
    }
    t[i + 8] = carry
  }

  // Montgomery reduction using p' = 1
  // For each iteration i from 0 to 7:
  //   k = t[i] * p' = t[i] (since p' = 1)
  //   t = t + k * p * 2^(32*i)
  // Then result = t >> 256
  montgomery_reduce(t)
}

/// Montgomery reduction of a 512-bit value.
/// Exploits the special structure of p:
///   p = [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 1, 0xFFFFFFFF]
fn montgomery_reduce(t : FixedArray[UInt]) -> FixedArray[UInt] {
  // Use 17 limbs to handle overflow during reduction
  let r = FixedArray::make(17, 0U)
  for i in 0..<16 {
    r[i] = t[i]
  }

  for i in 0..<8 {
    let k = r[i] // p' = 1, so k = t[i]

    // Add k * p at position i
    // p[0] = 0xFFFFFFFF, p[1] = 0xFFFFFFFF, p[2] = 0xFFFFFFFF
    // p[3] = 0, p[4] = 0, p[5] = 0
    // p[6] = 1, p[7] = 0xFFFFFFFF
    let mut carry = 0U

    // Multiply k by p[0] = 0xFFFFFFFF and add to r[i]
    let (lo0, hi0) = carrying_mul_add(k, 0xFFFFFFFFU, r[i], 0U)
    r[i] = lo0
    carry = hi0

    // k * p[1] = k * 0xFFFFFFFF
    let (lo1, hi1) = carrying_mul_add(k, 0xFFFFFFFFU, r[i + 1], carry)
    r[i + 1] = lo1
    carry = hi1

    // k * p[2] = k * 0xFFFFFFFF
    let (lo2, hi2) = carrying_mul_add(k, 0xFFFFFFFFU, r[i + 2], carry)
    r[i + 2] = lo2
    carry = hi2

    // k * p[3] = 0, just propagate carry
    let (lo3, hi3) = carrying_add(r[i + 3], carry, 0U)
    r[i + 3] = lo3
    carry = hi3

    // k * p[4] = 0
    let (lo4, hi4) = carrying_add(r[i + 4], carry, 0U)
    r[i + 4] = lo4
    carry = hi4

    // k * p[5] = 0
    let (lo5, hi5) = carrying_add(r[i + 5], carry, 0U)
    r[i + 5] = lo5
    carry = hi5

    // k * p[6] = k * 1
    let (lo6, hi6) = carrying_mul_add(k, 1U, r[i + 6], carry)
    r[i + 6] = lo6
    carry = hi6

    // k * p[7] = k * 0xFFFFFFFF
    let (lo7, hi7) = carrying_mul_add(k, 0xFFFFFFFFU, r[i + 7], carry)
    r[i + 7] = lo7

    // Propagate final carry through remaining limbs
    let mut final_carry = hi7
    let mut j = i + 8
    while final_carry != 0U && j < 17 {
      let (lo_fc, hi_fc) = carrying_add(r[j], final_carry, 0U)
      r[j] = lo_fc
      final_carry = hi_fc
      j = j + 1
    }
  }

  // Result is r[8..16], with possible overflow in r[16]
  let result = fe_new()
  for i in 0..<8 {
    result[i] = r[i + 8]
  }
  fe_sub_p_if_needed(result, r[16])
}

/// Field squaring: r = a^2 * R^{-1} mod p
fn fe_sqr(a : FixedArray[UInt]) -> FixedArray[UInt] {
  fe_mul(a, a)
}

/// Convert to Montgomery form: a_mont = a * R mod p = a * R^2 * R^{-1} mod p
fn fe_to_mont(a : FixedArray[UInt]) -> FixedArray[UInt] {
  fe_mul(a, field_r2)
}

/// Convert from Montgomery form: a = a_mont * R^{-1} mod p = a_mont * 1 * R^{-1} mod p
fn fe_from_mont(a : FixedArray[UInt]) -> FixedArray[UInt] {
  let one = fe_new()
  one[0] = 1U
  fe_mul(a, one)
}

/// Field inversion: r = a^{-1} mod p using Fermat's little theorem: a^{p-2} mod p
/// Uses an addition chain for p-2.
fn fe_inv(a : FixedArray[UInt]) -> FixedArray[UInt] {
  // p - 2 = ffffffff00000001000000000000000000000000fffffffffffffffffffffffd
  // Use square-and-multiply with the binary representation
  // This is not the most efficient addition chain but is correct.
  let mut result = fe_copy(field_one) // 1 in Montgomery form
  let mut base = fe_copy(a)

  // p - 2 in little-endian bits: process each limb from LSB
  let p_minus_2 : FixedArray[UInt] = [
    0xFFFFFFFDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U,
    0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU,
  ]

  for i in 0..<8 {
    let mut limb = p_minus_2[i]
    for _j in 0..<32 {
      if (limb & 1U) != 0U {
        result = fe_mul(result, base)
      }
      base = fe_sqr(base)
      limb = limb >> 1
    }
  }
  result
}

/// Field square root: r = a^{(p+1)/4} mod p (valid since p = 3 mod 4)
fn fe_sqrt(a : FixedArray[UInt]) -> FixedArray[UInt] {
  // (p+1)/4 = 3fffffff c0000000 40000000 00000000 00000000 40000000 00000000 00000000
  let exp : FixedArray[UInt] = [
    0x00000000U, 0x00000000U, 0x40000000U, 0x00000000U,
    0x00000000U, 0x40000000U, 0xC0000000U, 0x3FFFFFFFU,
  ]
  let mut result = fe_copy(field_one)
  let mut base = fe_copy(a)
  for i in 0..<8 {
    let mut limb = exp[i]
    for _j in 0..<32 {
      if (limb & 1U) != 0U {
        result = fe_mul(result, base)
      }
      base = fe_sqr(base)
      limb = limb >> 1
    }
  }
  result
}

/// Check if a field element is zero.
fn fe_is_zero(a : FixedArray[UInt]) -> Bool {
  let mut acc = 0U
  for i in 0..<8 {
    acc = acc | a[i]
  }
  acc == 0U
}

/// Check if two field elements are equal.
fn fe_eq(a : FixedArray[UInt], b : FixedArray[UInt]) -> Bool {
  let mut acc = 0U
  for i in 0..<8 {
    acc = acc | (a[i] ^ b[i])
  }
  acc == 0U
}

/// Conditional select: if choice == 1, return b; else return a. Constant-time.
fn fe_select(a : FixedArray[UInt], b : FixedArray[UInt], choice : UInt) -> FixedArray[UInt] {
  let mask = (0U - choice) // 0xFFFFFFFF if choice==1, 0 if choice==0
  let r = fe_new()
  for i in 0..<8 {
    r[i] = a[i] ^ (mask & (a[i] ^ b[i]))
  }
  r
}

/// Convert 32 bytes (big-endian) to field element limbs (little-endian).
fn fe_from_bytes(bytes : Array[UInt]) -> FixedArray[UInt] {
  let r = fe_new()
  for i in 0..<8 {
    let base = (7 - i) * 4
    r[i] = (bytes[base + 3] & 0xFFU) |
      ((bytes[base + 2] & 0xFFU) << 8) |
      ((bytes[base + 1] & 0xFFU) << 16) |
      ((bytes[base] & 0xFFU) << 24)
  }
  r
}

/// Convert field element limbs (little-endian) to 32 bytes (big-endian).
fn fe_to_bytes(a : FixedArray[UInt]) -> Array[UInt] {
  let bytes : Array[UInt] = Array::make(32, 0U)
  for i in 0..<8 {
    let base = (7 - i) * 4
    bytes[base] = (a[i] >> 24) & 0xFFU
    bytes[base + 1] = (a[i] >> 16) & 0xFFU
    bytes[base + 2] = (a[i] >> 8) & 0xFFU
    bytes[base + 3] = a[i] & 0xFFU
  }
  bytes
}

/// Check if the field element (non-Montgomery) is less than p.
fn fe_is_valid(a : FixedArray[UInt]) -> Bool {
  // Compare from MSB to LSB
  let mut i = 7
  while i >= 0 {
    if a[i] < field_p[i] {
      return true
    }
    if a[i] > field_p[i] {
      return false
    }
    i = i - 1
  }
  false // equal to p is not valid
}

