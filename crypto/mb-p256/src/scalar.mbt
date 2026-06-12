// P-256 scalar arithmetic (mod n) using Barrett reduction with 8x32-bit limbs.
//
// n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
// (the order of the P-256 generator point)

// Group order n (little-endian limbs)
let scalar_n : FixedArray[UInt] = [
  0xFC632551U, 0xF3B9CAC2U, 0xA7179E84U, 0xBCE6FAADU,
  0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU,
]

// Barrett constant MU = floor(2^512 / n), 9 limbs (little-endian)
let scalar_mu : FixedArray[UInt] = [
  0xEEDF9BFEU, 0x012FFD85U, 0xDF1A6C21U, 0x43190552U,
  0xFFFFFFFFU, 0xFFFFFFFEU, 0xFFFFFFFFU, 0x00000000U,
  0x00000001U,
]

/// Create a new scalar (8 limbs).
fn sc_new() -> FixedArray[UInt] {
  FixedArray::make(8, 0U)
}

/// Copy a scalar.
fn sc_copy(a : FixedArray[UInt]) -> FixedArray[UInt] {
  let r = sc_new()
  for i in 0..<8 {
    r[i] = a[i]
  }
  r
}

/// Check if scalar is zero.
fn sc_is_zero(a : FixedArray[UInt]) -> Bool {
  let mut acc = 0U
  for i in 0..<8 {
    acc = acc | a[i]
  }
  acc == 0U
}

/// Scalar addition: r = a + b mod n
fn sc_add(a : FixedArray[UInt], b : FixedArray[UInt]) -> FixedArray[UInt] {
  let r = sc_new()
  let mut carry = 0U
  for i in 0..<8 {
    let (sum, c) = carrying_add(a[i], b[i], carry)
    r[i] = sum
    carry = c
  }
  // Subtract n if needed
  sc_sub_n_if_needed(r, carry)
}

/// Conditionally subtract n.
fn sc_sub_n_if_needed(r : FixedArray[UInt], carry : UInt) -> FixedArray[UInt] {
  let result = sc_new()
  let mut borrow = 0U
  for i in 0..<8 {
    let (d, b) = carrying_sub(r[i], scalar_n[i], borrow)
    result[i] = d
    borrow = b
  }
  let use_original = if carry == 0U && borrow == 1U { 0xFFFFFFFFU } else { 0U }
  let out = sc_new()
  for i in 0..<8 {
    out[i] = (r[i] & use_original) | (result[i] & use_original.lnot())
  }
  out
}

/// Scalar subtraction: r = a - b mod n
fn sc_sub(a : FixedArray[UInt], b : FixedArray[UInt]) -> FixedArray[UInt] {
  let r = sc_new()
  let mut borrow = 0U
  for i in 0..<8 {
    let (d, b2) = carrying_sub(a[i], b[i], borrow)
    r[i] = d
    borrow = b2
  }
  let mask = if borrow != 0U { 0xFFFFFFFFU } else { 0U }
  let mut carry = 0U
  let out = sc_new()
  for i in 0..<8 {
    let (sum, c) = carrying_add(r[i], scalar_n[i] & mask, carry)
    out[i] = sum
    carry = c
  }
  out
}

/// Scalar negation: r = -a mod n
fn sc_neg(a : FixedArray[UInt]) -> FixedArray[UInt] {
  if sc_is_zero(a) {
    return sc_copy(a)
  }
  sc_sub(scalar_n, a)
}

/// Scalar multiplication: r = a * b mod n using Barrett reduction.
fn sc_mul(a : FixedArray[UInt], b : FixedArray[UInt]) -> FixedArray[UInt] {
  // Schoolbook multiply: 256x256 -> 512-bit product (16 limbs)
  let t = FixedArray::make(17, 0U) // extra limb for safety

  for i in 0..<8 {
    let mut carry = 0U
    for j in 0..<8 {
      let (lo, hi) = carrying_mul_add(a[i], b[j], t[i + j], carry)
      t[i + j] = lo
      carry = hi
    }
    t[i + 8] = carry
  }

  barrett_reduce(t)
}

/// Barrett reduction of a 512-bit value to mod n.
fn barrett_reduce(t : FixedArray[UInt]) -> FixedArray[UInt] {
  // Step 1: q1 = t >> 224 (top 9 limbs starting at limb 7)
  let q1 = FixedArray::make(9, 0U)
  for i in 0..<9 {
    if i + 7 < 17 {
      q1[i] = t[i + 7]
    }
  }

  // Step 2: q3 = (q1 * MU) >> 288 (= >> 9*32)
  // q1 is 9 limbs, MU is 9 limbs -> product is 18 limbs
  let q1_mu = FixedArray::make(18, 0U)
  for i in 0..<9 {
    let mut carry = 0U
    for j in 0..<9 {
      let (lo, hi) = carrying_mul_add(q1[i], scalar_mu[j], q1_mu[i + j], carry)
      q1_mu[i + j] = lo
      carry = hi
    }
    q1_mu[i + 9] = carry
  }

  let q3 = FixedArray::make(9, 0U)
  for i in 0..<9 {
    if i + 9 < 18 {
      q3[i] = q1_mu[i + 9]
    }
  }

  // Step 3: r1 = t mod 2^288 (bottom 9 limbs)
  let r1 = FixedArray::make(9, 0U)
  for i in 0..<9 {
    if i < 17 {
      r1[i] = t[i]
    }
  }

  // Step 4: r2 = (q3 * n) mod 2^288 (bottom 9 limbs)
  let r2 = FixedArray::make(9, 0U)
  for i in 0..<9 {
    let mut carry = 0U
    for j in 0..<8 {
      if i + j < 9 {
        let (lo, hi) = carrying_mul_add(q3[i], scalar_n[j], r2[i + j], carry)
        r2[i + j] = lo
        carry = hi
      } else {
        break
      }
    }
    // Propagate remaining carry into the next position (if within bounds)
    let next_pos = i + 8 // position after the last n limb
    if next_pos < 9 && carry != 0U {
      let (lo, _) = carrying_add(r2[next_pos], carry, 0U)
      r2[next_pos] = lo
    }
  }

  // Step 5: r = r1 - r2 (mod 2^288)
  let r = FixedArray::make(9, 0U)
  let mut borrow = 0U
  for i in 0..<9 {
    let (d, b) = carrying_sub(r1[i], r2[i], borrow)
    r[i] = d
    borrow = b
  }

  // Step 6: While r >= n, subtract n (at most twice).
  // r[8] may be nonzero (meaning r >= 2^256), so pass it as carry.
  let result = sc_new()
  for i in 0..<8 {
    result[i] = r[i]
  }
  let r1_reduced = sc_sub_n_if_needed(result, r[8])
  sc_sub_n_if_needed(r1_reduced, 0U)
}

/// Scalar inversion: r = a^{-1} mod n using Fermat's little theorem: a^{n-2} mod n
fn sc_inv(a : FixedArray[UInt]) -> FixedArray[UInt] {
  // n - 2 = ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f
  let n_minus_2 : FixedArray[UInt] = [
    0xFC63254FU, 0xF3B9CAC2U, 0xA7179E84U, 0xBCE6FAADU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU,
  ]
  let mut result = sc_new()
  result[0] = 1U
  let mut base = sc_copy(a)

  for i in 0..<8 {
    let mut limb = n_minus_2[i]
    for _j in 0..<32 {
      if (limb & 1U) != 0U {
        result = sc_mul(result, base)
      }
      base = sc_mul(base, base)
      limb = limb >> 1
    }
  }
  result
}

/// Convert 32 bytes (big-endian) to scalar limbs (little-endian).
fn sc_from_bytes(bytes : Array[UInt]) -> FixedArray[UInt] {
  fe_from_bytes(bytes) // Same layout
}

/// Convert scalar limbs (little-endian) to 32 bytes (big-endian).
fn sc_to_bytes(a : FixedArray[UInt]) -> Array[UInt] {
  fe_to_bytes(a) // Same layout
}

/// Check if scalar is in valid range [1, n-1].
fn sc_is_valid(a : FixedArray[UInt]) -> Bool {
  if sc_is_zero(a) {
    return false
  }
  // Check a < n
  let mut i = 7
  while i >= 0 {
    if a[i] < scalar_n[i] {
      return true
    }
    if a[i] > scalar_n[i] {
      return false
    }
    i = i - 1
  }
  false // equal to n is not valid
}

/// Reduce a scalar mod n (for values that might be >= n).
fn sc_reduce(a : FixedArray[UInt]) -> FixedArray[UInt] {
  sc_sub_n_if_needed(a, 0U)
}
