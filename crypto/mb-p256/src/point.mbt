// P-256 elliptic curve point operations.
// Uses projective coordinates with complete addition formulas from
// Renes-Costello-Batina 2015 (specialized for a = -3).
//
// Curve equation: y^2 = x^3 - 3x + b (mod p)
// b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

// Curve coefficient b in Montgomery form
let curve_b_mont : FixedArray[UInt] = FixedArray::make(8, 0U)

// Generator point Gx (raw, big-endian hex bytes -> little-endian limbs)
let gen_x_raw : FixedArray[UInt] = [
  0xD898C296U, 0xF4A13945U, 0x2DEB33A0U, 0x77037D81U,
  0x63A440F2U, 0xF8BCE6E5U, 0xE12C4247U, 0x6B17D1F2U,
]

let gen_y_raw : FixedArray[UInt] = [
  0x37BF51F5U, 0xCBB64068U, 0x6B315ECEU, 0x2BCE3357U,
  0x7C0F9E16U, 0x8EE7EB4AU, 0xFE1A7F9BU, 0x4FE342E2U,
]

let curve_b_raw : FixedArray[UInt] = [
  0x27D2604BU, 0x3BCE3C3EU, 0xCC53B0F6U, 0x651D06B0U,
  0x769886BCU, 0xB3EBBD55U, 0xAA3A93E7U, 0x5AC635D8U,
]

/// Projective point: (X : Y : Z) where affine (x, y) = (X/Z, Y/Z)
/// Identity point: (0 : 1 : 0)
pub struct ProjectivePoint {
  x : FixedArray[UInt]
  y : FixedArray[UInt]
  z : FixedArray[UInt]
}

/// Affine point: (x, y) or identity
pub struct AffinePoint {
  x : FixedArray[UInt]
  y : FixedArray[UInt]
  infinity : Bool
}

/// Create the identity point in projective coordinates.
fn point_identity() -> ProjectivePoint {
  ProjectivePoint::{
    x: fe_copy(field_zero),
    y: fe_copy(field_one), // 1 in Montgomery form
    z: fe_copy(field_zero),
  }
}

/// Create the generator point.
fn point_generator() -> ProjectivePoint {
  let gx = fe_to_mont(gen_x_raw)
  let gy = fe_to_mont(gen_y_raw)
  ProjectivePoint::{
    x: gx,
    y: gy,
    z: fe_copy(field_one),
  }
}

/// Check if a projective point is the identity.
fn point_is_identity(p : ProjectivePoint) -> Bool {
  fe_is_zero(p.z)
}

/// Convert projective to affine.
fn point_to_affine(p : ProjectivePoint) -> AffinePoint {
  if point_is_identity(p) {
    return AffinePoint::{
      x: fe_copy(field_zero),
      y: fe_copy(field_zero),
      infinity: true,
    }
  }
  let z_inv = fe_inv(p.z)
  let x = fe_mul(p.x, z_inv)
  let y = fe_mul(p.y, z_inv)
  AffinePoint::{
    x: fe_from_mont(x),
    y: fe_from_mont(y),
    infinity: false,
  }
}

/// Convert affine to projective.
fn affine_to_projective(p : AffinePoint) -> ProjectivePoint {
  if p.infinity {
    return point_identity()
  }
  ProjectivePoint::{
    x: fe_to_mont(p.x),
    y: fe_to_mont(p.y),
    z: fe_copy(field_one),
  }
}

/// Get curve_b in Montgomery form (lazy init pattern).
fn get_curve_b_mont() -> FixedArray[UInt] {
  fe_to_mont(curve_b_raw)
}

/// Get the a coefficient (-3) in Montgomery form.
fn get_curve_a_mont() -> FixedArray[UInt] {
  // a = -3 = p - 3 in the field
  let three = fe_new()
  three[0] = 3U
  let a_raw = fe_new()
  let mut borrow = 0U
  for i in 0..<8 {
    let (d, b) = carrying_sub(field_p[i], three[i], borrow)
    a_raw[i] = d
    borrow = b
  }
  fe_to_mont(a_raw)
}

/// Complete point addition using Renes-Costello-Batina formulas for a = -3.
/// Algorithm 4 from https://eprint.iacr.org/2015/1060
fn point_add(
  p1 : ProjectivePoint,
  p2 : ProjectivePoint,
) -> ProjectivePoint {
  let b3 = fe_add(get_curve_b_mont(), fe_add(get_curve_b_mont(), get_curve_b_mont()))

  let t0 = fe_mul(p1.x, p2.x)
  let t1 = fe_mul(p1.y, p2.y)
  let t2 = fe_mul(p1.z, p2.z)
  let t3 = fe_add(p1.x, p1.y)
  let t4 = fe_add(p2.x, p2.y)
  let t3b = fe_mul(t3, t4)
  let t4b = fe_add(t0, t1)
  let t3c = fe_sub(t3b, t4b)
  let t4c = fe_add(p1.x, p1.z)
  let t5 = fe_add(p2.x, p2.z)
  let t4d = fe_mul(t4c, t5)
  let t5b = fe_add(t0, t2)
  let t4e = fe_sub(t4d, t5b)
  let t5c = fe_add(p1.y, p1.z)
  let x3 = fe_add(p2.y, p2.z)
  let t5d = fe_mul(t5c, x3)
  let x3b = fe_add(t1, t2)
  let t5e = fe_sub(t5d, x3b)
  // a = -3, so a*t4 = -3*t4 = -(t4+t4+t4)
  let z3 = fe_mul(get_curve_a_mont(), t4e)
  let x3c = fe_mul(b3, t2)
  let z3b = fe_add(x3c, z3)
  let x3d = fe_sub(t1, z3b)
  let z3c = fe_add(t1, z3b)
  let y3 = fe_mul(x3d, z3c)
  let t1b = fe_add(t0, t0)
  let t1c = fe_add(t1b, t0)
  // a*t2 = -3*t2
  let t2b = fe_mul(get_curve_a_mont(), t2)
  let t4f = fe_mul(b3, t4e)
  let t1d = fe_add(t1c, t2b)
  let t2c = fe_sub(t0, t2b)
  // a*t2c = -3*t2c
  let t2d = fe_mul(get_curve_a_mont(), t2c)
  let t4g = fe_add(t4f, t2d)
  let t0b = fe_mul(t1d, t4g)
  let y3b = fe_add(y3, t0b)
  let t0c = fe_mul(t5e, t4g)
  let x3e = fe_mul(t3c, x3d)
  let x3f = fe_sub(x3e, t0c)
  let t0d = fe_mul(t3c, t1d)
  let z3d = fe_mul(t5e, z3c)
  let z3e = fe_add(z3d, t0d)

  ProjectivePoint::{ x: x3f, y: y3b, z: z3e }
}

/// Point doubling using Renes-Costello-Batina formulas (dbl-2015-rcb).
/// From https://hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2015-rcb
fn point_double(p : ProjectivePoint) -> ProjectivePoint {
  let b3 = fe_add(get_curve_b_mont(), fe_add(get_curve_b_mont(), get_curve_b_mont()))

  let t0 = fe_sqr(p.x)           // t0 = X1^2
  let t1 = fe_sqr(p.y)           // t1 = Y1^2
  let t2 = fe_sqr(p.z)           // t2 = Z1^2
  let t3 = fe_mul(p.x, p.y)      // t3 = X1*Y1
  let t3b = fe_add(t3, t3)       // t3 = t3+t3
  let z3 = fe_mul(p.x, p.z)      // Z3 = X1*Z1
  let z3b = fe_add(z3, z3)       // Z3 = Z3+Z3
  let x3 = fe_mul(get_curve_a_mont(), z3b) // X3 = a*Z3
  let y3 = fe_mul(b3, t2)        // Y3 = b3*t2
  let y3b = fe_add(x3, y3)       // Y3 = X3+Y3
  let x3b = fe_sub(t1, y3b)      // X3 = t1-Y3
  let y3c = fe_add(t1, y3b)      // Y3 = t1+Y3
  let y3d = fe_mul(x3b, y3c)     // Y3 = X3*Y3
  let x3c = fe_mul(t3b, x3b)     // X3 = t3*X3
  let z3c = fe_mul(b3, z3b)      // Z3 = b3*Z3
  let t2b = fe_mul(get_curve_a_mont(), t2) // t2 = a*t2
  let t3c = fe_sub(t0, t2b)      // t3 = t0-t2
  let t3d = fe_mul(get_curve_a_mont(), t3c) // t3 = a*t3
  let t3e = fe_add(t3d, z3c)     // t3 = t3+Z3
  let z3d = fe_add(t0, t0)       // Z3 = t0+t0
  let t0b = fe_add(z3d, t0)      // t0 = Z3+t0
  let t0c = fe_add(t0b, t2b)     // t0 = t0+t2
  let t0d = fe_mul(t0c, t3e)     // t0 = t0*t3
  let y3e = fe_add(y3d, t0d)     // Y3 = Y3+t0
  let t2c = fe_mul(p.y, p.z)     // t2 = Y1*Z1
  let t2d = fe_add(t2c, t2c)     // t2 = t2+t2
  let t0e = fe_mul(t2d, t3e)     // t0 = t2*t3
  let x3d = fe_sub(x3c, t0e)     // X3 = X3-t0
  let z3e = fe_mul(t2d, t1)      // Z3 = t2*t1
  let z3f = fe_add(z3e, z3e)     // Z3 = Z3+Z3
  let z3g = fe_add(z3f, z3f)     // Z3 = Z3+Z3

  ProjectivePoint::{ x: x3d, y: y3e, z: z3g }
}

/// Scalar multiplication: compute k * P using 4-bit windowed method.
/// Constant-time: always performs the same sequence of operations.
fn point_mul(
  k : FixedArray[UInt],
  p : ProjectivePoint,
) -> ProjectivePoint {
  // Build lookup table: table[i] = i * P for i in 0..16
  let table : Array[ProjectivePoint] = []
  table.push(point_identity()) // 0*P
  table.push(ProjectivePoint::{ x: fe_copy(p.x), y: fe_copy(p.y), z: fe_copy(p.z) }) // 1*P
  let mut prev = table[1]
  for _i in 2..<16 {
    prev = point_add(prev, p)
    table.push(ProjectivePoint::{ x: fe_copy(prev.x), y: fe_copy(prev.y), z: fe_copy(prev.z) })
  }

  // Process scalar 4 bits at a time from MSB to LSB
  let mut result = point_identity()

  // 256 bits = 64 nybbles, process from top
  let mut nybble_idx = 63
  while nybble_idx >= 0 {
    // Double 4 times
    if nybble_idx < 63 {
      result = point_double(result)
      result = point_double(result)
      result = point_double(result)
      result = point_double(result)
    }

    // Extract 4-bit window from scalar
    let limb_idx = (nybble_idx * 4) / 32
    let bit_idx = (nybble_idx * 4) % 32
    let window = (k[limb_idx] >> bit_idx) & 0xFU

    // Constant-time table lookup: scan all entries
    let mut selected = point_identity()
    for i in 1..<16 {
      let eq = if window == i.reinterpret_as_uint() { 1U } else { 0U }
      selected = ProjectivePoint::{
        x: fe_select(selected.x, table[i].x, eq),
        y: fe_select(selected.y, table[i].y, eq),
        z: fe_select(selected.z, table[i].z, eq),
      }
    }

    result = point_add(result, selected)
    nybble_idx = nybble_idx - 1
  }
  result
}

/// Double scalar multiplication: compute u1*G + u2*Q (for ECDSA verify).
fn point_mul2(
  u1 : FixedArray[UInt],
  u2 : FixedArray[UInt],
  q : ProjectivePoint,
) -> ProjectivePoint {
  let r1 = point_mul(u1, point_generator())
  let r2 = point_mul(u2, q)
  point_add(r1, r2)
}
