// crypto/mb-jwt/src/types.mbt

///| Represents the standard JWT Header as defined in the RFC 7515 specification.
pub struct JWTHeader {
  alg : String // Cryptographic algorithm used for signing, e.g., "HS256", "ES256"
  typ : String // Token type, which is always "JWT"
} derive(ToJson, FromJson, Debug, Eq)

///| Represents the industrial-grade strongly-typed JWT Claims Set as defined in RFC 7519.
///| Optional fields and timestamps are wrapped in `Option[Int64]` for rigorous type-safety.
pub struct JWTPayload {
  iss : Option[String] // Issuer: Identifies the principal that issued the JWT
  sub : Option[String] // Subject: Identifies the principal that is the subject of the JWT (e.g., User ID)
  aud : Option[String] // Audience: Identifies the recipients that the JWT is intended for
  exp : Option[Int64]  // Expiration Time: Unix timestamp (in seconds) after which the token must be rejected
  nbf : Option[Int64]  // Not Before: Unix timestamp (in seconds) before which the token must not be accepted
  iat : Option[Int64]  // Issued At: Unix timestamp (in seconds) indicating when the JWT was created
  jti : Option[String] // JWT ID: Unique identifier for the token, used primarily to prevent replay attacks
} derive(ToJson, FromJson, Debug, Eq)

///| The final combined, strongly-typed standard JSON Web Token object.
pub struct JWT {
  header : JWTHeader
  payload : JWTPayload
  signature : String
} derive(Debug, Eq)

///| A type-safe key enum that binds the signing algorithm to its required key material.
///| This prevents callers from accidentally passing the wrong type of key (e.g., using
///| an HMAC secret where an ECDSA private key is expected).
///|
///| Variants:
///| - `HS256(String)`: Symmetric HMAC-SHA256 secret key
///| - `ES256(Array[UInt])`: Asymmetric ECDSA P-256 private key (32 bytes, big-endian)
pub(all) enum JwtKey {
  HS256(String)
  ES256(Array[UInt])
} derive(Debug, Eq, Show)

///| Represents all errors that can occur during JWT operations.
pub enum JWTError {
  InvalidFormat                    // TOken does not have the correct "header.payload.signature" format
  InvalidSignature                 // Signature verification failed (e.g., HMAC mismatch, ECDSA signature invalid)
  AlgorithmMismatch(String)        // Header "alg" field does not match the expected algorithm (e.g., "HS256" vs "ES256")
  CryptoError(String)              // Underlying cryptography library computation failed (e.g., ECDSA operation failed)
  TokenExpired(Int64, Int64)       // Token has expired (current time, expiration time)
  TokenNotYetValid(Int64, Int64)   // Token is not yet valid (current time, not before time)
  InvalidIssuer(String)            // Issuer does not match
  InvalidAudience(String)          // Audience does not match
} derive(Debug, Eq, Show)

///| Creates a new JWT Header with the given algorithm and type.
pub fn new_jwt_header(alg : String, typ : String) -> JWTHeader {
  { alg, typ }
}

///| Creates a new JWT Payload with the given claims.
pub fn new_jwt_payload(
  iss : Option[String],
  sub : Option[String],
  aud : Option[String],
  exp : Option[Int64],
  nbf : Option[Int64],
  iat : Option[Int64],
  jti : Option[String],
) -> JWTPayload {
  { iss, sub, aud, exp, nbf, iat, jti }
}

///| Creates a new JWT with the given header, payload, and signature.
pub fn new_jwt(
  header : JWTHeader,
  payload : JWTPayload,
  signature : String,
) -> JWT {
  { header, payload, signature }
}