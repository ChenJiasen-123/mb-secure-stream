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

///| Creates a new JWT Header with the given algorithm and type.
///|
///| Example:
///| ```
///| let header = new_jwt_header("HS256", "JWT")
///| ```
pub fn new_jwt_header(alg : String, typ : String) -> JWTHeader {
  { alg, typ }
}

///| Creates a new JWT Payload with the given claims.
///|
///| All claims are optional and can be set to `None` if not needed.
///|
///| Example:
///| ```
///| let payload = new_jwt_payload(
///|   Some("issuer"),
///|   Some("subject"),
///|   None,
///|   Some(1000L),
///|   None,
///|   Some(100L),
///|   Some("jwt-id")
///| )
///| ```
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
///|
///| Example:
///| ```
///| let header = new_jwt_header("HS256", "JWT")
///| let payload = new_jwt_payload(Some("sub"), Some("user"), None, None, None, Some(100L), None)
///| let jwt = new_jwt(header, payload, "signature_string")
///| ```
pub fn new_jwt(
  header : JWTHeader,
  payload : JWTPayload,
  signature : String,
) -> JWT {
  { header, payload, signature }
}