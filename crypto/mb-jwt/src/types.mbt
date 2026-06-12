// crypto/mb-jwt/src/types.mbt

///| Represents the standard JWT Header as defined in the RFC 7515 specification.
pub struct JWTHeader {
  alg : String 
  typ : String 
} derive(ToJson, FromJson, Show, Eq)

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
} derive(ToJson, FromJson, Show, Eq)

///| The final combined, strongly-typed standard JSON Web Token object.
pub struct JWT {
  header : JWTHeader
  payload : JWTPayload
  signature : String
} derive(Show, Eq)