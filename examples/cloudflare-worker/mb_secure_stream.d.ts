// TypeScript type definitions for mb-secure-stream WASM module
// Auto-generated FFI bindings for MoonBit gateway functions

/**
 * Stream context object returned by new_stream_context()
 * Contains authentication state and user metadata after security filter execution
 */
export interface StreamContext {
  /** JWT token string */
  token: string;
  
  /** Whether the request is allowed (true) or blocked (false) */
  is_allowed: boolean;
  
  /** User ID extracted from JWT 'sub' claim */
  user_id: string;
  
  /** User role extracted from JWT 'role' claim (defaults to "guest" if not present) */
  user_role: string;
  
  /** Error message if authentication failed (empty string if successful) */
  error_message: string;
}

/**
 * Creates a new stream context for JWT authentication
 * @param token - JWT token string (without "Bearer " prefix)
 * @returns StreamContext object with initial state
 */
export function new_stream_context(token: string): StreamContext;

/**
 * Executes the security filter on a stream context
 * Performs JWT verification, expiration checks, and claims extraction
 * 
 * @param ctx - StreamContext object created by new_stream_context()
 * @param secret - HMAC-SHA256 secret key for JWT verification (for HS256 tokens)
 * @param current_time - Current Unix timestamp in seconds (use Math.floor(Date.now() / 1000))
 * 
 * Side effects:
 * - Updates ctx.is_allowed to true if token is valid, false otherwise
 * - Updates ctx.user_id with the 'sub' claim value
 * - Updates ctx.user_role with the 'role' claim value (or "guest" if not present)
 * - Updates ctx.error_message with error details if validation fails
 */
export function execute_security_filter(
  ctx: StreamContext,
  secret: string,
  current_time: number
): void;

/**
 * AEAD encryption function (ChaCha20-Poly1305)
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce (must be unique per message)
 * @param aad - Additional authenticated data (can be empty)
 * @param plaintext - Data to encrypt
 * @returns Tuple of [ciphertext, 16-byte authentication tag]
 */
export function aead_encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array
): [Uint8Array, Uint8Array];

/**
 * AEAD decryption function (ChaCha20-Poly1305)
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce (must match encryption nonce)
 * @param aad - Additional authenticated data (must match encryption AAD)
 * @param ciphertext - Encrypted data
 * @param tag - 16-byte authentication tag from encryption
 * @returns Decrypted plaintext, or throws error if authentication fails
 */
export function aead_decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array
): Uint8Array;
