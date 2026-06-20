// Cloudflare Worker — JWT security gateway
// Uses Web Crypto API for HMAC-SHA256 JWT verification (no Wasm dependency)

/// <reference types="@cloudflare/workers-types" />

interface StreamContext {
  is_allowed: boolean;
  error_message: string;
  user_id?: string;
  user_role?: string;
}

interface Env {
  JWT_SECRET: string;       // HMAC-SHA256 secret key for JWT verification
  ALLOWED_ORIGINS: string;  // Comma-separated list of allowed origins
  ORIGIN_URL: string;       // Upstream origin server URL
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // CORS preflight handling
    if (request.method === "OPTIONS") {
      return handleCORS(request, env);
    }

    // Extract JWT token from Authorization header
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return new Response("Missing or invalid Authorization header", {
        status: 401,
        headers: { "WWW-Authenticate": 'Bearer realm="API Gateway"' },
      });
    }

    const token = authHeader.substring(7); // Remove "Bearer " prefix

    try {
      const ctx = await executeSecurityFilter(token, env.JWT_SECRET);

      // Check if request is allowed
      if (!ctx.is_allowed) {
        return new Response(
          JSON.stringify({
            error: "Unauthorized",
            message: ctx.error_message,
          }),
          {
            status: 401,
            headers: { 
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": request.headers.get("Origin") || "*" 
            },
          }
        );
      }

      // Rewrite URL to point to upstream origin server
      const url = new URL(request.url);
      const originUrl = new URL(env.ORIGIN_URL);
      url.hostname = originUrl.hostname;
      url.protocol = originUrl.protocol;
      url.port = originUrl.port;

      const modifiedRequest = new Request(url.toString(), {
        method: request.method,
        body: request.body,
        headers: new Headers(request.headers),
      });
      
      modifiedRequest.headers.set("X-User-ID", ctx.user_id || "");
      modifiedRequest.headers.set("X-User-Role", ctx.user_role || "guest");

      const response = await fetch(modifiedRequest);

      const secureResponse = new Response(response.body, response);
      secureResponse.headers.set("X-Content-Type-Options", "nosniff");
      secureResponse.headers.set("X-Frame-Options", "DENY");
      secureResponse.headers.set("X-XSS-Protection", "1; mode=block");
      secureResponse.headers.set(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains"
      );

      const origin = request.headers.get("Origin");
      const allowedOrigins = env.ALLOWED_ORIGINS.split(",");
      if (origin && allowedOrigins.includes(origin)) {
        secureResponse.headers.set("Access-Control-Allow-Origin", origin);
      }

      return secureResponse;
    } catch (error) {
      console.error("Security filter error:", error);
      return new Response(
        JSON.stringify({
          error: "Internal Server Error",
          message: "Security validation failed",
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
  },
};

// =============================================================================
// Native JWT verification using Web Crypto API
// =============================================================================

function base64UrlDecode(str: string): Uint8Array {
  // Convert base64url to base64
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  // Pad with = characters
  while (str.length % 4 !== 0) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

function base64UrlEncode(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function parseJwtPayload(payload: string): any {
  try {
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

async function executeSecurityFilter(token: string, secret: string): Promise<StreamContext> {
  const ctx: StreamContext = {
    is_allowed: false,
    error_message: "",
    user_id: undefined,
    user_role: undefined,
  };

  // Step 1: Parse token parts (header.payload.signature)
  const parts = token.split('.');
  if (parts.length !== 3) {
    ctx.error_message = "Crypto Blocked: Malformed token format";
    return ctx;
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  // Step 2: Decode and parse header
  let headerStr: string;
  try {
    headerStr = new TextDecoder().decode(base64UrlDecode(headerB64));
  } catch {
    ctx.error_message = "Crypto Blocked: Malformed token format";
    return ctx;
  }

  let header: any;
  try {
    header = JSON.parse(headerStr);
  } catch {
    ctx.error_message = "Crypto Blocked: Malformed token format";
    return ctx;
  }

  // Step 3: Verify algorithm — only HS256 supported
  if (header.alg !== "HS256") {
    ctx.error_message = "Crypto Blocked: Algorithm mismatch";
    return ctx;
  }

  // Step 4: Verify signature using Web Crypto API
  const signingInput = headerB64 + "." + payloadB64;
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signatureBytes = base64UrlDecode(signatureB64);
  const isValid = await crypto.subtle.verify(
    "HMAC",
    key,
    signatureBytes,
    encoder.encode(signingInput)
  );

  if (!isValid) {
    ctx.error_message = "Crypto Blocked: Invalid signature";
    return ctx;
  }

  // Step 5: Decode and parse payload
  let payloadStr: string;
  try {
    payloadStr = new TextDecoder().decode(base64UrlDecode(payloadB64));
  } catch {
    ctx.error_message = "Crypto Blocked: Malformed token format";
    return ctx;
  }

  const payload = parseJwtPayload(payloadStr);
  if (!payload) {
    ctx.error_message = "Gateway Error: Failed to parse payload JSON";
    return ctx;
  }

  if (typeof payload !== "object" || Array.isArray(payload)) {
    ctx.error_message = "Gateway Error: Expected JSON object";
    return ctx;
  }

  // Step 6: Extract required claims
  if (typeof payload.sub !== "string") {
    ctx.error_message = "Gateway Error: Missing or invalid 'sub' claim";
    return ctx;
  }

  if (typeof payload.exp !== "number") {
    ctx.error_message = "Gateway Error: Missing or invalid 'exp' claim";
    return ctx;
  }

  // Step 7: Validate expiration (exp is exclusive upper bound)
  const currentTime = Math.floor(Date.now() / 1000);
  if (currentTime >= payload.exp) {
    ctx.error_message = "Gateway Blocked: Token has expired";
    return ctx;
  }

  // Step 8: Validate not-before (nbf is inclusive lower bound)
  if (payload.nbf !== undefined && typeof payload.nbf === "number") {
    if (currentTime < payload.nbf) {
      ctx.error_message = "Gateway Blocked: Token is not yet valid (nbf)";
      return ctx;
    }
  }

  // Step 9: Authorize
  ctx.is_allowed = true;
  ctx.user_id = payload.sub;
  ctx.user_role = payload.role || "guest";

  return ctx;
}

function handleCORS(request: Request, env: Env): Response {
  const origin = request.headers.get("Origin");
  const allowedOrigins = env.ALLOWED_ORIGINS.split(",").map(o => o.trim());

  if (origin && allowedOrigins.includes(origin)) {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  return new Response("Forbidden", { status: 403 });
}