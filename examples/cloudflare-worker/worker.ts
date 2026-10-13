interface Env {
  JWT_SECRET: string;
  JWT_ISSUER: string;
  JWT_AUDIENCE: string;
  ALLOWED_ORIGINS: string;
  ORIGIN_URL: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const allowedHeaders = ["authorization", "content-type"];

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function headerValue(value: unknown, limit: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= limit &&
    value.trim() === value && /^[\x20-\x7e]+$/.test(value);
}

function b64url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new Error("Invalid base64url");
  const bytes = atob(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "="));
  const canonical = btoa(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  if (canonical !== value) throw new Error("Noncanonical base64url");
  return Uint8Array.from(bytes, character => character.charCodeAt(0));
}

async function verify(token: string, env: Env): Promise<{sub: string; role: string} | null> {
  if (token.length > 8192) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [hb, pb, sb] = parts;
  let signature: Uint8Array<ArrayBuffer>;
  try {
    const header: unknown = JSON.parse(decoder.decode(b64url(hb)));
    if (!object(header) || header.alg !== "HS256" ||
        (header.typ !== undefined && header.typ !== "JWT") ||
        "crit" in header || "b64" in header) return null;
    signature = b64url(sb);
    if (signature.length !== 32) return null;
  } catch { return null; }
  const key = await crypto.subtle.importKey("raw", encoder.encode(env.JWT_SECRET), {name: "HMAC", hash: "SHA-256"}, false, ["verify"]);
  if (!(await crypto.subtle.verify("HMAC", key, signature, encoder.encode(`${hb}.${pb}`)))) return null;
  try {
    const claims: unknown = JSON.parse(decoder.decode(b64url(pb)));
    if (!object(claims) || !headerValue(claims.sub, 256) ||
        !Number.isSafeInteger(claims.exp) || claims.iss !== env.JWT_ISSUER ||
        claims.aud !== env.JWT_AUDIENCE) return null;
    const now = Math.floor(Date.now() / 1000);
    if (now >= (claims.exp as number)) return null;
    if ("nbf" in claims && (!Number.isSafeInteger(claims.nbf) || now < (claims.nbf as number))) return null;
    if ("role" in claims && !headerValue(claims.role, 64)) return null;
    return {sub: claims.sub, role: (claims.role as string | undefined) ?? "guest"};
  } catch { return null; }
}

function originPolicy(env: Env): URL {
  if (typeof env.JWT_SECRET !== "string" || encoder.encode(env.JWT_SECRET).length < 32 ||
      typeof env.JWT_ISSUER !== "string" || !env.JWT_ISSUER.trim() ||
      typeof env.JWT_AUDIENCE !== "string" || !env.JWT_AUDIENCE.trim() ||
      typeof env.ALLOWED_ORIGINS !== "string") throw new Error("Missing gateway policy");
  const origin = new URL(env.ORIGIN_URL);
  if (origin.protocol !== "https:" || origin.username || origin.password ||
      origin.pathname !== "/" || origin.search || origin.hash) throw new Error("Invalid upstream origin");
  return origin;
}

function responseWithCORS(response: Response, origin: string | null, allowed: string[]): Response {
  const result = new Response(response.body, response);
  // Only this gateway's allowlist can grant CORS, including error and redirect responses.
  for (const name of ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Expose-Headers"]) result.headers.delete(name);
  if (origin && allowed.includes(origin)) result.headers.set("Access-Control-Allow-Origin", origin);
  const vary = (result.headers.get("Vary") || "").split(",").map(value => value.trim()).filter(Boolean);
  if (!vary.some(value => value.toLowerCase() === "origin") && !vary.includes("*")) vary.push("Origin");
  result.headers.set("Vary", vary.join(", "));
  result.headers.set("Cache-Control", "private, no-store");
  result.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  return result;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const origin = req.headers.get("Origin");
    const allowed = typeof env.ALLOWED_ORIGINS === "string" ? env.ALLOWED_ORIGINS.split(",").map(value => value.trim()).filter(Boolean) : [];
    const finish = (response: Response) => responseWithCORS(response, origin, allowed);
    const error = (status: number, message: string) => finish(new Response(JSON.stringify({error: message}), {status, headers: {"Content-Type": "application/json", "Cache-Control": "no-store"}}));
    let upstream: URL;
    try { upstream = originPolicy(env); }
    catch { return error(500, "Gateway configuration error"); }
    if (origin && !allowed.includes(origin)) return error(403, "Origin forbidden");
    if (req.method === "OPTIONS") {
      const method = req.headers.get("Access-Control-Request-Method");
      const headers = (req.headers.get("Access-Control-Request-Headers") || "").split(",").map(value => value.trim().toLowerCase()).filter(Boolean);
      if (!origin || !method || !methods.includes(method) || headers.some(value => !allowedHeaders.includes(value))) return error(403, "Preflight forbidden");
      return finish(new Response(null, {status: 204, headers: {
        "Access-Control-Allow-Methods": methods.join(", "),
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Max-Age": "86400",
      }}));
    }
    const auth = req.headers.get("Authorization");
    if (!auth?.startsWith("Bearer ")) return error(401, "Unauthorized");
    let identity: {sub: string; role: string} | null;
    try { identity = await verify(auth.slice(7), env); }
    catch { return error(500, "Authentication service error"); }
    if (!identity) return error(401, "Unauthorized");
    const incoming = new URL(req.url);
    upstream.pathname = incoming.pathname;
    upstream.search = incoming.search;
    const headers = new Headers(req.headers);
    headers.delete("Authorization");
    headers.delete("Proxy-Authorization");
    headers.delete("Host");
    headers.set("X-User-ID", identity.sub);
    headers.set("X-User-Role", identity.role);
    // Keep method/body/signal; never forward credentials or identity through an automatic redirect.
    const proxy = new Request(new Request(upstream.toString(), req), {headers, redirect: "manual", cache: "no-store"});
    try { return finish(await fetch(proxy)); }
    catch { return error(502, "Upstream unavailable"); }
  },
};
