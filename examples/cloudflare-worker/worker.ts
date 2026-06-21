interface Env {
  JWT_SECRET: string;
  ALLOWED_ORIGINS: string;
  ORIGIN_URL: string;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === "OPTIONS") return handleCORS(req, env);

    const auth = req.headers.get("Authorization");
    if (!auth?.startsWith("Bearer ")) {
      return new Response("Missing or invalid Authorization header", { status: 401 });
    }

    try {
      const ctx = await verify(auth.slice(7), env.JWT_SECRET);
      if (!ctx.ok) {
        return new Response(JSON.stringify({ error: "Unauthorized", message: ctx.msg }), {
          status: 401,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": req.headers.get("Origin") || "*" },
        });
      }

      const url = new URL(req.url);
      const origin = new URL(env.ORIGIN_URL);
      url.hostname = origin.hostname;
      url.protocol = origin.protocol;
      url.port = origin.port;

      const proxy = new Request(url, { method: req.method, body: req.body, headers: req.headers });
      proxy.headers.set("X-User-ID", ctx.sub!);
      proxy.headers.set("X-User-Role", ctx.role!);

      const res = await fetch(proxy);
      const secure = new Response(res.body, res);
      secure.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

      const allowed = env.ALLOWED_ORIGINS.split(",");
      const originH = req.headers.get("Origin");
      if (originH && allowed.includes(originH)) secure.headers.set("Access-Control-Allow-Origin", originH);

      return secure;
    } catch (e) {
      console.error("Security filter error:", e);
      return new Response(JSON.stringify({ error: "Internal Server Error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  },
};

function b64url(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

async function verify(token: string, secret: string) {
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false as const, msg: "Malformed token" };

  const [hb, pb, sb] = parts;
  const enc = new TextEncoder();

  const sig = b64url(sb);
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  if (!(await crypto.subtle.verify("HMAC", key, sig, enc.encode(`${hb}.${pb}`)))) {
    return { ok: false as const, msg: "Invalid signature" };
  }

  let p: any;
  try {
    p = JSON.parse(new TextDecoder().decode(b64url(pb)));
  } catch {
    return { ok: false as const, msg: "Malformed payload" };
  }

  if (typeof p.sub !== "string") return { ok: false as const, msg: "Missing sub" };
  if (typeof p.exp !== "number") return { ok: false as const, msg: "Missing exp" };

  const now = Math.floor(Date.now() / 1000);
  if (now >= p.exp) return { ok: false as const, msg: "Token expired" };
  if (typeof p.nbf === "number" && now < p.nbf) return { ok: false as const, msg: "Token not yet valid" };

  return { ok: true as const, sub: p.sub, role: p.role || "guest" };
}

function handleCORS(req: Request, env: Env): Response {
  const origin = req.headers.get("Origin");
  const allowed = env.ALLOWED_ORIGINS.split(",").map((s) => s.trim());
  if (origin && allowed.includes(origin)) {
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