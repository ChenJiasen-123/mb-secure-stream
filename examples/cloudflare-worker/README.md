# Cloudflare Worker — JWT gateway example

This historical example is an independent TypeScript/Web Crypto gateway. It does not call the MoonBit JWT or secretstream implementation and is not evidence of a deployed MoonBit integration.

## Local checks

Use Node 24. From this directory:

```sh
npm ci --ignore-scripts
npm test
npm run check
npm run build
```

`build` runs `wrangler deploy --dry-run`: it bundles locally without publishing. Tests sign synthetic tokens and mock the upstream; they do not call a real service. The lockfile pins the tested dependency graph.

## Configure before running

| Setting | Contract |
|---|---|
| `JWT_SECRET` | Random HS256 secret, at least 32 UTF-8 bytes; configure with `wrangler secret put JWT_SECRET` for deployment, never in wrangler.toml |
| `JWT_ISSUER` | Required exact issuer |
| `JWT_AUDIENCE` | Required exact string audience; audience arrays are rejected |
| `ALLOWED_ORIGINS` | Comma-separated exact browser origins; spaces around entries are trimmed; empty permits server requests without Origin only |
| `ORIGIN_URL` | HTTPS origin only, with no credentials, path prefix, query or fragment |

For local development put the secret in an ignored `.dev.vars` file and set the other values in `wrangler.toml`, then run `npm run dev`. The committed `.invalid` upstream/issuer placeholders must be replaced for a real application. Missing policy returns 500 without contacting the upstream.

When you intentionally deploy, configure the secret and a trusted upstream first, then run `npm run deploy`. This repository's CI performs checks and dry-run bundling only.

## Authentication and forwarding

Only canonical unpadded base64url HS256 JWTs of at most 8192 characters are accepted. `typ`, if present, must be JWT; unsupported `crit` and `b64` headers are rejected. `sub` is required and limited to 256 printable ASCII characters without edge whitespace; optional `role` has a 64-character equivalent limit and defaults to guest only when absent. These bounds make the identity headers unambiguous. `exp` and optional `nbf` must be safe integers; malformed present claims fail closed.

After signature, issuer, audience and time validation, the worker forwards the method, body, path and query to the configured upstream origin. It removes Authorization, Proxy-Authorization and the incoming Host, and overwrites X-User-ID/X-User-Role. Redirects are returned to the caller instead of followed with identity headers. Upstream fetches and responses use no-store to avoid sharing identity-specific content through a cache.

The origin must restrict access to the trusted gateway or authenticate it separately; an origin publicly trusting arbitrary X-User-ID headers can be bypassed directly. CORS is browser policy, not origin authentication. This example does not implement JWT revocation, replay protection, per-request rate limiting or end-to-end application authorization.

## Response policy

Disallowed browser origins receive 403. Allowed origins receive the same CORS policy on success and failure, with Vary: Origin; upstream wildcard/credential CORS grants are removed. Malformed or rejected tokens return 401, misconfiguration returns 500, and upstream network failure returns 502. Tokens and secrets are not logged.

The use of manual redirect and no-store follows the [Workers Request API](https://developers.cloudflare.com/workers/runtime-apis/request/). Actual Cloudflare runtime integration and a real origin deployment require separate deployment validation.
