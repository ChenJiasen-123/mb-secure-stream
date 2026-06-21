# Cloudflare Worker — JWT Gateway

Pure TypeScript JWT security gateway using Web Crypto API (no Wasm dependency).

## Quick start

```bash
npm install
npm run dev
```

## Deploy

```bash
npm run deploy
```

## Environment

Set in `wrangler.toml` or via `wrangler secret put`:

| Key | Description |
|-----|-------------|
| `JWT_SECRET` | HMAC-SHA256 key for JWT verification |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins |
| `ORIGIN_URL` | Upstream origin server URL |

## Usage

```bash
curl -H "Authorization: Bearer <jwt>" https://worker.dev/anything
```

Successful requests get `X-User-ID` and `X-User-Role` headers forwarded to the origin.