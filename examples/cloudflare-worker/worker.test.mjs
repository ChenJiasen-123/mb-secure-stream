import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import worker from './worker.ts';

const env = {JWT_SECRET: 'synthetic-only-secret-32-bytes-long', JWT_ISSUER: 'issuer', JWT_AUDIENCE: 'service', ALLOWED_ORIGINS: 'https://app.example', ORIGIN_URL: 'https://upstream.example'};
const payload = {sub: 'user-1', role: 'reader', exp: 4000000000, iss: 'issuer', aud: 'service'};
function token(claims = payload, header = {alg: 'HS256', typ: 'JWT'}) {
  const parts = [Buffer.from(JSON.stringify(header)).toString('base64url'), Buffer.from(typeof claims === 'string' ? claims : JSON.stringify(claims)).toString('base64url')];
  const signature = createHmac('sha256', env.JWT_SECRET).update(parts.join('.')).digest('base64url');
  return [...parts, signature].join('.');
}
async function request(jwt, config = env, extra = {}) {
  const previous = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async req => {
    calls.push(req);
    return new Response('upstream', {headers: {'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true'}});
  };
  try {
    const response = await worker.fetch(new Request('https://gateway.example/data?q=1', {headers: {Authorization: 'Bearer ' + jwt, ...extra}}), config);
    return {response, calls};
  } finally {globalThis.fetch = previous;}
}

test('signed token is restricted to HS256 and understood JOSE header fields', async () => {
  for (const header of [{alg: 'none'}, {alg: 'HS384'}, {}, {alg: 'HS256', crit: ['unknown']}, {alg: 'HS256', b64: false}]) {
    const {response, calls} = await request(token(payload, header));
    assert.equal(response.status, 401);
    assert.equal(calls.length, 0);
  }
});

test('issuer audience and optional claim types fail closed', async () => {
  for (const claims of [{...payload, iss: 'other'}, {...payload, aud: 'other'}, {...payload, iss: undefined}, {...payload, aud: undefined}, {...payload, nbf: '4000000000'}, {...payload, role: {}}, {...payload, role: null}, {...payload, sub: 'user\r\nInjected: true'}, {...payload, exp: 1.5}, null, '[]', '{"sub":"u","exp":1e999,"iss":"issuer","aud":"service"}']) {
    const {response, calls} = await request(token(claims));
    assert.equal(response.status, 401, JSON.stringify(claims));
    assert.equal(calls.length, 0);
  }
});

test('malformed token and oversized token never become upstream requests or 500s', async () => {
  for (const jwt of ['a.b.%', 'a..c', 'x'.repeat(8193), token().slice(0, -3)]) {
    const {response, calls} = await request(jwt);
    assert.equal(response.status, 401);
    assert.equal(calls.length, 0);
  }
});

test('forwarding pins upstream strips bearer and overwrites spoofed identity', async () => {
  const {response, calls} = await request(token(), env, {'X-User-ID': 'attacker', 'X-User-Role': 'admin', Origin: 'https://app.example'});
  assert.equal(response.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://upstream.example/data?q=1');
  assert.equal(calls[0].headers.get('Authorization'), null);
  assert.equal(calls[0].headers.get('X-User-ID'), 'user-1');
  assert.equal(calls[0].headers.get('X-User-Role'), 'reader');
  assert.equal(calls[0].redirect, 'manual');
  assert.equal(calls[0].cache, 'no-store');
  assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
  assert.equal(response.headers.get('Access-Control-Allow-Origin'), 'https://app.example');
  assert.equal(response.headers.get('Access-Control-Allow-Credentials'), null);
  assert.match(response.headers.get('Vary'), /Origin/);
});

test('disallowed origins cannot obtain reflected CORS headers', async () => {
  const {response, calls} = await request('malformed', env, {Origin: 'https://attacker.example'});
  assert.equal(response.status, 403);
  assert.equal(response.headers.get('Access-Control-Allow-Origin'), null);
  assert.equal(calls.length, 0);
});

test('missing auth and auth errors use the same trimmed origin allowlist', async () => {
  const config = {...env, ALLOWED_ORIGINS: ' https://app.example , https://other.example '};
  const missing = await worker.fetch(new Request('https://gateway.example', {headers: {Origin: 'https://app.example'}}), config);
  assert.equal(missing.status, 401);
  assert.equal(missing.headers.get('Access-Control-Allow-Origin'), 'https://app.example');
  const {response} = await request('malformed', config, {Origin: 'https://app.example'});
  assert.equal(response.status, 401);
  assert.equal(response.headers.get('Access-Control-Allow-Origin'), 'https://app.example');
});

test('invalid server policy fails without contacting upstream', async () => {
  for (const config of [{...env, JWT_ISSUER: ''}, {...env, JWT_AUDIENCE: ''}, {...env, JWT_SECRET: 'short'}, {...env, ORIGIN_URL: 'http://upstream.example'}, {...env, ORIGIN_URL: 'https://user:pass@upstream.example'}, {...env, ORIGIN_URL: 'https://upstream.example/ignored-path'}]) {
    const {response, calls} = await request(token(), config);
    assert.equal(response.status, 500);
    assert.equal(calls.length, 0);
  }
});

test('expiry future nbf and header-safe subject checks are enforced', async () => {
  for (const claims of [{...payload, exp: 0}, {...payload, nbf: 4000000000}, {...payload, sub: ''}, {...payload, sub: 'a'.repeat(257)}, {...payload, role: 'a'.repeat(65)}]) {
    const {response, calls} = await request(token(claims));
    assert.equal(response.status, 401);
    assert.equal(calls.length, 0);
  }
  const {response, calls} = await request(token({...payload, role: undefined}));
  assert.equal(response.status, 200);
  assert.equal(calls[0].headers.get('X-User-Role'), 'guest');
});

test('preflight validates requested method and headers', async () => {
  for (const [method, headers, status] of [['POST', 'authorization, content-type', 204], ['TRACE', 'authorization', 403], ['GET', 'x-admin', 403]]) {
    const result = await worker.fetch(new Request('https://gateway.example', {method: 'OPTIONS', headers: {Origin: 'https://app.example', 'Access-Control-Request-Method': method, 'Access-Control-Request-Headers': headers}}), env);
    assert.equal(result.status, status);
    assert.equal(result.headers.get('Access-Control-Allow-Origin'), 'https://app.example');
  }
});

test('POST body survives forwarding and network failure becomes a CORS-aware 502', async () => {
  const previous = globalThis.fetch;
  try {
    globalThis.fetch = async req => {
      assert.equal(req.method, 'POST');
      assert.equal(await req.text(), 'synthetic body');
      assert.equal(req.redirect, 'manual');
      return new Response(null, {status: 307, headers: {Location: 'https://different.example'}});
    };
    const req = new Request('https://gateway.example/post', {method: 'POST', body: 'synthetic body', headers: {Authorization: 'Bearer ' + token(), Origin: 'https://app.example'}});
    const res = await worker.fetch(req, env);
    assert.equal(res.status, 307);
    assert.equal(res.headers.get('Location'), 'https://different.example');
    globalThis.fetch = async () => {throw new Error('network failure');};
    const failed = await worker.fetch(new Request('https://gateway.example', {headers: {Authorization: 'Bearer ' + token(), Origin: 'https://app.example'}}), env);
    assert.equal(failed.status, 502);
    assert.equal(failed.headers.get('Access-Control-Allow-Origin'), 'https://app.example');
  } finally {globalThis.fetch = previous;}
});
