import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { validateDestination } from '../src/index.js';

class MemoryD1 {
  constructor() { this.rows = new Map(); this.reports = []; }
  prepare(sql) {
    const db = this;
    return {
      values: [],
      bind(...values) { this.values = values; return this; },
      async run() {
        if (sql.startsWith('INSERT INTO shares')) {
          const [id, iv, ciphertext, keyId, revokeHash, createdAt, expiresAt] = this.values;
          db.rows.set(id, { id, iv, ciphertext, key_id: keyId, revoke_hash: revokeHash, created_at: createdAt, expires_at: expiresAt, revoked_at: null });
          return { meta: { changes: 1 } };
        }
        if (sql.startsWith('UPDATE shares')) {
          const [revokedAt, id] = this.values;
          const row = db.rows.get(id);
          if (row && row.revoked_at === null) row.revoked_at = revokedAt;
          return { meta: { changes: row ? 1 : 0 } };
        }
        if (sql.startsWith('INSERT INTO abuse_reports')) {
          db.reports.push({ share_id: this.values[0], reason: this.values[1], created_at: this.values[2] });
          return { meta: { changes: 1 } };
        }
        if (sql.startsWith('DELETE FROM shares WHERE id')) {
          db.rows.delete(this.values[0]);
          return { meta: { changes: 1 } };
        }
        if (sql.startsWith('DELETE FROM shares WHERE expires_at')) {
          let changes = 0;
          for (const [id, row] of db.rows) {
            if (row.expires_at <= this.values[0] || row.revoked_at !== null) {
              db.rows.delete(id); changes += 1;
            }
          }
          return { meta: { changes } };
        }
        return { meta: { changes: 0 } };
      },
      async first() {
        const row = db.rows.get(this.values[0]);
        if (!row) return null;
        if (sql.includes('revoke_hash')) return { revoke_hash: row.revoke_hash, revoked_at: row.revoked_at };
        if (sql.includes('SELECT id, expires_at')) return { id: row.id, expires_at: row.expires_at, revoked_at: row.revoked_at };
        return { iv: row.iv, ciphertext: row.ciphertext, key_id: row.key_id, expires_at: row.expires_at, revoked_at: row.revoked_at };
      },
    };
  }
}

function makeEnv() {
  return {
    DB: new MemoryD1(),
    LINKLOCK_MASTER_KEYS: JSON.stringify({
      v1: Buffer.alloc(32, 7).toString('base64'),
      v2: Buffer.alloc(32, 8).toString('base64'),
    }),
    LINKLOCK_ACTIVE_KEY_ID: 'v1',
    CREATE_RATE_LIMITER: { limit: async () => ({ success: true }) },
    REPORT_RATE_LIMITER: { limit: async () => ({ success: true }) },
  };
}

test('destination validation accepts HTTP and HTTPS links', () => {
  assert.equal(validateDestination('https://example.com/a').ok, true);
  assert.equal(validateDestination(' http://example.org/path ').url, 'http://example.org/path');
});

test('destination validation rejects invisible Unicode format and control characters', () => {
  for (const url of [
    'https://exa\u2060mple.com/',
    'https://example.com/\u200bhidden',
    'https://example.com/\u202Etxt.exe',
    'https://example.com/\u0001control',
  ]) assert.equal(validateDestination(url).ok, false, JSON.stringify(url));
});

test('destination validation blocks unsafe schemes, credentials, and local hosts', () => {
  for (const url of [
    'javascript:alert(1)',
    'file:///etc/passwd',
    'https://user:pass@example.com/',
    'http://localhost/admin',
    'http://127.0.0.1/',
    'http://192.168.1.1/',
    'http://printer.local/',
    'http://localhost./admin',
    'http://router.localhost./admin',
  ]) assert.equal(validateDestination(url).ok, false, url);
});

test('share creation stores ciphertext and POST from the interstitial is required before redirect', async () => {
  const env = makeEnv();
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com/private?q=hello' }),
  }), env);
  assert.equal(response.status, 201);
  const created = await response.json();
  assert.match(created.id, /^[A-Za-z0-9_-]{24}$/u);
  const sharePath = new URL(created.shareUrl).pathname;
  const shareToken = sharePath.slice('/s/'.length);
  assert.match(shareToken, new RegExp(`^${created.id}\\.v1\\.[A-Za-z0-9_-]{16}\\.[A-Za-z0-9_-]{20,3800}$`, 'u'));
  assert.equal(shareToken.split('.')[3], env.DB.rows.get(created.id).ciphertext);
  assert.ok(created.shareUrl.length < 4096);
  assert.ok(created.revokeToken);
  assert.equal(env.DB.rows.size, 1);
  const stored = env.DB.rows.get(created.id);
  assert.equal(stored.ciphertext.includes('example.com'), false);

  const opened = await worker.fetch(new Request(created.shareUrl), env);
  assert.equal(opened.status, 200);
  assert.match(opened.headers.get('content-type'), /text\/html/u);
  const interstitial = await opened.text();
  assert.match(interstitial, /example\.com/u);
  assert.match(interstitial, /method="post"/u);
  const previewOnly = await worker.fetch(new Request(`https://share.example/go/${shareToken}`), env);
  assert.equal(previewOnly.status, 405);
  const crossOrigin = await worker.fetch(new Request(`https://share.example/go/${shareToken}`, {
    method: 'POST', headers: { origin: 'https://attacker.example' },
  }), env);
  assert.equal(crossOrigin.status, 403);
  const continued = await worker.fetch(new Request(`https://share.example/go/${shareToken}`, {
    method: 'POST', headers: { origin: 'https://share.example', 'sec-fetch-site': 'same-origin' },
  }), env);
  assert.equal(continued.status, 302);
  assert.equal(continued.headers.get('location'), 'https://example.com/private?q=hello');
  assert.equal(continued.headers.get('cache-control'), 'no-store, max-age=0');
});

test('share can be revoked only with its management token', async () => {
  const env = makeEnv();
  const createdResponse = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com' }),
  }), env);
  const created = await createdResponse.json();

  const denied = await worker.fetch(new Request(`https://share.example/api/shares/${created.id}`, {
    method: 'DELETE', headers: { authorization: 'Bearer wrong-token-value-wrong-token-value-wrong' },
  }), env);
  assert.equal(denied.status, 403);

  const revoked = await worker.fetch(new Request(`https://share.example/api/shares/${created.id}`, {
    method: 'DELETE', headers: { authorization: `Bearer ${created.revokeToken}` },
  }), env);
  assert.equal(revoked.status, 200);
  const opened = await worker.fetch(new Request(created.shareUrl), env);
  assert.equal(opened.status, 404);
});

test('invalid URL and unsupported TTL are rejected before storage', async () => {
  const env = makeEnv();
  const invalid = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'javascript:alert(1)' }),
  }), env);
  assert.equal(invalid.status, 400);
  const badTtl = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com', ttlSeconds: 60 }),
  }), env);
  assert.equal(badTtl.status, 400);
  assert.equal(env.DB.rows.size, 0);
});


test('legacy ID-only share URLs remain compatible', async () => {
  const env = makeEnv();
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com/legacy' }),
  }), env);
  const created = await response.json();
  const legacyPage = await worker.fetch(new Request(`https://share.example/s/${created.id}`), env);
  assert.equal(legacyPage.status, 200);
  assert.match(await legacyPage.text(), /example\.com/u);
  const legacyContinue = await worker.fetch(new Request(`https://share.example/go/${created.id}`, {
    method: 'POST', headers: { origin: 'https://share.example' },
  }), env);
  assert.equal(legacyContinue.status, 302);
  assert.equal(legacyContinue.headers.get('location'), 'https://example.com/legacy');
});

test('embedded ciphertext is part of the share URL and tampering is rejected', async () => {
  const env = makeEnv();
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com/inside-the-link' }),
  }), env);
  const created = await response.json();
  const token = new URL(created.shareUrl).pathname.slice('/s/'.length);
  const parts = token.split('.');
  assert.equal(parts.length, 4);
  assert.equal(parts[0], created.id);
  assert.equal(parts[1], 'v1');
  assert.equal(parts[2], env.DB.rows.get(created.id).iv);
  assert.equal(parts[3], env.DB.rows.get(created.id).ciphertext);
  assert.equal(token.includes('example.com'), false);

  const changedCiphertext = `${parts[3][0] === 'A' ? 'B' : 'A'}${parts[3].slice(1)}`;
  const tamperedToken = [parts[0], parts[1], parts[2], changedCiphertext].join('.');
  const tampered = await worker.fetch(new Request(`https://share.example/s/${tamperedToken}`), env);
  assert.equal(tampered.status, 404);
});

test('share ciphertext is bound to its share ID', async () => {
  const env = makeEnv();
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com/bound' }),
  }), env);
  const created = await response.json();
  const original = env.DB.rows.get(created.id);
  const substitutedId = 'Z'.repeat(24);
  env.DB.rows.set(substitutedId, { ...original, id: substitutedId });
  const opened = await worker.fetch(new Request(`https://share.example/s/${substitutedId}`), env);
  assert.equal(opened.status, 503);
  assert.equal(opened.headers.get('location'), null);
});

test('expired shares return 410 and are deleted from storage', async () => {
  const env = makeEnv();
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com/expired' }),
  }), env);
  const created = await response.json();
  env.DB.rows.get(created.id).expires_at = Math.floor(Date.now() / 1000) - 1;
  const opened = await worker.fetch(new Request(created.shareUrl), env);
  assert.equal(opened.status, 410);
  assert.equal(env.DB.rows.has(created.id), false);
});

test('malformed JSON shapes are rejected without throwing', async () => {
  const env = makeEnv();
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: 'null',
  }), env);
  assert.equal(response.status, 400);
  assert.equal(env.DB.rows.size, 0);
});


test('create endpoint returns 429 when rate limiter blocks the source', async () => {
  const env = makeEnv();
  env.CREATE_RATE_LIMITER.limit = async () => ({ success: false });
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com' }),
  }), env);
  assert.equal(response.status, 429);
  assert.equal(env.DB.rows.size, 0);
});


test('oversized request bodies are rejected before JSON parsing', async () => {
  const env = makeEnv();
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: `https://example.com/${'a'.repeat(5000)}` }),
  }), env);
  assert.equal(response.status, 413);
  assert.equal(env.DB.rows.size, 0);
});


test('new shares use active key version while old shares remain decryptable', async () => {
  const env = makeEnv();
  const create = async () => worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com/key-version' }),
  }), env);
  const oldShare = await (await create()).json();
  assert.equal(env.DB.rows.get(oldShare.id).key_id, 'v1');
  env.LINKLOCK_ACTIVE_KEY_ID = 'v2';
  const newShare = await (await create()).json();
  assert.equal(env.DB.rows.get(newShare.id).key_id, 'v2');
  const follow = (share) => {
    const token = new URL(share.shareUrl).pathname.slice('/s/'.length);
    return worker.fetch(new Request(`https://share.example/go/${token}`, {
      method: 'POST', headers: { origin: 'https://share.example' },
    }), env);
  };
  const oldOpen = await follow(oldShare);
  const newOpen = await follow(newShare);
  assert.equal(oldOpen.headers.get('location'), 'https://example.com/key-version');
  assert.equal(newOpen.headers.get('location'), 'https://example.com/key-version');
});

test('report endpoint accepts only supported reasons and stores no destination URL', async () => {
  const env = makeEnv();
  const createdResponse = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com/report-me' }),
  }), env);
  const created = await createdResponse.json();
  const report = await worker.fetch(new Request('https://share.example/api/reports', {
    method: 'POST', headers: {
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'https://share.example',
    },
    body: new URLSearchParams({ id: created.id, reason: 'phishing' }),
  }), env);
  assert.equal(report.status, 200);
  assert.match(await report.text(), /تم استلام البلاغ/u);

  const invalidReason = await worker.fetch(new Request('https://share.example/api/reports', {
    method: 'POST', headers: {
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'https://share.example',
    },
    body: new URLSearchParams({ id: created.id, reason: 'javascript' }),
  }), env);
  assert.equal(invalidReason.status, 400);
  assert.deepEqual(env.DB.reports.map((item) => item.reason), ['phishing']);
  assert.equal(JSON.stringify(env.DB.reports).includes('example.com'), false);
});

test('report endpoint rejects missing or cross-origin form submissions', async () => {
  const env = makeEnv();
  const body = new URLSearchParams({ id: 'A'.repeat(24), reason: 'phishing' });
  const missingOrigin = await worker.fetch(new Request('https://share.example/api/reports', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  }), env);
  const crossOrigin = await worker.fetch(new Request('https://share.example/api/reports', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'https://attacker.example',
    },
    body,
  }), env);
  assert.equal(missingOrigin.status, 403);
  assert.equal(crossOrigin.status, 403);
  assert.equal(env.DB.reports.length, 0);
});

test('report endpoint is rate limited', async () => {
  const env = makeEnv();
  env.REPORT_RATE_LIMITER.limit = async () => ({ success: false });
  const report = await worker.fetch(new Request('https://share.example/api/reports', {
    method: 'POST', headers: {
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'https://share.example',
    },
    body: new URLSearchParams({ id: 'A'.repeat(24), reason: 'phishing' }),
  }), env);
  assert.equal(report.status, 429);
});
