const MAX_URL_LENGTH = 2048;
const DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;
const MIN_TTL_SECONDS = 60 * 60;
const MAX_TTL_SECONDS = 30 * 24 * 60 * 60;
const ID_BYTES = 18;
const REVOKE_TOKEN_BYTES = 32;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store, max-age=0',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    },
  });
}

function plain(message, status) {
  return new Response(message, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store, max-age=0',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    },
  });
}

function html(document, status = 200) {
  return new Response(document, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store, max-age=0',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    },
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/gu, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function sharePage(id, hostname, routeToken) {
  const safeHost = escapeHtml(hostname);
  const safeId = encodeURIComponent(id);
  const safeRouteToken = encodeURIComponent(routeToken);
  return html(`<!doctype html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>تحذير قبل فتح الرابط - LinkLock</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:8vh auto;padding:24px;line-height:1.7;color:#17212b;background:#f7f8fa}main{background:#fff;border:1px solid #d9dee5;border-radius:16px;padding:24px}h1{font-size:1.45rem}.host{direction:ltr;unicode-bidi:break-all;font-weight:700;padding:12px;background:#f0f3f6;border-radius:8px;overflow-wrap:anywhere}.warning{color:#8a3b00}.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}button,a.btn{font:inherit;padding:11px 16px;border-radius:9px;border:1px solid #9aa5b1;background:#fff;color:#15202b;text-decoration:none;cursor:pointer}.primary{background:#173f74!important;color:white!important;border-color:#173f74!important}form{margin-top:18px;padding-top:14px;border-top:1px solid #e2e6eb}select{font:inherit;padding:9px;max-width:100%}.small{font-size:.9rem;color:#536170}</style></head>
<body><main><h1>تأكد قبل ما تفتح الرابط</h1><p class="warning"><strong>تنبيه:</strong> رابط المشاركة سيحوّلك إلى موقع خارجي. LinkLock لا يضمن أن الموقع آمن أو موثوق.</p><p>الموقع المقصود:</p><div class="host">${safeHost}</div><p>تأكد أن اسم الموقع هو المتوقع، ولا تدخل كلمة مرور أو بيانات شخصية لو مش واثق من الموقع.</p><div class="actions"><form method="post" action="/go/${safeRouteToken}" style="margin:0;padding:0;border:0"><button class="primary" type="submit">متابعة إلى الموقع الخارجي</button></form><a class="btn" href="/">إلغاء والعودة</a></div>
<form method="post" action="/api/reports"><h2>الإبلاغ عن رابط مشبوه</h2><input type="hidden" name="id" value="${safeId}"><label for="reason">سبب البلاغ: </label><select id="reason" name="reason" required><option value="phishing">تصيّد أو سرقة بيانات</option><option value="malware">برمجيات ضارة</option><option value="spam">احتيال أو محتوى مزعج</option><option value="other">سبب آخر</option></select> <button type="submit">إرسال بلاغ</button></form>
<p class="small">لا يتم تحويلك تلقائيًا. عنوان الموقع الأصلي سيظهر في شريط المتصفح بعد المتابعة.</p></main></body></html>`);
}

function reportConfirmation() {
  return html('<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>تم استلام البلاغ</title><body style="font-family:system-ui;max-width:600px;margin:10vh auto;padding:24px;line-height:1.7"><h1>تم استلام البلاغ</h1><p>شكرًا للمساعدة. البلاغ لا يعني أن الرابط تم حظره بالفعل.</p><a href="/">العودة</a></body></html>');
}

function base64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function fromBase64(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  return Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0));
}

function randomToken(byteLength) {
  return base64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

function isPrivateIpv4(host) {
  const parts = host.split('.');
  if (parts.length !== 4 || !parts.every((part) => /^\d{1,3}$/u.test(part))) return false;
  const octets = parts.map(Number);
  if (octets.some((part) => part > 255)) return true;
  const [a, b] = octets;
  return a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) || a >= 224;
}

export function validateDestination(value) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    return { ok: false, error: 'اكتب الرابط الأول' };
  }
  // Reject invisible Unicode formatting controls instead of silently trimming
  // or normalizing them; they can make a displayed URL differ from its target.
  if (/[\p{Cf}\p{Cc}]/u.test(value)) {
    return { ok: false, error: 'الرابط يحتوي على محارف تحكم أو حروف Unicode مخفية' };
  }
  const trimmed = value.trim();
  if (new TextEncoder().encode(trimmed).length > MAX_URL_LENGTH) {
    return { ok: false, error: 'الرابط أطول من الحد المسموح' };
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { ok: false, error: 'الرابط غير صالح' };
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { ok: false, error: 'المسموح روابط HTTP وHTTPS فقط' };
  }
  if (!parsed.hostname || parsed.username || parsed.password) {
    return { ok: false, error: 'صيغة الرابط غير مسموح بها' };
  }

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/gu, '').replace(/\.$/u, '');
  const privateIpv6 = host.includes(':') && (
    host === '::' || host === '::1' || host.startsWith('fc') ||
    host.startsWith('fd') || host.startsWith('fe80:') ||
    host.startsWith('::ffff:')
  );
  if (
    host === 'localhost' || host.endsWith('.localhost') ||
    host.endsWith('.local') || host.endsWith('.lan') ||
    host.endsWith('.home') || host.endsWith('.home.arpa') ||
    host.endsWith('.internal') || host.endsWith('.intranet') ||
    privateIpv6 || isPrivateIpv4(host)
  ) {
    return { ok: false, error: 'روابط الشبكات المحلية غير مسموح بها' };
  }
  return { ok: true, url: parsed.toString() };
}

async function loadMasterKey(env, keyId) {
  if (!/^[A-Za-z0-9_-]{1,32}$/u.test(keyId)) throw new Error('Invalid master key ID');
  let encoded;
  if (typeof env.LINKLOCK_MASTER_KEYS === 'string' && env.LINKLOCK_MASTER_KEYS.trim()) {
    let keyRing;
    try { keyRing = JSON.parse(env.LINKLOCK_MASTER_KEYS); } catch { throw new Error('Invalid LINKLOCK_MASTER_KEYS JSON'); }
    if (!keyRing || typeof keyRing !== 'object' || Array.isArray(keyRing)) {
      throw new Error('LINKLOCK_MASTER_KEYS must be a JSON object');
    }
    encoded = keyRing[keyId];
  } else if (keyId === 'v1' && typeof env.LINKLOCK_MASTER_KEY === 'string') {
    // Temporary backward compatibility for the first deployed schema.
    encoded = env.LINKLOCK_MASTER_KEY;
  }
  if (typeof encoded !== 'string' || !encoded) throw new Error(`Missing master key version ${keyId}`);
  const keyBytes = fromBase64(encoded.trim());
  if (keyBytes.length !== 32) throw new Error(`Master key ${keyId} must decode to 32 bytes`);
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptDestination(url, id, env) {
  const keyId = typeof env.LINKLOCK_ACTIVE_KEY_ID === 'string' && env.LINKLOCK_ACTIVE_KEY_ID
    ? env.LINKLOCK_ACTIVE_KEY_ID : 'v1';
  const key = await loadMasterKey(env, keyId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(url);
  const aad = new TextEncoder().encode(`linklock-share-v1:${id}`);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128, additionalData: aad },
    key,
    plaintext,
  );
  return { iv: base64Url(iv), ciphertext: base64Url(new Uint8Array(ciphertext)), keyId };
}

async function decryptDestination(row, id, env) {
  const key = await loadMasterKey(env, row.key_id || 'v1');
  const clear = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: fromBase64(row.iv),
      tagLength: 128,
      additionalData: new TextEncoder().encode(`linklock-share-v1:${id}`),
    },
    key,
    fromBase64(row.ciphertext),
  );
  return new TextDecoder('utf-8', { fatal: true }).decode(clear);
}

async function sha256Hex(value) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function readLimitedBody(request, maximumBytes) {
  if (!request.body) return { tooLarge: false, text: '' };
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        return { tooLarge: true, text: '' };
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { tooLarge: false, text: new TextDecoder('utf-8', { fatal: true }).decode(bytes) };
}

function parseShareToken(value) {
  if (typeof value !== 'string' || value.length > 4096 || value.includes('/')) return null;
  // Backward compatibility for existing short-ID shares.
  if (/^[A-Za-z0-9_-]{24}$/u.test(value)) {
    return { id: value, embedded: null, routeToken: value };
  }
  const match = /^([A-Za-z0-9_-]{24})\.([A-Za-z0-9_-]{1,32})\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{20,3800})$/u.exec(value);
  if (!match) return null;
  return {
    id: match[1],
    embedded: { keyId: match[2], iv: match[3], ciphertext: match[4] },
    routeToken: value,
  };
}

function buildShareToken(id, encrypted) {
  return `${id}.${encrypted.keyId}.${encrypted.iv}.${encrypted.ciphertext}`;
}

async function createShare(request, env) {
  const rawLength = request.headers.get('content-length');
  const contentLength = rawLength === null ? null : Number(rawLength);
  if (contentLength !== null && (!Number.isFinite(contentLength) || contentLength < 0 || contentLength > 4096)) {
    return json({ error: 'حجم الطلب أكبر من المسموح' }, 413);
  }
  if (!request.headers.get('content-type')?.toLowerCase().includes('application/json')) {
    return json({ error: 'نوع الطلب غير مدعوم' }, 415);
  }

  let body;
  try {
    const bounded = await readLimitedBody(request, 4096);
    if (bounded.tooLarge) return json({ error: 'حجم الطلب أكبر من المسموح' }, 413);
    body = JSON.parse(bounded.text);
  } catch {
    return json({ error: 'بيانات الطلب غير صالحة' }, 400);
  }

  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return json({ error: 'بيانات الطلب غير صالحة' }, 400);
  }
  const checked = validateDestination(body.url);
  if (!checked.ok) return json({ error: checked.error }, 400);

  const ttl = body.ttlSeconds === undefined ? DEFAULT_TTL_SECONDS : body.ttlSeconds;
  if (!Number.isInteger(ttl) || ttl < MIN_TTL_SECONDS || ttl > MAX_TTL_SECONDS) {
    return json({ error: 'مدة الصلاحية لازم تكون من ساعة إلى 30 يوم' }, 400);
  }

  try {
    const id = randomToken(ID_BYTES);
    const encrypted = await encryptDestination(checked.url, id, env);
    const revokeToken = randomToken(REVOKE_TOKEN_BYTES);
    const revokeHash = await sha256Hex(revokeToken);
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + ttl;

    await env.DB.prepare(
      'INSERT INTO shares (id, iv, ciphertext, key_id, revoke_hash, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)',
    ).bind(id, encrypted.iv, encrypted.ciphertext, encrypted.keyId, revokeHash, now, expiresAt).run();

    const origin = new URL(request.url).origin;
    // The encrypted payload is embedded in the share URL. The server key is
    // never included; the Worker validates it against D1 before decryption.
    const shareToken = buildShareToken(id, encrypted);
    const shareUrl = `${origin}/s/${shareToken}`;
    if (shareUrl.length > 4096) {
      await env.DB.prepare('DELETE FROM shares WHERE id = ?').bind(id).run();
      return json({ error: 'الرابط المشفّر الناتج أطول من الحد المسموح' }, 413);
    }
    return json({
      id,
      shareUrl,
      revokeToken,
      expiresAt: new Date(expiresAt * 1000).toISOString(),
    }, 201);
  } catch {
    return json({ error: 'الخادم لم يستطع إنشاء رابط المشاركة' }, 503);
  }
}

async function revokeShare(request, env, id) {
  if (!/^[A-Za-z0-9_-]{24}$/u.test(id)) return json({ error: 'الرابط غير موجود' }, 404);
  const authorization = request.headers.get('authorization') || '';
  const match = /^Bearer ([A-Za-z0-9_-]{40,50})$/u.exec(authorization);
  if (!match) return json({ error: 'رمز الإلغاء غير صحيح' }, 401);

  try {
    const suppliedHash = await sha256Hex(match[1]);
    const row = await env.DB.prepare('SELECT revoke_hash, revoked_at FROM shares WHERE id = ?')
      .bind(id).first();
    if (!row || row.revoked_at !== null || !constantTimeEqual(suppliedHash, row.revoke_hash)) {
      return json({ error: 'تعذر إلغاء الرابط؛ تحقق من الرمز أو حالة الرابط' }, 403);
    }
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare('UPDATE shares SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL')
      .bind(now, id).run();
    return json({ revoked: true });
  } catch {
    return json({ error: 'الخادم لم يستطع إلغاء الرابط' }, 503);
  }
}

async function getShareDestination(env, id, embedded = null) {
  if (!/^[A-Za-z0-9_-]{24}$/u.test(id)) return { response: plain('الرابط غير موجود', 404) };
  const row = await env.DB.prepare(
    'SELECT iv, ciphertext, key_id, expires_at, revoked_at FROM shares WHERE id = ?',
  ).bind(id).first();
  if (!row || row.revoked_at !== null) return { response: plain('الرابط غير موجود أو تم إلغاؤه', 404) };
  if (embedded && (embedded.keyId !== row.key_id || embedded.iv !== row.iv || embedded.ciphertext !== row.ciphertext)) {
    return { response: plain('بيانات التشفير داخل رابط المشاركة غير صحيحة', 404) };
  }
  const now = Math.floor(Date.now() / 1000);
  if (row.expires_at <= now) {
    await env.DB.prepare('DELETE FROM shares WHERE id = ?').bind(id).run();
    return { response: plain('انتهت صلاحية رابط المشاركة', 410) };
  }
  const destination = await decryptDestination(row, id, env);
  const checked = validateDestination(destination);
  if (!checked.ok || checked.url !== destination) return { response: plain('تعذر فتح الرابط', 410) };
  return { destination };
}

async function showSharePage(env, parsedToken) {
  try {
    const result = await getShareDestination(env, parsedToken.id, parsedToken.embedded);
    if (result.response) return result.response;
    return sharePage(parsedToken.id, new URL(result.destination).host, parsedToken.routeToken);
  } catch {
    return plain('تعذر فتح رابط المشاركة حاليًا', 503);
  }
}

async function continueShare(request, env, parsedToken) {
  const requestOrigin = request.headers.get('origin');
  if (requestOrigin !== new URL(request.url).origin) {
    return plain('لازم فتح المتابعة من صفحة التحذير الأصلية', 403);
  }
  const fetchSite = request.headers.get('sec-fetch-site');
  if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') {
    return plain('مصدر طلب المتابعة غير مسموح', 403);
  }
  try {
    const result = await getShareDestination(env, parsedToken.id, parsedToken.embedded);
    if (result.response) return result.response;
    return new Response(null, {
      status: 302,
      headers: {
        location: result.destination,
        'cache-control': 'no-store, max-age=0',
        'referrer-policy': 'no-referrer',
        'x-content-type-options': 'nosniff',
      },
    });
  } catch {
    return plain('تعذر فتح رابط المشاركة حاليًا', 503);
  }
}

async function createReport(request, env) {
  if (!request.headers.get('content-type')?.toLowerCase().includes('application/x-www-form-urlencoded')) {
    return plain('نوع بيانات البلاغ غير مدعوم', 415);
  }
  let form;
  try {
    const bounded = await readLimitedBody(request, 1024);
    if (bounded.tooLarge) return plain('بيانات البلاغ أكبر من المسموح', 413);
    form = new URLSearchParams(bounded.text);
  } catch { return plain('بيانات البلاغ غير صالحة', 400); }
  const id = String(form.get('id') || '');
  const reason = String(form.get('reason') || '');
  if (!/^[A-Za-z0-9_-]{24}$/u.test(id) || !['phishing', 'malware', 'spam', 'other'].includes(reason)) {
    return plain('بيانات البلاغ غير صالحة', 400);
  }
  const row = await env.DB.prepare('SELECT id, expires_at, revoked_at FROM shares WHERE id = ?').bind(id).first();
  if (!row || row.revoked_at !== null || row.expires_at <= Math.floor(Date.now() / 1000)) {
    return plain('الرابط غير متاح للإبلاغ عنه', 404);
  }
  await env.DB.prepare('INSERT INTO abuse_reports (share_id, reason, created_at) VALUES (?, ?, ?)')
    .bind(id, reason, Math.floor(Date.now() / 1000)).run();
  return reportConfirmation();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'POST' && url.pathname === '/api/shares') {
      try {
        const sourceIp = request.headers.get('cf-connecting-ip') || 'unknown';
        const { success } = await env.CREATE_RATE_LIMITER.limit({ key: sourceIp });
        if (!success) return json({ error: 'طلبات إنشاء كثيرة من نفس الشبكة. جرّب بعد دقيقة.' }, 429);
      } catch {
        return json({ error: 'حماية معدل الطلبات غير متاحة حاليًا.' }, 503);
      }
      return createShare(request, env);
    }
    if (request.method === 'DELETE' && url.pathname.startsWith('/api/shares/')) {
      const id = url.pathname.slice('/api/shares/'.length);
      return revokeShare(request, env, id);
    }
    if (request.method === 'GET' && url.pathname.startsWith('/s/')) {
      const parsedToken = parseShareToken(url.pathname.slice('/s/'.length));
      if (!parsedToken) return plain('رابط المشاركة غير صالح', 404);
      return showSharePage(env, parsedToken);
    }
    if (url.pathname.startsWith('/go/')) {
      if (request.method !== 'POST') return plain('طريقة الطلب غير مسموحة', 405);
      const parsedToken = parseShareToken(url.pathname.slice('/go/'.length));
      if (!parsedToken) return plain('رابط المشاركة غير صالح', 404);
      return continueShare(request, env, parsedToken);
    }
    if (request.method === 'POST' && url.pathname === '/api/reports') {
      // This endpoint is submitted by a same-origin HTML form. Require the
      // browser Origin header so an unrelated site cannot forge report posts.
      if (request.headers.get('origin') !== url.origin) {
        return plain('مصدر البلاغ غير مسموح', 403);
      }
      try {
        const sourceIp = request.headers.get('cf-connecting-ip') || 'unknown';
        const { success } = await env.REPORT_RATE_LIMITER.limit({ key: sourceIp });
        if (!success) return plain('تم إرسال بلاغات كثيرة. حاول لاحقًا.', 429);
      } catch {
        return plain('خدمة البلاغات غير متاحة حاليًا.', 503);
      }
      return createReport(request, env);
    }
    if (request.method === 'GET' && url.pathname === '/health') {
      return json({ ok: true });
    }
    if (request.method === 'GET' && url.pathname === '/') {
      return html('<!doctype html><html lang=\"ar\" dir=\"rtl\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>LinkLock</title><body style=\"font-family:system-ui;max-width:620px;margin:10vh auto;padding:24px;line-height:1.7\"><h1>LinkLock</h1><p>خدمة مشاركة الروابط. لا تفتح أي رابط إلا إذا كنت تثق في وجهته.</p></body></html>');
    }
    return json({ error: 'غير موجود' }, 404);
  },

  async scheduled(_controller, env) {
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare('DELETE FROM shares WHERE expires_at <= ? OR revoked_at IS NOT NULL')
      .bind(now).run();
    await env.DB.prepare('DELETE FROM abuse_reports WHERE created_at <= ?')
      .bind(now - (180 * 24 * 60 * 60)).run();
  },
};
