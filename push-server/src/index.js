// Systematic Push Server — Cloudflare Worker
// Receives push subscriptions + notification schedules from the app,
// then fires them at the right time via Web Push (RFC 8291 / VAPID RFC 8292).
// No npm packages — uses only the Web Crypto API available in Workers.

// ─── Utilities ────────────────────────────────────────────────────────────────

const enc = new TextEncoder();

const b64u = buf =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

const b64uDec = s => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
};

// ─── VAPID JWT (RFC 8292) ──────────────────────────────────────────────────────

async function vapidJWT(audience, subject, pubB64, privB64) {
  const pub = b64uDec(pubB64);
  const jwk = {
    kty: 'EC', crv: 'P-256',
    x: b64u(pub.slice(1, 33)),
    y: b64u(pub.slice(33, 65)),
    d: b64u(b64uDec(privB64)),
  };
  const key = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
  const header  = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const payload = b64u(enc.encode(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 43200,  // 12 hrs
    sub: subject,
  })));
  const signing = `${header}.${payload}`;
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(signing)
  );
  return `${signing}.${b64u(sig)}`;
}

// ─── Web Push Payload Encryption (RFC 8291 / aes128gcm) ───────────────────────

async function encryptPayload(p256dhB64, authB64, plaintext) {
  const uaPub  = b64uDec(p256dhB64);   // subscriber public key (65 bytes)
  const auth   = b64uDec(authB64);     // auth secret (16 bytes)
  const data   = typeof plaintext === 'string' ? enc.encode(plaintext) : plaintext;

  // 1. Ephemeral sender key pair
  const senderPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const senderPubRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', senderPair.publicKey)
  );

  // 2. ECDH shared secret
  const subKey = await crypto.subtle.importKey(
    'raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: subKey }, senderPair.privateKey, 256
  );

  // 3. PRK: HKDF-SHA256(salt=auth, IKM=sharedSecret, info="WebPush: info\0"||uaPub||senderPub)
  const prkInfo = new Uint8Array([
    ...enc.encode('WebPush: info\x00'), ...uaPub, ...senderPubRaw
  ]);
  const sharedKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveBits']);
  const prkBits   = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: auth, info: prkInfo }, sharedKey, 256
  );
  const prkKey = await crypto.subtle.importKey('raw', prkBits, 'HKDF', false, ['deriveBits']);

  // 4. Random 16-byte salt for the content-coding header
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // 5. CEK = HKDF(salt, PRK, "Content-Encoding: aes128gcm\0", 16)
  const cekBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('Content-Encoding: aes128gcm\x00') },
    prkKey, 128
  );
  const cek = await crypto.subtle.importKey('raw', cekBits, 'AES-GCM', false, ['encrypt']);

  // 6. Nonce = HKDF(salt, PRK, "Content-Encoding: nonce\0", 12)
  const nonceBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('Content-Encoding: nonce\x00') },
    prkKey, 96
  );

  // 7. Encrypt: AES-128-GCM(CEK, nonce, data || 0x02)
  const plainPadded = new Uint8Array([...data, 2]);
  const ciphertext  = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonceBits }, cek, plainPadded)
  );

  // 8. Build aes128gcm content-coding header: salt(16) | rs(4 BE) | idlen(1) | keyid
  const header = new Uint8Array(16 + 4 + 1 + senderPubRaw.length);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096, false);  // record size, big-endian
  header[20] = senderPubRaw.length;
  header.set(senderPubRaw, 21);

  const body = new Uint8Array(header.length + ciphertext.length);
  body.set(header);
  body.set(ciphertext, header.length);
  return body;
}

// ─── Send one push notification ────────────────────────────────────────────────

async function sendPush(subscription, notification, env) {
  const { endpoint, keys: { p256dh, auth } } = subscription;
  const audience = new URL(endpoint).origin;

  const jwt  = await vapidJWT(audience, env.VAPID_SUBJECT, env.VAPID_PUBLIC_KEY, env.VAPID_PRIVATE_KEY);
  const body = await encryptPayload(p256dh, auth, JSON.stringify(notification));

  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Authorization':     `vapid t=${jwt},k=${env.VAPID_PUBLIC_KEY}`,
      'Content-Encoding':  'aes128gcm',
      'Content-Type':      'application/octet-stream',
      'TTL':               '86400',
    },
    body,
  });
  return res.status;
}

// ─── CORS helper ──────────────────────────────────────────────────────────────

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });

// ─── Worker entry points ───────────────────────────────────────────────────────

export default {

  // HTTP endpoints called by the app
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    const url = new URL(req.url);

    // Return VAPID public key so the app can subscribe
    if (url.pathname === '/key') {
      return json({ key: env.VAPID_PUBLIC_KEY });
    }

    // Store / update a subscription + its notification schedule
    if (url.pathname === '/subscribe' && req.method === 'POST') {
      const { subId, subscription, notifications } = await req.json();
      if (!subId || !subscription?.endpoint) return json({ error: 'bad request' }, 400);
      await env.STORE.put(
        `sub:${subId}`,
        JSON.stringify({ subscription, notifications: notifications || [], updated: Date.now() }),
        { expirationTtl: 60 * 60 * 24 * 30 }  // auto-expire after 30 days of no sync
      );
      return json({ ok: true, scheduled: (notifications || []).length });
    }

    return new Response('Systematic Push Server', { headers: CORS });
  },

  // Cron: runs every 2 minutes, fires any due notifications
  async scheduled(event, env) {
    const now    = Date.now();
    const window = 2.5 * 60 * 1000;  // fire anything within a 2.5-min window

    const list = await env.STORE.list({ prefix: 'sub:' });

    for (const { name } of list.keys) {
      const raw = await env.STORE.get(name);
      if (!raw) continue;

      let data;
      try { data = JSON.parse(raw); } catch { continue; }

      let changed = false;

      for (const notif of data.notifications || []) {
        if (notif.sent) continue;
        if (notif.notifyAt < now - 60000) { notif.sent = true; changed = true; continue; }  // missed, skip
        if (notif.notifyAt > now + window) continue;  // not yet

        try {
          const status = await sendPush(data.subscription, {
            title: notif.title,
            body:  notif.body,
            tag:   notif.id,
          }, env);

          notif.sent = true;
          changed = true;

          // If subscription is gone, remove it
          if (status === 410 || status === 404) {
            await env.STORE.delete(name);
            break;
          }
        } catch (e) {
          console.error('Push failed:', name, e.message);
        }
      }

      // Prune notifications older than 6 hours
      const cutoff = now - 6 * 3600 * 1000;
      const before = data.notifications.length;
      data.notifications = data.notifications.filter(n => n.notifyAt > cutoff);
      if (data.notifications.length !== before) changed = true;

      if (changed) {
        await env.STORE.put(name, JSON.stringify(data), { expirationTtl: 60 * 60 * 24 * 30 });
      }
    }
  },
};
