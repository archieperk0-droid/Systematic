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

    // ── Cloud sync ──────────────────────────────────────────────────────────────
    // GET  /sync?id=<syncId>  → return stored state (or {found:false})
    // POST /sync?id=<syncId>  → store state blob (max 4 MB)
    if (url.pathname === '/sync') {
      const id = url.searchParams.get('id');
      if (!id || id.length < 8) return json({ error: 'bad request' }, 400);
      const key = `sync:${id}`;

      if (req.method === 'GET') {
        const raw = await env.STORE.get(key);
        if (!raw) return json({ found: false });
        return new Response(raw, { headers: { ...CORS, 'Content-Type': 'application/json' } });
      }

      if (req.method === 'POST') {
        const body = await req.text();
        if (!body || body.length > 4 * 1024 * 1024) return json({ error: 'too large' }, 413);
        await env.STORE.put(key, body, { expirationTtl: 60 * 60 * 24 * 90 }); // 90-day TTL
        return json({ ok: true });
      }
    }

    // Parse a timetable screenshot via Claude vision → return structured events
    if (url.pathname === '/parse-image' && req.method === 'POST') {
      if (!env.ANTHROPIC_API_KEY) return json({ error: 'ANTHROPIC_API_KEY not configured on Worker' }, 500);

      const { image, mediaType } = await req.json();
      if (!image) return json({ error: 'no image provided' }, 400);

      const prompt = `This is a weekly timetable/schedule image. Extract every event shown in the grid.

The grid has:
- Left column: time slots (05:00, 05:30, 06:00, etc.)
- Top row: day names (Monday, Tuesday, etc.)
- A row with dates in DD/MM/YY format (e.g. 22/06/26)
- Cells: event names, often with time ranges in the text

For EACH event cell output a JSON object with these exact keys:
- "day": the day column name ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
- "date": the date for that column in DD/MM/YY format (e.g. "22/06/26")
- "title": the event name only (strip any trailing time info)
- "startTime": start in HH:MM 24-hour (e.g. "09:30")
- "endTime": end in HH:MM 24-hour (e.g. "17:30")

Time parsing rules:
- "17:30pm" or "18:30pm" → 24-hr already, ignore pm → "17:30", "18:30"
- "1:00pm" → "13:00", "2:30pm" → "14:30", "12:00pm" → "12:00", "12:00am" → "00:00"
- "6:30am" → "06:30", "9:30am" → "09:30"
- If the event text contains a range like "Travel 8:30am - 9:30am" → startTime "08:30", endTime "09:30", title "Travel"
- If event spans visually across multiple rows, use the top row as startTime and the bottom row end as endTime
- If no end time can be determined, use startTime + 30 minutes

Return ONLY a valid JSON array with no explanation, markdown, or code fences.`;

      const aiResp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type':      'application/json',
          'x-api-key':         env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model:      'claude-haiku-4-5-20251001',
          max_tokens: 4096,
          messages: [{
            role: 'user',
            content: [
              { type: 'image', source: { type: 'base64', media_type: mediaType || 'image/jpeg', data: image } },
              { type: 'text',  text: prompt },
            ],
          }],
        }),
      });

      if (!aiResp.ok) {
        const errText = await aiResp.text();
        return json({ error: `Claude API error ${aiResp.status}: ${errText.slice(0,200)}` }, 500);
      }

      const aiData = await aiResp.json();
      const raw = (aiData.content?.[0]?.text || '').trim()
        .replace(/^```json\s*/,'').replace(/^```\s*/,'').replace(/```\s*$/,'');

      let events;
      try { events = JSON.parse(raw); }
      catch { return json({ error: 'Claude returned unparseable JSON', raw: raw.slice(0,500) }, 500); }

      return json({ events });
    }

    // Fire an immediate test push to a stored subscription
    if (url.pathname === '/test' && req.method === 'POST') {
      const { subId } = await req.json();
      if (!subId) return json({ error: 'bad request' }, 400);
      const raw = await env.STORE.get(`sub:${subId}`);
      if (!raw) return json({ error: 'no subscription found for this device — open the app first' }, 404);
      const data = JSON.parse(raw);
      const status = await sendPush(data.subscription, {
        title: '🔔 Systematic',
        body:  'Push notifications are working!',
        tag:   'test',
      }, env);
      return json({ ok: status < 300, status });
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
