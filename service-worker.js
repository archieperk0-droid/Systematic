const CACHE = 'systematic-v12';

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(['./'])));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  const isHtml = url.pathname.endsWith('/') || url.pathname.endsWith('.html');

  if (isHtml) {
    // Network-first for the main page so the user always gets the latest code.
    // Falls back to cache only when offline.
    e.respondWith(
      fetch(e.request, { cache: 'no-store' })
        .then(res => {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
          return res;
        })
        .catch(() => caches.match(e.request).then(r => r || caches.match('./')))
    );
  } else {
    // Cache-first for assets (icons, fonts, etc.)
    e.respondWith(
      caches.match(e.request).then(r => r || fetch(e.request).catch(() => caches.match('./')))
    );
  }
});

// Receive push from server → show notification on lock screen
self.addEventListener('push', e => {
  const data = e.data?.json() || {};
  e.waitUntil(
    self.registration.showNotification(data.title || 'Systematic', {
      body:     data.body  || '',
      icon:     './icon-192.png',
      badge:    './icon-192.png',
      tag:      data.tag   || 'systematic',
      renotify: true,
      data:     { url: './' },
    })
  );
});

// Tap notification → open app
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      const open = list.find(c => c.url.includes('Systematic') || c.url.includes('systematic'));
      if (open) return open.focus();
      return self.clients.openWindow('./');
    })
  );
});
