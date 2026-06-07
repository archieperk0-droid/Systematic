const CACHE = 'systematic-v4';

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
  e.respondWith(
    caches.match(e.request).then(r => r || fetch(e.request).catch(() => caches.match('./')))
  );
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
