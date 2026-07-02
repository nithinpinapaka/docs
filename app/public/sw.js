// Bump to force clients onto the new worker (and new notification icons)
const SW_VERSION = 2;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(clients.claim()));

self.addEventListener('push', (event) => {
  const data = event.data?.json() ?? {};
  event.waitUntil(
    self.registration.showNotification(data.title ?? 'Notification', {
      body: data.body ?? '',
      icon: '/icons/icon-192.png',
      // badge is the Android status-bar icon: must be monochrome
      badge: '/icons/badge-96.png',
      data: { url: data.url ?? '/' },
    }),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = event.notification.data?.url ?? '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windows) => {
      const existing = windows.find((w) => new URL(w.url).pathname === url);
      return existing ? existing.focus() : clients.openWindow(url);
    }),
  );
});
