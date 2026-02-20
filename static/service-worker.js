self.addEventListener('install', event => {
  event.waitUntil(caches.open('ddosguard-v1').then(cache => cache.addAll([
    '/', '/static/css/styles.css', '/static/js/main.js', '/manifest.json'
  ])));
});
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request).then(resp => resp || fetch(event.request))
  );
});


