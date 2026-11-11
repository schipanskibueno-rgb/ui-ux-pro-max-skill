// Vitrine Castro – service worker: funciona offline e permite instalar o app
const CACHE = "vitrine-v17";
const ARQUIVOS = ["./", "./index.html", "./manifest.webmanifest", "./config.js", "./empresa.html", "./admin.html", "./icons/icon-192.png", "./icons/icon-512.png", "./icons/apple-touch-icon.png",
  "./img/logo-simbolo.png", "./img/logo-palavra.png", "./img/b_vs.jpg", "./img/vs_logo.jpg", "./img/cat1.jpg", "./img/cat2.jpg", "./img/cat3.jpg", "./img/cat4.jpg",
  "./img/of1.jpg", "./img/of2.jpg", "./img/of3.jpg", "./img/of4.jpg"];
self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(ARQUIVOS))); self.skipWaiting(); });
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
// Só cuida dos arquivos do próprio site. Bibliotecas, fontes e o banco (Supabase)
// vão direto pela internet, sem passar por aqui.
// Sempre tenta a versão nova; sem internet, usa a cópia salva.
self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  if (new URL(e.request.url).origin !== location.origin) return;
  e.respondWith(
    fetch(e.request).then(r => {
      if (r.ok) { const copia = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copia)); }
      return r;
    }).catch(() => caches.match(e.request).then(r => r || (e.request.mode === "navigate" ? caches.match("./index.html") : Response.error())))
  );
});
