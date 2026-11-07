// Vitrine Castro – service worker: funciona offline e permite instalar o app.
// Segurança: só guarda arquivos do PRÓPRIO site. Chamadas ao Supabase (dados,
// login, pontos) nunca passam pelo cache: sempre vão direto para a internet.
const CACHE = "vitrine-v5";
const ARQUIVOS = ["./", "./index.html", "./manifest.webmanifest", "./config.js", "./empresa.html", "./icons/icon-192.png", "./icons/icon-512.png",
  "./img/b_vs.jpg", "./img/vs_logo.jpg", "./img/cat1.jpg", "./img/cat2.jpg", "./img/cat3.jpg", "./img/cat4.jpg",
  "./img/of1.jpg", "./img/of2.jpg", "./img/of3.jpg", "./img/of4.jpg"];
self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(ARQUIVOS))); self.skipWaiting(); });
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
// Sempre tenta a versão nova da internet; sem internet, usa a cópia salva
self.addEventListener("fetch", e => {
  const req = e.request;
  if (req.method !== "GET" || new URL(req.url).origin !== location.origin) return; // outros sites: o navegador resolve sozinho
  e.respondWith(
    fetch(req).then(r => {
      if (r.ok && r.type === "basic") { const copia = r.clone(); caches.open(CACHE).then(c => c.put(req, copia)); }
      return r;
    }).catch(() => caches.match(req).then(r => r || (req.mode === "navigate" ? caches.match("./index.html") : Response.error())))
  );
});
