# Netlify – passo a passo de proteção

## 1. Cabeçalhos de segurança (`netlify.toml` na raiz publicada)
```toml
[[headers]]
  for = "/*"
  [headers.values]
    Content-Security-Policy = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob: https://*.supabase.co; connect-src 'self' https://*.supabase.co wss://*.supabase.co; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'; upgrade-insecure-requests"
    Strict-Transport-Security = "max-age=31536000; includeSubDomains"
    X-Content-Type-Options = "nosniff"
    Referrer-Policy = "strict-origin-when-cross-origin"
    Permissions-Policy = "camera=(), microphone=(), geolocation=()"
    X-Frame-Options = "DENY"
```
- Ajuste a CSP às CDNs e APIs que o site realmente usa. Teste no navegador (Console mostra "Refused to load..." se faltar algo).
- Se o site usa `onclick="..."`/`<script>` inline, precisa de `'unsafe-inline'` em `script-src` (protege menos). O ideal é mover o JS para arquivos e usar `addEventListener`.
- Confira em https://securityheaders.com depois do deploy.

## 2. Não publicar o que não é público
- Publique só a pasta do site (`[build] publish = "dist"` ou uma pasta `public/`), não o repositório inteiro.
- Bloqueie arquivos internos que precisem ficar na pasta:
  ```toml
  [[redirects]]
    from = "/supabase.sql"
    to = "/404.html"
    status = 404
    force = true
  ```
- Nunca suba `.env`, `.sql` com dados, backups, `.git`.

## 3. Segredos
- Site configuration > **Environment variables** (marque como secret). Só Functions/Edge Functions e o build leem.
- Variáveis usadas no build de frameworks com prefixo público (`VITE_`, `NEXT_PUBLIC_`) **vão para o navegador**: só valores públicos.
- Ative **Secrets scanning** do deploy (Netlify bloqueia o deploy se achar segredo no bundle).

## 4. Functions
- Toda Function confere o usuário (token Supabase) e valida a entrada ([api-exposta.md](api-exposta.md)).
- Responda CORS só para seus domínios.
- Rate limit (Edge + Upstash/KV, ou regras de rate limiting do plano).

## 5. Conta e deploys
- **2FA** na conta Netlify e no GitHub.
- **Deploy previews / branch deploys**: proteja com senha (Site configuration > Access & security > Visitor access) ou desative se expõem versões com dados de teste.
- Domínio próprio com **HTTPS forçado** (Domain management > HTTPS > Force).
- **Forms da Netlify**: ative o filtro de spam e adicione campo honeypot (`netlify-honeypot="bot-field"`).

## 6. Depois de publicar
- Rode `security_scan.py` na pasta publicada.
- Teste cabeçalhos (securityheaders.com) e abra o site com o Console aberto: nenhum erro de CSP.
