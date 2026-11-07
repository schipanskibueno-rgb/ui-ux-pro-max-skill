---
name: web-security-shield
description: "Proteção de sites, landing pages, PWAs e apps web contra os ataques mais comuns em projetos feitos com IA: XSS, rotas de API expostas, chaves de API expostas (service_role, Stripe, OpenAI), banco de dados aberto (Supabase sem RLS, Firebase com regras abertas), SQL injection, falta de limite de tentativas (rate limit, força bruta, CAPTCHA), prompt injection em recursos de IA e pacotes inventados/typosquatting (slopsquatting). Inclui scanner automático sem dependências e guias passo a passo para Supabase e Netlify. Use ao criar, revisar ou publicar qualquer site ou app web, ao configurar Supabase, Netlify, Vercel ou Firebase, ao adicionar login, pagamentos, upload, rotas de API ou IA, ou quando o usuário pedir 'segurança', 'proteger o site', 'security review', 'hardening', 'RLS', 'CSP', 'rate limit'."
---

# Web Security Shield – proteção para sites e apps web

Regra de ouro: **o navegador é território do atacante.** Tudo que está no HTML/JS pode ser lido, alterado e chamado por qualquer pessoa. Segurança de verdade mora no **servidor/banco** (RLS, funções protegidas, variáveis de ambiente), nunca em "esconder" código ou botões.

## Quando usar

- Antes de publicar qualquer site/app (gate de pré-deploy).
- Ao criar ou mudar: login, cadastro, pontos/saldo/dinheiro, upload de arquivos, rotas de API, webhooks, pagamentos, recursos de IA.
- Ao configurar Supabase, Firebase, Netlify, Vercel, ou adicionar pacotes npm/pip sugeridos por IA.
- Quando o usuário pedir revisão de segurança, "proteger o site", "hardening".

## Fluxo (siga nesta ordem)

1. **Rode o scanner** na pasta do projeto:
   ```bash
   python3 "<pasta-desta-skill>/scripts/security_scan.py" <pasta-do-projeto>
   python3 "<pasta-desta-skill>/scripts/security_scan.py" <pasta-do-projeto> --online   # também consulta npm/PyPI
   ```
   Trate CRÍTICO e ALTO antes de qualquer outra coisa. O scanner é heurístico: ele aponta o que revisar e não prova que está seguro.
2. **Identifique a stack** (Supabase? Netlify? Next.js? Firebase? IA?) e abra só as referências que se aplicam (tabela abaixo).
3. **Corrija na camada certa**: regra de negócio e permissão no banco/servidor; o front-end só exibe.
4. **Teste o ataque, não só o caminho feliz**: tente, logado como usuário comum, ler dados de outro, se dar pontos/VIP, chamar a rota sem token, repetir 100 vezes, mandar `<img src=x onerror=alert(1)>` em todo campo de texto.
5. **Rode o scanner de novo** e a [checklist de pré-deploy](references/checklist.md).

## Os 8 ataques e onde está a defesa

| # | Ataque | Sinal de alerta | Defesa principal | Referência |
|---|--------|-----------------|------------------|------------|
| 1 | **XSS** | `innerHTML`/`v-html`/`dangerouslySetInnerHTML` com dado do usuário, `eval` | Escapar todo dado (`esc()`/`textContent`), CSP no servidor, sanitizar HTML com DOMPurify | [xss.md](references/xss.md) |
| 2 | **Rotas de API expostas** | Rota que grava sem checar login; CORS `*`; service_role na rota | Verificar usuário e dono do recurso em toda rota; CORS com lista de domínios | [api-exposta.md](references/api-exposta.md) |
| 3 | **Chaves de API expostas** | `service_role`, `sk_live_`, `sk-` no front ou no git; `NEXT_PUBLIC_*SECRET` | Só chave pública no front; segredos em variáveis do servidor; **rotacionar** a que vazou | [chaves-expostas.md](references/chaves-expostas.md) |
| 4 | **Banco de dados aberto** | Tabela sem RLS; `using (true)` em insert/update/delete; Firebase `if true` | RLS em 100% das tabelas; políticas por dono; funções `security definer` com `search_path` | [banco-aberto.md](references/banco-aberto.md), [supabase.md](references/supabase.md) |
| 5 | **SQL injection** | SQL com `${}`/`+`/f-string; `EXECUTE ... \|\|` | Consulta parametrizada; `format('%I %L')`; query builder | [sql-injection.md](references/sql-injection.md) |
| 6 | **Sem limite de tentativas** | Login, cupom, código, IA ou formulário sem limite | Rate limit no servidor (tabela de limites, Upstash, Edge), CAPTCHA, bloqueio progressivo | [limite-tentativas.md](references/limite-tentativas.md) |
| 7 | **Prompt injection** | Texto do usuário no prompt de sistema; resposta da IA no `innerHTML`; IA com ferramentas de shell/SQL | Prompt de sistema fixo; dados como dados; saída tratada como não confiável; ferramentas mínimas com confirmação | [prompt-injection.md](references/prompt-injection.md) |
| 8 | **Pacotes inventados** | Pacote que não existe, muito novo, nome parecido com famoso, CDN sem versão | Conferir no registro antes de instalar; versão fixa + lockfile; SRI em CDN | [pacotes-inventados.md](references/pacotes-inventados.md) |

Guias de plataforma: [supabase.md](references/supabase.md) · [netlify.md](references/netlify.md) · [checklist.md](references/checklist.md)

## Regras inegociáveis (aplique sem o usuário pedir)

1. **Nada de segredo no front-end.** No navegador só vão chaves feitas para serem públicas (Supabase `anon`/`sb_publishable_`, Stripe `pk_`, Firebase config). Se uma secreta vazou, **gere outra**: apagar do código não basta, ela continua no histórico do git e em caches.
2. **RLS ligado em toda tabela do Supabase** e política para cada operação. Sem política = ninguém acessa (seguro). `using (true)` em escrita = qualquer um escreve (inseguro).
3. **Valores que valem dinheiro** (pontos, saldo, VIP, plano, preço, desconto, aprovação) **só mudam por função no servidor** que confere quem chama. Nunca confie em `update` vindo do navegador para esses campos; proteja com trigger ou `revoke`.
4. **Todo dado externo vira texto antes de entrar no HTML** (usuário, banco, URL, IA). Prefira `textContent`; em templates, `esc()` em tudo que não for constante do código.
5. **Toda ação repetível tem limite** no servidor: login, cadastro, pegar cupom, validar código, enviar formulário, chamar IA.
6. **Toda rota de API começa conferindo o usuário** (401 sem login, 403 sem permissão) e valida a entrada (tipo, tamanho, formato).
7. **Pacote novo sugerido por IA é suspeito até provar o contrário**: confira se existe, quem publica, idade e downloads.
8. **Cabeçalhos de segurança** em todo deploy: CSP, HSTS, nosniff, Referrer-Policy, `frame-ancestors 'none'`.
9. **Mensagens de erro genéricas** para o usuário; detalhe só no log do servidor.
10. **Mínimo privilégio**: `revoke execute` em funções internas, `grant` só para `authenticated` quando a ação exige login.

## Como relatar

Para cada achado: **severidade**, **arquivo:linha**, **como explorar** (1 frase, em linguagem simples), **correção** (código), **como testar que foi corrigido**. Ordene por severidade. Seja honesto sobre o que não foi possível verificar (ex.: configurações que só existem no painel do Supabase/Netlify), e diga ao usuário exatamente onde clicar.

## O que esta skill NÃO faz

Não substitui pentest profissional, não verifica configurações que só existem nos painéis (Auth do Supabase, variáveis da Netlify) e não analisa binários. Para pagamentos, siga sempre o checkout/webhook oficial do provedor, com validação de assinatura no servidor.
