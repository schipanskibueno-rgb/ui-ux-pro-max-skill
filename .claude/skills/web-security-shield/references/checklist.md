# Checklist de pré-deploy (segurança)

Marque tudo antes de publicar. Itens com ★ são os que mais vazam dados em sites feitos com IA.

## Código
- [ ] ★ `security_scan.py` sem CRÍTICO/ALTO (`--online` se houver package.json/requirements.txt)
- [ ] ★ Nenhuma chave secreta no front-end, no repositório ou em variável com prefixo público
- [ ] ★ Todo dado externo escapado antes de ir para o HTML; nenhum `eval`
- [ ] Links `target=_blank` com `rel="noopener noreferrer"`; URLs externas só `https://`
- [ ] Mensagens de erro genéricas para o usuário
- [ ] Pacotes conferidos (existem, conhecidos, versão fixa, lockfile); CDN com versão exata + SRI

## Banco / back-end
- [ ] ★ RLS em todas as tabelas; políticas por operação; nada de `(true)` em escrita
- [ ] ★ Valores que valem dinheiro (pontos, saldo, VIP, plano, preço, aprovação) só mudam por função no servidor
- [ ] Funções `security definer` com `search_path` fixo, checagem de `auth.uid()`, `revoke`/`grant` corretos
- [ ] ★ Rotas de API: 401 sem login, 403 sem permissão, 400 para entrada inválida
- [ ] ★ Limite de tentativas em login, cadastro, códigos/cupons, formulários, IA
- [ ] Upload: tamanho e tipo limitados; pasta por usuário; sem SVG/HTML de usuário
- [ ] Webhooks com assinatura validada e processamento idempotente

## Plataforma
- [ ] Supabase: confirmação de e-mail, senha 8+, Redirect URLs restritas, CAPTCHA, Security Advisor zerado
- [ ] Netlify/Vercel: cabeçalhos de segurança, HTTPS forçado, só a pasta pública publicada, segredos em variáveis de ambiente
- [ ] 2FA nas contas (GitHub, Netlify, Supabase, provedor de pagamento, domínio)
- [ ] Backup do banco configurado

## IA (se houver)
- [ ] Chave só no servidor; prompt de sistema fixo; saída da IA escapada; ferramentas mínimas; `max_tokens` e limite de gasto

## Teste de ataque (10 minutos)
- [ ] Logado como cliente comum: tentar ler dados de outro, mudar campo caro, chamar função de admin → tudo bloqueado
- [ ] Deslogado: mesmas tentativas → bloqueadas
- [ ] `<img src=x onerror=alert(1)>` em todos os campos de texto → aparece como texto
- [ ] 100 chamadas seguidas na ação sensível → bloqueia
- [ ] Console do navegador sem erros de CSP no site publicado
