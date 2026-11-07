# Supabase – passo a passo de proteção

## 1. Chaves
- No site: **Project URL** + chave **anon / publishable**. Nunca `service_role` / `sb_secret_`.
- `service_role` só em Edge Functions (`supabase secrets set`) ou servidor.
- Vazou a service_role? Settings > API Keys: gere nova/rotacione o JWT secret **na hora**.

## 2. Banco (SQL Editor)
- [ ] `alter table ... enable row level security;` em **todas** as tabelas do schema `public`.
- [ ] Uma política por operação (select/insert/update/delete), sempre com `auth.uid()`; nada de `using (true)` em escrita.
- [ ] Colunas sensíveis (saldo, pontos, VIP, plano, aprovado, papel) protegidas por trigger, privilégio de coluna ou tabela separada gravada só por função.
- [ ] Funções `security definer` com `set search_path = ''`, checagem de `auth.uid()` dentro, `revoke execute ... from public, anon` e `grant` só para quem usa.
- [ ] Limite de tentativas nas funções sensíveis ([limite-tentativas.md](limite-tentativas.md)).
- [ ] Views com `security_invoker = true`.
- [ ] **Database > Advisors > Security Advisor**: zerar os alertas (RLS desativado, search_path mutável, etc.).

Teste de fogo (console do navegador, logado como usuário comum):
```js
const { data } = await supabase.from('perfis').select('*');                // deve vir só o seu
await supabase.from('perfis').update({ vip_ate: '2099-01-01' }).eq('id', (await supabase.auth.getUser()).data.user.id); // não deve mudar
await supabase.rpc('admin_dar_vip', { p_cliente: '...', p_dias: 365 });    // deve dar erro
```

## 3. Storage
- [ ] Bucket com `file_size_limit` (ex.: 2 MB) e `allowed_mime_types` (`image/jpeg`, `image/png`, `image/webp`).
- [ ] Políticas por pasta do usuário: `(storage.foldername(name))[1] = auth.uid()::text`.
- [ ] Bucket público só para o que pode ser público (fotos de produtos). Documentos pessoais: bucket privado + URL assinada com expiração.
- [ ] Não aceite SVG/HTML de usuários (podem carregar script).

## 4. Authentication (painel)
- [ ] **Providers > Email**: "Confirm email" ligado; senha mínima **8+**; "Secure password change" ligado.
- [ ] **URL Configuration**: *Site URL* = seu domínio; *Redirect URLs* = só seus domínios (nada de `*`). Evita roubo de link de login/recuperação.
- [ ] **Attack Protection**: CAPTCHA (Turnstile/hCaptcha) em cadastro, login e recuperação de senha.
- [ ] **Rate Limits**: revise os valores (e-mails, sign-ups e sign-ins por hora).
- [ ] **SMTP próprio** (Resend, Brevo, SES) em produção: o SMTP padrão tem limite baixo e cai em spam.
- [ ] **MFA** para contas de administrador.
- [ ] Sessões: tempo de expiração razoável (Settings > Auth > Sessions, quando disponível).

## 5. API (Settings > API / Data API)
- [ ] Exponha só o schema `public` (e o que precisar). Tabelas internas em outro schema não exposto.
- [ ] *Max rows* com um teto (ex.: 1000) para evitar despejo do banco inteiro numa chamada.

## 6. Operação
- [ ] **Backups** (Point-in-Time Recovery em produção paga, ou `pg_dump` agendado).
- [ ] Logs (Logs Explorer) de Auth e API olhados depois do lançamento.
- [ ] Projeto de **teste** separado do de produção.
- [ ] Admins na tabela `admins` com MFA; nunca "admin" decidido por campo que o próprio usuário edita.
