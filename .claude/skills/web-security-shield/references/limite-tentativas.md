# Sem limite de tentativas (força bruta, robôs, abuso)

**O que é:** uma ação pode ser repetida sem parar. Resultado: senhas adivinhadas, códigos de cupom testados em sequência, cadastros falsos em massa, conta da IA estourada, SMS/e-mails cobrados.

**Onde precisa de limite:** login, cadastro, "esqueci a senha", validar código/cupom/QR, pegar cupom, enviar formulário/contato, upload, chamada de IA, qualquer rota de API.

## Camadas
1. **Servidor (obrigatório)** – o limite no navegador é só conforto; o atacante pula o navegador.
2. **CAPTCHA** em cadastro/login/formulários públicos (Cloudflare Turnstile ou hCaptcha).
3. **Bloqueio progressivo**: depois de N erros, espera crescente (1, 2, 5, 10 min).
4. **Códigos longos e aleatórios** (`gen_random_uuid`, `crypto.getRandomValues`) – nunca sequenciais.
5. **Mensagens que não revelam**: "Se o e-mail existir, enviamos o link" (não confirma quem tem conta).

## Supabase Auth (painel)
- Authentication > **Rate Limits**: ajuste e-mails/hora, verificações, refresh de token, sign-in/sign-up por IP.
- Authentication > **Attack Protection**: ative **CAPTCHA** (Turnstile/hCaptcha) e mande o token: `supabase.auth.signInWithPassword({ email, password, options: { captchaToken } })`.
- Authentication > Providers > Email: **Confirm email** ligado; senha mínima 8+ e "leaked password protection" (planos pagos).

## Limite dentro do Postgres (funciona com supabase.rpc)
```sql
create table if not exists public.limites (chave text primary key, inicio timestamptz not null default now(), qtd int not null default 0);
alter table public.limites enable row level security;            -- sem políticas: ninguém de fora mexe
revoke all on public.limites from anon, authenticated;

create or replace function public.checar_limite(p_chave text, p_max int, p_janela interval) returns void
language plpgsql security definer set search_path = '' as $$
declare v int;
begin
  insert into public.limites as l (chave, inicio, qtd) values (p_chave, now(), 1)
  on conflict (chave) do update set
    qtd    = case when l.inicio < now() - p_janela then 1 else l.qtd + 1 end,
    inicio = case when l.inicio < now() - p_janela then now() else l.inicio end
  returning qtd into v;
  if v > p_max then raise exception 'Muitas tentativas. Aguarde alguns minutos.' using errcode = 'P0001'; end if;
end $$;
revoke execute on function public.checar_limite(text,int,interval) from public, anon, authenticated;  -- só outras funções usam

-- uso dentro de uma função do app:
perform public.checar_limite('cupom:' || auth.uid(), 20, interval '1 day');
```
Chave por **usuário** (`auth.uid()`), por **recurso atacado** (`'scan:' || empresa_id`) ou ambos. Limpe a tabela de vez em quando (`delete from public.limites where inicio < now() - interval '7 days'`, via pg_cron).

## Netlify / Vercel / Node
- **Netlify**: regras de *Rate limiting* no painel (Site configuration > Security, planos que oferecem) ou Edge Function com contador em KV/Upstash.
- **Upstash Ratelimit** (Redis serverless): `new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(10, "1 m") })` e `await ratelimit.limit(ip ou userId)`.
- **Express**: `express-rate-limit` (por IP) + limite por usuário nas rotas autenticadas.
- Atrás de proxy, use o IP certo (`x-nf-client-connection-ip` na Netlify; `trust proxy` no Express).

## No navegador (complemento, não proteção)
Desabilite o botão enquanto envia, mostre "Aguarde N segundos" depois de 5 erros. Isso melhora a experiência; a segurança é a do servidor.

## Como testar
Rode um laço de 100 chamadas (console ou script) e confirme que a partir do limite volta erro 429/"Muitas tentativas".
