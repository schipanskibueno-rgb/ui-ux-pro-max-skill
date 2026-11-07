# Rotas de API expostas

**O que é:** uma rota (`/api/...`, Netlify Function, Edge Function, Express) que faz algo importante sem conferir **quem** está chamando e **se pode**. Qualquer pessoa descobre a rota abrindo o DevTools (aba Rede) e chama direto, sem passar pela tela.

## Erros típicos
- Rota grava/apaga sem verificar login.
- Verifica login, mas não verifica **dono** (`/api/pedidos/123` devolve pedido de outra pessoa — IDOR).
- Usa `SUPABASE_SERVICE_ROLE_KEY` (ignora RLS) e confia no `user_id` que veio no corpo da requisição.
- CORS `Access-Control-Allow-Origin: *`, principalmente com cookies.
- Devolve `error.stack` ou mensagem do banco para o cliente.
- Webhook de pagamento que não confere a assinatura.

## Modelo seguro (Netlify Function / Next.js route com Supabase)
```ts
export async function POST(req: Request) {
  // 1. Quem é?
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  if (!token) return new Response("Não autorizado", { status: 401 });
  const supa = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!, {
    global: { headers: { Authorization: `Bearer ${token}` } } });       // usa a chave ANON + token do usuário: o RLS continua valendo
  const { data: { user } } = await supa.auth.getUser(token);
  if (!user) return new Response("Não autorizado", { status: 401 });

  // 2. Entrada válida? (tipo, tamanho, formato) – nunca confie no corpo
  const body = await req.json().catch(() => null);
  const valor = Number(body?.valor);
  if (!Number.isFinite(valor) || valor <= 0 || valor > 50000) return new Response("Valor inválido", { status: 400 });

  // 3. Pode? (dono do recurso / papel) – de preferência deixe o RLS ou uma função SQL decidir
  const { data, error } = await supa.rpc("confirmar_compra", { p_codigo: body.codigo, p_valor: valor });
  if (error) { console.error(error); return new Response("Não foi possível concluir", { status: 400 }); }
  return Response.json(data);
}
```

## Regras
- **Prefira não ter rota**: com Supabase, a maior parte da lógica pode ser função SQL `security definer` chamada via `supabase.rpc()`, protegida por `auth.uid()`, `revoke`/`grant` e limite de tentativas.
- `service_role` só em servidor, só quando inevitável (tarefas de admin, webhooks), e **sempre** depois de validar quem chamou ou a assinatura do webhook.
- CORS: liste seus domínios (`https://seusite.netlify.app`, domínio próprio). Nunca `*` com credenciais.
- Limite de requisições por usuário/IP em toda rota ([limite-tentativas.md](limite-tentativas.md)).
- Webhooks (Stripe, Mercado Pago, Asaas): valide a assinatura com o segredo do webhook, confira o valor/status consultando a API do provedor e torne o processamento **idempotente** (mesmo evento 2x não credita 2x).
- Erros: mensagem genérica para fora; detalhes só no log.

## Como testar
1. Abra o DevTools > Rede, copie uma chamada como `cURL`.
2. Rode sem o header `Authorization` → deve dar 401.
3. Rode logado como outro usuário trocando IDs → deve dar 403/vazio.
4. Mande valores absurdos (negativo, 10^9, texto, 1 MB) → deve dar 400.
