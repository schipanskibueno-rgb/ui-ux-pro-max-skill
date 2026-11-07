# Chaves de API expostas

**O que é:** uma chave secreta (que dá poder total sobre um serviço) está no código do site, num repositório público ou numa variável que vai para o navegador. Robôs varrem o GitHub e sites o tempo todo atrás disso; o abuso começa em minutos (cobranças na OpenAI/AWS, banco apagado, e-mails de spam).

## O que PODE ir para o navegador (público por natureza)
| Serviço | Pode | NUNCA |
|---|---|---|
| Supabase | URL do projeto, `anon` / `sb_publishable_...` | `service_role` / `sb_secret_...`, senha do banco, JWT secret |
| Stripe | `pk_live_` / `pk_test_` | `sk_live_`, `rk_live_`, `whsec_` |
| Firebase | objeto `firebaseConfig` | Service account JSON |
| Google Maps | chave com restrição de domínio | chave sem restrição |
| OpenAI / Anthropic / Gemini | — (nenhuma) | qualquer chave |
| Mercado Pago | Public key | Access token (`APP_USR-...`) |

A chave `anon` do Supabase **é pública**: quem protege seus dados é o RLS ([banco-aberto.md](banco-aberto.md)).

## Onde colocar segredos
- **Netlify**: Site configuration > Environment variables (marque "Contains secret values"). Só Functions/Edge Functions leem.
- **Supabase Edge Functions**: `supabase secrets set NOME=valor`.
- **Vercel**: Settings > Environment Variables.
- **Local**: arquivo `.env` **no `.gitignore`** + um `.env.example` sem valores.
- **Cuidado com prefixos públicos**: `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `PUBLIC_`, `EXPO_PUBLIC_` são embutidos no JavaScript do navegador.

## Vazou? Faça nesta ordem
1. **Gere uma chave nova e revogue a antiga no painel do serviço** (Supabase: Settings > API Keys / JWT; Stripe: Developers > API keys > Roll key). Apagar do código NÃO resolve: ela está no histórico do git, em forks e caches.
2. Atualize a chave nova nas variáveis de ambiente e faça deploy.
3. Veja os logs/cobranças do serviço desde o vazamento.
4. Remova do histórico se o repositório for público (`git filter-repo` / BFG) e force push. Mesmo assim, considere a antiga comprometida.
5. Ative proteção: GitHub > Settings > Code security > Secret scanning + Push protection.

## Prevenção
- Rode o scanner antes de cada commit/deploy.
- Opcional: `gitleaks protect --staged` num hook de pre-commit.
- Chaves com **menor permissão possível** e **limite de gasto** (OpenAI/Anthropic: usage limits; Google: restrição de API e de referrer).
