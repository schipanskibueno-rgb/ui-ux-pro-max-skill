# Banco de dados aberto

**O que é:** o banco aceita leitura/escrita de qualquer pessoa. No Supabase, a URL e a chave `anon` estão no site; se uma tabela estiver **sem RLS** (Row Level Security), qualquer pessoa pode, com 1 linha de JS no console, listar todos os clientes, mudar preços, se dar saldo ou apagar tudo.

```js
// Qualquer visitante, no console do navegador:
await supabase.from('perfis').update({ pontos: 999999 }).eq('id', meuId)   // funciona se faltar RLS/proteção
```

## Supabase / Postgres – padrão seguro
```sql
alter table public.pedidos enable row level security;                    -- 1. SEMPRE
create policy "ver os meus"  on public.pedidos for select using (cliente = auth.uid());
create policy "criar o meu"  on public.pedidos for insert to authenticated with check (cliente = auth.uid());
-- sem política de update/delete = ninguém altera/apaga pelo app (seguro)
```

### Campos que valem dinheiro (pontos, saldo, VIP, plano, aprovado, preço)
O RLS libera a **linha**, não a **coluna**. Se o usuário pode dar `update` no próprio perfil, ele pode mudar `vip_ate` também. Opções:
1. **Trigger que trava colunas** (o valor antigo volta se não for admin):
   ```sql
   create or replace function public.protege_perfil() returns trigger
   language plpgsql security definer set search_path = '' as $$
   begin
     if not public.is_admin() then new.vip_ate := old.vip_ate; new.saldo := old.saldo; end if;
     return new;
   end $$;
   ```
2. **Tabela separada** só gravada por função (`pontos_mov` como livro-caixa, sem política de insert).
3. **Privilégio de coluna**: `revoke update on public.perfis from authenticated; grant update (nome, whatsapp) on public.perfis to authenticated;`

### Funções `security definer`
Rodam com poder de dono (ignoram RLS). Obrigatório:
- `set search_path = ''` e nomes completos (`public.tabela`) – evita sequestro por objeto com mesmo nome.
- Conferir `auth.uid()` e permissões **dentro** da função.
- `revoke execute on function x from public, anon, authenticated;` para funções internas; `grant execute ... to authenticated` só nas que o app chama.
- Travar linhas disputadas (`select ... for update`) para evitar uso duplo por cliques simultâneos.

### Também verifique
- **Storage**: bucket com limite de tamanho e tipos (`image/jpeg`, `image/png`, `image/webp`), políticas por pasta do usuário (`(storage.foldername(name))[1] = auth.uid()::text`).
- **Views**: crie com `with (security_invoker = true)`, senão ignoram o RLS.
- **Realtime**: só publique tabelas que o usuário já pode ler.
- **Security Advisor** do Supabase (Database > Advisors) sem alertas vermelhos.

## Firebase
```
// ERRADO
allow read, write: if true;
// CERTO
match /pedidos/{id} { allow read, write: if request.auth != null && request.auth.uid == resource.data.dono; }
```

## Outros bancos
- Postgres/MySQL/Mongo/Redis **nunca** expostos direto na internet: firewall, IP permitido, senha forte, TLS.
- Usuário do app sem permissão de `DROP`/`ALTER`.

## Como testar (obrigatório antes de publicar)
Logado como **cliente comum**, no console do navegador:
```js
await supabase.from('TABELA').select('*')                       // vê só o que deveria?
await supabase.from('TABELA').update({ campo_caro: 999 }).eq('id', 'meu-id')   // valor não muda?
await supabase.from('TABELA').delete().neq('id', '0')           // não apaga nada?
await supabase.rpc('funcao_admin', {...})                        // erro de permissão?
```
Repita deslogado (anon).
