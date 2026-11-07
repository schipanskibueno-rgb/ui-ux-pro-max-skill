# SQL injection

**O que é:** o texto digitado pelo usuário vira parte do comando SQL. Com `' OR 1=1 --` ele lê tudo; com `'; DROP TABLE clientes; --` apaga.

```js
// ERRADO
db.query(`SELECT * FROM clientes WHERE email = '${email}'`);
db.query("SELECT * FROM clientes WHERE email = '" + email + "'");
```

## Certo: parâmetros (o banco trata o valor como dado, nunca como comando)
```js
// node-postgres
await db.query("SELECT * FROM clientes WHERE email = $1", [email]);
// postgres.js / Prisma (tagged template parametriza sozinho)
await sql`SELECT * FROM clientes WHERE email = ${email}`;
await prisma.$queryRaw`SELECT * FROM clientes WHERE email = ${email}`;   // NUNCA $queryRawUnsafe com texto do usuário
```
```python
cur.execute("SELECT * FROM clientes WHERE email = %s", (email,))       # nunca f"...{email}"
```
```php
$st = $pdo->prepare("SELECT * FROM clientes WHERE email = ?"); $st->execute([$email]);
```

## Supabase
- `supabase.from().select().eq('email', email)` e `supabase.rpc('fn', { p: valor })` já são parametrizados.
- Cuidado com filtros montados como texto: `.or(\`nome.ilike.%${busca}%\`)` deixa o usuário injetar outros filtros (vírgulas, parênteses). Limpe: `busca.replace(/[,().*%]/g, "")` ou use `.ilike('nome', \`%${limpo}%\`)`.
- Dentro de funções plpgsql com SQL dinâmico:
  ```sql
  execute format('select count(*) from %I where dono = %L', nome_tabela, p_dono);   -- %I identificador, %L literal
  execute 'select * from t where id = $1' using p_id;
  -- NUNCA: execute 'select * from ' || p_tabela || ' where id = ' || p_id;
  ```
- Nomes de coluna/ordenação escolhidos pelo usuário: use **lista permitida** (`if (!["nome","preco"].includes(col)) col = "nome"`).

## Extra
- Usuário do banco do app sem permissão de DDL.
- Validação de entrada (tipo, tamanho) antes de chegar no banco: reduz superfície, mas **não substitui** parâmetros.
