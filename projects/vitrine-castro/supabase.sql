-- =====================================================================
-- VITRINE CASTRO – Banco de dados (cole tudo no SQL Editor do Supabase e clique em RUN)
-- Cria: empresas, ofertas, administradores, pasta de fotos e as regras de segurança.
-- =====================================================================

-- ---------- ADMINISTRADORES (você) ----------
create table if not exists public.admins (
  user_id uuid primary key references auth.users on delete cascade
);
alter table public.admins enable row level security;
drop policy if exists "admin ve a si mesmo" on public.admins;
create policy "admin ve a si mesmo" on public.admins for select using (user_id = auth.uid());

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins where user_id = auth.uid())
$$;

-- ---------- EMPRESAS ----------
create table if not exists public.empresas (
  id         uuid primary key default gen_random_uuid(),
  dono       uuid not null default auth.uid() references auth.users on delete cascade,
  nome       text not null check (char_length(nome) between 2 and 80),
  ramo       text not null default 'Outro' check (char_length(ramo) <= 60),
  whatsapp   text check (char_length(whatsapp) <= 20),
  endereco   text check (char_length(endereco) <= 150),
  logo_url   text,
  plano      text not null default 'basico' check (plano in ('basico','destaque','premium')),
  aprovada   boolean not null default false,
  criado_em  timestamptz not null default now()
);
-- Cada lojista tem 1 loja. O ADM pode cadastrar várias (ficam marcadas como pelo_adm).
alter table public.empresas add column if not exists pelo_adm boolean not null default false;
drop index if exists public.empresas_um_por_dono;
create unique index empresas_um_por_dono on public.empresas(dono) where not pelo_adm;

-- Só você (admin) pode aprovar e mudar o plano
create or replace function public.protege_empresa() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    if tg_op = 'INSERT' then
      new.aprovada := false; new.plano := 'basico'; new.dono := auth.uid(); new.pelo_adm := false;
    else
      new.aprovada := old.aprovada; new.plano := old.plano; new.dono := old.dono; new.pelo_adm := old.pelo_adm;
    end if;
  elsif tg_op = 'INSERT' and new.dono = auth.uid() then
    new.pelo_adm := true;   -- loja cadastrada pelo ADM: ele pode ter quantas quiser
  end if;
  return new;
end $$;
drop trigger if exists t_protege_empresa on public.empresas;
create trigger t_protege_empresa before insert or update on public.empresas
  for each row execute function public.protege_empresa();

-- Qual loja a pessoa logada está usando agora (o ADM escolhe entre as dele; lojista tem 1 só)
create or replace function public.loja_do_usuario(p_empresa uuid, p_aprovada boolean default false) returns uuid
language plpgsql stable security definer set search_path = public as $$
declare emp uuid;
begin
  select e.id into emp from public.empresas e
   where (e.dono = auth.uid() or (p_empresa is not null and public.is_admin()))
     and (p_empresa is null or e.id = p_empresa)
     and (not p_aprovada or e.aprovada)
   order by e.pelo_adm, e.criado_em limit 1;
  return emp;
end $$;
revoke execute on function public.loja_do_usuario(uuid, boolean) from public, anon, authenticated;

alter table public.empresas enable row level security;
drop policy if exists "empresas ver"     on public.empresas;
drop policy if exists "empresas criar"   on public.empresas;
drop policy if exists "empresas editar"  on public.empresas;
drop policy if exists "empresas apagar"  on public.empresas;
create policy "empresas ver"    on public.empresas for select using (aprovada or dono = auth.uid() or public.is_admin());
create policy "empresas criar"  on public.empresas for insert to authenticated with check (dono = auth.uid());
create policy "empresas editar" on public.empresas for update to authenticated using (dono = auth.uid() or public.is_admin());
create policy "empresas apagar" on public.empresas for delete to authenticated using (public.is_admin());

-- ---------- OFERTAS ----------
create table if not exists public.ofertas (
  id           uuid primary key default gen_random_uuid(),
  empresa_id   uuid not null references public.empresas on delete cascade,
  titulo       text not null check (char_length(titulo) between 2 and 40),   -- ex: 20% OFF
  descricao    text not null check (char_length(descricao) <= 300),
  regras       text check (char_length(regras) <= 200),
  categoria    text not null default 'vest' check (char_length(categoria) <= 20),
  foto_url     text,
  validade     date,
  economia     numeric not null default 0 check (economia >= 0 and economia < 100000),
  ativa        boolean not null default true,
  destaque     boolean not null default false,   -- só admin
  banner       boolean not null default false,   -- só admin (banner do topo)
  banner_topo  text check (char_length(banner_topo) <= 20),
  criado_em    timestamptz not null default now()
);
create index if not exists ofertas_empresa on public.ofertas(empresa_id);

-- Destaque/banner só admin + limite de ofertas ativas por plano
create or replace function public.protege_oferta() returns trigger
language plpgsql security definer set search_path = public as $$
declare pl text; lim int; qtd int;
begin
  if not public.is_admin() then
    if tg_op = 'UPDATE' then new.empresa_id := old.empresa_id; end if;
    select plano into pl from public.empresas where id = new.empresa_id;
    if tg_op = 'INSERT' then
      new.destaque := false;
      if pl is distinct from 'premium' then new.banner := false; end if;          -- banner do topo: só plano Premium
    else
      new.destaque := old.destaque;
      if pl is distinct from 'premium' then new.banner := old.banner; end if;
    end if;
  end if;
  if new.ativa then
    select plano into pl from public.empresas where id = new.empresa_id;
    lim := case pl when 'basico' then 1 when 'destaque' then 3 else 1000 end;
    select count(*) into qtd from public.ofertas where empresa_id = new.empresa_id and ativa and id <> new.id;
    if qtd >= lim then
      raise exception 'Seu plano permite % oferta(s) ativa(s) ao mesmo tempo. Pause outra oferta ou mude de plano.', lim;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists t_protege_oferta on public.ofertas;
create trigger t_protege_oferta before insert or update on public.ofertas
  for each row execute function public.protege_oferta();

alter table public.ofertas enable row level security;
drop policy if exists "ofertas ver"     on public.ofertas;
drop policy if exists "ofertas criar"   on public.ofertas;
drop policy if exists "ofertas editar"  on public.ofertas;
drop policy if exists "ofertas apagar"  on public.ofertas;
create policy "ofertas ver" on public.ofertas for select using (
  (ativa and (validade is null or validade >= current_date)
     and exists (select 1 from public.empresas e where e.id = empresa_id and e.aprovada))
  or exists (select 1 from public.empresas e where e.id = empresa_id and e.dono = auth.uid())
  or public.is_admin());
create policy "ofertas criar" on public.ofertas for insert to authenticated with check (
  exists (select 1 from public.empresas e where e.id = empresa_id and e.dono = auth.uid()) or public.is_admin());
create policy "ofertas editar" on public.ofertas for update to authenticated using (
  exists (select 1 from public.empresas e where e.id = empresa_id and e.dono = auth.uid()) or public.is_admin());
create policy "ofertas apagar" on public.ofertas for delete to authenticated using (
  exists (select 1 from public.empresas e where e.id = empresa_id and e.dono = auth.uid()) or public.is_admin());

-- ---------- ENTREGA (nova opção do post) ----------
-- 'sim' = a loja entrega (aparece o botão "Pedir com entrega") | 'retirada' = só na loja
alter table public.ofertas add column if not exists entrega text not null default 'sim';
alter table public.ofertas drop constraint if exists ofertas_entrega_check;
alter table public.ofertas add constraint ofertas_entrega_check check (entrega in ('sim','retirada'));

-- ---------- PREÇO "DE/POR", REGRAS DA OFERTA E HORÁRIO DA LOJA ----------
alter table public.ofertas add column if not exists preco_de  numeric(10,2) check (preco_de  is null or (preco_de  > 0 and preco_de  < 1000000));
alter table public.ofertas add column if not exists preco_por numeric(10,2) check (preco_por is null or (preco_por >= 0 and preco_por < 1000000));
alter table public.ofertas add column if not exists limite_cupons int check (limite_cupons is null or limite_cupons between 1 and 100000); -- "Restam X cupons"
alter table public.ofertas add column if not exists um_por_cliente boolean not null default true;                                      -- 1 cupom por pessoa
alter table public.ofertas add column if not exists dias text check (dias is null or dias ~ '^[0-6](,[0-6]){0,6}$');                     -- dias da semana válidos (0=domingo)
alter table public.ofertas add column if not exists hora_ini time;
alter table public.ofertas add column if not exists hora_fim time;
alter table public.ofertas add column if not exists inicia_em date;                                                                     -- oferta agendada
alter table public.empresas add column if not exists abre time;
alter table public.empresas add column if not exists fecha time;
alter table public.empresas add column if not exists dias_func text check (dias_func is null or dias_func ~ '^[0-6](,[0-6]){0,6}$');
alter table public.empresas add column if not exists instagram text check (instagram is null or instagram ~ '^[A-Za-z0-9._]{1,40}$');

-- ---------- NÚMEROS DO EMPRESÁRIO (visualizações, cupons, entregas, compras) ----------
-- O app registra o que acontece com cada oferta. Ninguém lê nem grava estas tabelas direto:
-- só pelas funções abaixo. Não guarda nome nem telefone do cliente, só um código aleatório do aparelho.
create table if not exists public.eventos (
  id         bigint generated always as identity primary key,
  oferta_id  uuid not null references public.ofertas on delete cascade,
  empresa_id uuid not null references public.empresas on delete cascade,
  tipo       text not null check (tipo in ('aparicao','visualizacao','whatsapp','cupom','entrega','compra')),
  aparelho   text check (char_length(aparelho) <= 40),
  valor      numeric(10,2),
  dia        date not null default current_date,
  criado_em  timestamptz not null default now()
);
-- a mesma pessoa conta 1 aparição e 1 visualização por oferta por dia
create unique index if not exists eventos_1_por_dia on public.eventos (oferta_id, tipo, aparelho, dia) where tipo in ('aparicao','visualizacao');
create index if not exists eventos_empresa_dia on public.eventos (empresa_id, dia);
create index if not exists eventos_aparelho_dia on public.eventos (aparelho, dia);
alter table public.eventos enable row level security;
revoke all on public.eventos from anon, authenticated;

-- Cupons oficiais: o código é criado aqui, então a loja consegue conferir se é verdadeiro e se já foi usado
create table if not exists public.cupons (
  codigo     text primary key,
  oferta_id  uuid not null references public.ofertas on delete cascade,
  empresa_id uuid not null references public.empresas on delete cascade,
  aparelho   text check (char_length(aparelho) <= 40),
  criado_em  timestamptz not null default now(),
  usado_em   timestamptz,
  valor      numeric(10,2)
);
create index if not exists cupons_aparelho on public.cupons (aparelho, criado_em);
alter table public.cupons enable row level security;
revoke all on public.cupons from anon, authenticated;

-- Conta as tentativas de consultar código (contra quem tenta adivinhar cupons)
create table if not exists public.tentativas (
  empresa_id uuid not null,
  criado_em  timestamptz not null default now()
);
create index if not exists tentativas_empresa on public.tentativas (empresa_id, criado_em);
alter table public.tentativas enable row level security;
revoke all on public.tentativas from anon, authenticated;

-- App do cliente: registra aparição, visualização, clique no WhatsApp ou pedido de entrega
create or replace function public.registrar_evento(p_oferta uuid, p_tipo text, p_aparelho text) returns void
language plpgsql security definer set search_path = public as $$
declare emp uuid;
begin
  if p_tipo not in ('aparicao','visualizacao','whatsapp','entrega') then return; end if;
  if p_aparelho is null or p_aparelho !~ '^[a-z0-9]{12,40}$' then return; end if;
  select o.empresa_id into emp from public.ofertas o join public.empresas e on e.id = o.empresa_id
   where o.id = p_oferta and o.ativa and e.aprovada;
  if emp is null then return; end if;
  if (select count(*) from public.eventos where aparelho = p_aparelho and dia = current_date) >= 300 then return; end if; -- limite por aparelho/dia
  insert into public.eventos (oferta_id, empresa_id, tipo, aparelho) values (p_oferta, emp, p_tipo, p_aparelho)
  on conflict do nothing;
end $$;

-- App do cliente: cria o código oficial do cupom (máx. 30 cupons por aparelho por dia)
create or replace function public.emitir_cupom(p_oferta uuid, p_aparelho text) returns text
language plpgsql security definer set search_path = public as $$
declare o public.ofertas; cod text; tent int := 0;
begin
  if p_aparelho is null or p_aparelho !~ '^[a-z0-9]{12,40}$' then return null; end if;
  select * into o from public.ofertas where id = p_oferta for update;          -- uma emissão por vez (o limite não estoura)
  if not found or not o.ativa
     or (o.validade is not null and o.validade < current_date)
     or (o.inicia_em is not null and o.inicia_em > current_date)               -- oferta agendada ainda não começou
     or not exists (select 1 from public.empresas e where e.id = o.empresa_id and e.aprovada) then
    return null;
  end if;
  select codigo into cod from public.cupons where oferta_id = p_oferta and aparelho = p_aparelho and usado_em is null limit 1;
  if cod is not null then return cod; end if;
  if o.um_por_cliente and exists (select 1 from public.cupons where oferta_id = p_oferta and aparelho = p_aparelho) then
    return 'JA_USOU';                                                         -- 1 cupom por pessoa
  end if;
  if o.limite_cupons is not null and (select count(*) from public.cupons where oferta_id = p_oferta) >= o.limite_cupons then
    return 'ESGOTADO';                                                        -- acabaram os cupons
  end if;
  if (select count(*) from public.cupons where aparelho = p_aparelho and criado_em > now() - interval '1 day') >= 30 then return null; end if;
  loop
    cod := 'VC-' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 6));
    begin
      insert into public.cupons (codigo, oferta_id, empresa_id, aparelho) values (cod, p_oferta, o.empresa_id, p_aparelho);
      exit;
    exception when unique_violation then
      tent := tent + 1; if tent > 5 then return null; end if;
    end;
  end loop;
  insert into public.eventos (oferta_id, empresa_id, tipo, aparelho) values (p_oferta, o.empresa_id, 'cupom', p_aparelho);
  return cod;
end $$;

-- App do cliente: quantos cupons já saíram de cada oferta (para mostrar "Restam X")
create or replace function public.cupons_usados(p_ofertas uuid[]) returns table (oferta_id uuid, qtd bigint)
language sql stable security definer set search_path = public as $$
  select c.oferta_id, count(*) from public.cupons c
   where cardinality(p_ofertas) <= 500 and c.oferta_id = any(p_ofertas)
   group by c.oferta_id
$$;
revoke execute on function public.cupons_usados(uuid[]) from public;
grant execute on function public.cupons_usados(uuid[]) to anon, authenticated;

-- Área da Empresa: conferir um código (só cupons das ofertas da PRÓPRIA loja; 60 consultas a cada 10 min)
drop function if exists public.consultar_cupom(text);
create or replace function public.consultar_cupom(p_codigo text, p_empresa uuid default null) returns json
language plpgsql security definer set search_path = public as $$
declare emp uuid; c public.cupons; tit text;
begin
  emp := public.loja_do_usuario(p_empresa);
  if emp is null then raise exception 'Cadastre sua loja primeiro.'; end if;
  if (select count(*) from public.tentativas where empresa_id = emp and criado_em > now() - interval '10 minutes') >= 60 then
    raise exception 'Muitas tentativas. Aguarde alguns minutos.';
  end if;
  insert into public.tentativas (empresa_id) values (emp);
  select * into c from public.cupons where codigo = upper(trim(p_codigo)) and empresa_id = emp;
  if not found then return json_build_object('ok', false); end if;
  select titulo into tit from public.ofertas where id = c.oferta_id;
  return json_build_object('ok', true, 'titulo', tit, 'usado_em', c.usado_em, 'valor', c.valor);
end $$;

-- Área da Empresa: confirmar a compra (uma vez só) e registrar o valor vendido
drop function if exists public.confirmar_cupom(text, numeric);
create or replace function public.confirmar_cupom(p_codigo text, p_valor numeric, p_empresa uuid default null) returns json
language plpgsql security definer set search_path = public as $$
declare emp uuid; c public.cupons; ganhos int := 0;
begin
  emp := public.loja_do_usuario(p_empresa, true);
  if emp is null then raise exception 'Só lojas aprovadas podem confirmar compras.'; end if;
  if p_valor is null or p_valor <= 0 or p_valor > 50000 then raise exception 'Valor da compra inválido.'; end if;
  select * into c from public.cupons where codigo = upper(trim(p_codigo)) and empresa_id = emp for update;  -- trava contra confirmar 2 vezes
  if not found then return json_build_object('ok', false, 'motivo', 'Código não encontrado para a sua loja.'); end if;
  if c.usado_em is not null then return json_build_object('ok', false, 'motivo', 'Este cupom já foi usado.'); end if;
  update public.cupons set usado_em = now(), valor = round(p_valor, 2) where codigo = c.codigo;
  insert into public.eventos (oferta_id, empresa_id, tipo, aparelho, valor) values (c.oferta_id, emp, 'compra', c.aparelho, round(p_valor, 2));
  ganhos := public.dar_pontos_compra(c.aparelho, emp, c.codigo, round(p_valor, 2));      -- pontos do cliente (seção PONTOS E BRINDES)
  return json_build_object('ok', true, 'pontos', ganhos);
end $$;

-- Área da Empresa: números da PRÓPRIA loja por oferta e por dia
drop function if exists public.metricas_empresa(date);
create or replace function public.metricas_empresa(p_desde date, p_empresa uuid default null) returns table (oferta_id uuid, tipo text, dia date, qtd bigint, valor numeric)
language sql stable security definer set search_path = public as $$
  select ev.oferta_id, ev.tipo, ev.dia, count(*), coalesce(sum(ev.valor), 0)
    from public.eventos ev join public.empresas e on e.id = ev.empresa_id
   where e.id = public.loja_do_usuario(p_empresa) and ev.dia >= p_desde
   group by ev.oferta_id, ev.tipo, ev.dia
$$;

-- Administrador: números de TODAS as lojas (só quem está na tabela admins)
create or replace function public.metricas_admin(p_desde date) returns table (empresa_id uuid, tipo text, qtd bigint, valor numeric)
language sql stable security definer set search_path = public as $$
  select ev.empresa_id, ev.tipo, count(*), coalesce(sum(ev.valor), 0)
    from public.eventos ev
   where public.is_admin() and ev.dia >= p_desde
   group by ev.empresa_id, ev.tipo
$$;
revoke execute on function public.metricas_admin(date) from public, anon;
grant execute on function public.metricas_admin(date) to authenticated;

-- Administrador: ficha de UMA loja (números por oferta e por dia)
create or replace function public.metricas_admin_empresa(p_empresa uuid, p_desde date) returns table (oferta_id uuid, tipo text, dia date, qtd bigint, valor numeric)
language sql stable security definer set search_path = public as $$
  select ev.oferta_id, ev.tipo, ev.dia, count(*), coalesce(sum(ev.valor), 0)
    from public.eventos ev
   where public.is_admin() and ev.empresa_id = p_empresa and ev.dia >= p_desde
   group by ev.oferta_id, ev.tipo, ev.dia
$$;
revoke execute on function public.metricas_admin_empresa(uuid, date) from public, anon;
grant execute on function public.metricas_admin_empresa(uuid, date) to authenticated;

-- ---------- FINANCEIRO: mensalidades das empresas e Plano VIP dos clientes ----------
-- O administrador registra cada pagamento recebido. Só administradores leem e gravam.
create table if not exists public.pagamentos (
  id               uuid primary key default gen_random_uuid(),
  tipo             text not null check (tipo in ('mensalidade','vip')),
  empresa_id       uuid references public.empresas on delete set null,
  empresa_nome     text check (empresa_nome is null or char_length(empresa_nome) <= 80),
  cliente_nome     text check (cliente_nome is null or char_length(cliente_nome) between 2 and 80),
  cliente_whatsapp text check (cliente_whatsapp is null or cliente_whatsapp ~ '^[0-9]{10,13}$'),
  valor            numeric(10,2) not null check (valor >= 0 and valor < 100000),
  referencia       text not null check (referencia ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),   -- mês: 2026-11
  forma            text not null default 'pix' check (forma in ('pix','dinheiro','cartao','boleto','cortesia','outro')),
  pago_em          date not null default current_date check (pago_em <= current_date + 1),
  obs              text check (obs is null or char_length(obs) <= 200),
  criado_por       uuid default auth.uid(),
  criado_em        timestamptz not null default now(),
  check ((tipo = 'mensalidade' and empresa_nome is not null) or (tipo = 'vip' and cliente_nome is not null))
);
alter table public.pagamentos add column if not exists plano text check (plano is null or plano in ('basico','destaque','premium'));  -- plano na época do pagamento
create unique index if not exists pagamentos_1_mensalidade_por_mes on public.pagamentos (empresa_id, referencia) where tipo = 'mensalidade';
create index if not exists pagamentos_data on public.pagamentos (pago_em desc);
alter table public.pagamentos enable row level security;
revoke all on public.pagamentos from public, anon;
grant select, insert, update, delete on public.pagamentos to authenticated;
drop policy if exists "so admin financeiro" on public.pagamentos;
create policy "so admin financeiro" on public.pagamentos for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- ---------- CLIENTES: cadastro feito na entrada do app (nome e WhatsApp) ----------
-- O app grava pelo celular (sem login). Só o administrador lê a lista.
create table if not exists public.clientes (
  aparelho       text primary key check (aparelho ~ '^[a-z0-9]{12,40}$'),
  nome           text not null check (char_length(nome) between 2 and 80),
  whatsapp       text not null check (whatsapp ~ '^[0-9]{10,13}$'),
  aceita_ofertas boolean not null default false,          -- só manda oferta para quem marcou (LGPD)
  criado_em      timestamptz not null default now(),
  atualizado_em  timestamptz not null default now()
);
create index if not exists clientes_whatsapp on public.clientes (whatsapp);
create index if not exists clientes_criado on public.clientes (criado_em desc);
alter table public.clientes enable row level security;
revoke all on public.clientes from public, anon;
grant select, delete on public.clientes to authenticated;
drop policy if exists "so admin clientes" on public.clientes;
create policy "so admin clientes" on public.clientes for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

create or replace function public.registrar_cliente(p_aparelho text, p_nome text, p_whats text, p_ofertas boolean default false) returns boolean
language plpgsql security definer set search_path = public as $$
declare n text := regexp_replace(btrim(coalesce(p_nome, '')), '\s+', ' ', 'g'); w text := regexp_replace(coalesce(p_whats, ''), '\D', '', 'g');
begin
  if p_aparelho is null or p_aparelho !~ '^[a-z0-9]{12,40}$' then return false; end if;
  if char_length(n) < 2 or char_length(n) > 80 then return false; end if;
  if w !~ '^[0-9]{10,13}$' then return false; end if;
  -- limite contra robôs: no máximo 500 cadastros novos por hora no app inteiro
  if not exists (select 1 from public.clientes where aparelho = p_aparelho)
     and (select count(*) from public.clientes where criado_em > now() - interval '1 hour') >= 500 then return false; end if;
  insert into public.clientes (aparelho, nome, whatsapp, aceita_ofertas) values (p_aparelho, n, w, coalesce(p_ofertas, false))
  on conflict (aparelho) do update set nome = excluded.nome, whatsapp = excluded.whatsapp,
     aceita_ofertas = excluded.aceita_ofertas, atualizado_em = now();
  -- bônus de boas-vindas: 50 pontos, uma vez por celular
  insert into public.pontos (aparelho, tipo, pontos, ref) values (p_aparelho, 'bonus', 50, 'cadastro') on conflict do nothing;
  return true;
end $$;

-- "Apagar meus dados" no app também apaga o cadastro no banco
create or replace function public.apagar_cliente(p_aparelho text) returns void
language sql security definer set search_path = public as $$
  delete from public.clientes where aparelho = p_aparelho and p_aparelho ~ '^[a-z0-9]{12,40}$';
$$;
revoke execute on function public.registrar_cliente(text, text, text, boolean), public.apagar_cliente(text) from public, anon;
grant execute on function public.registrar_cliente(text, text, text, boolean), public.apagar_cliente(text) to anon, authenticated;

-- ---------- VITRINE VIP: pedido com Pix (QR Code) ----------
-- O cliente gera o pedido no app (sem login). O valor é fixo aqui no banco (R$ 9,90).
-- Só o administrador vê os pedidos e confirma o Pix; aí o VIP ativa sozinho no celular do cliente.
create table if not exists public.pedidos_vip (
  txid      text primary key check (txid ~ '^VIP[A-Z0-9]{8}$'),
  aparelho  text not null check (aparelho ~ '^[a-z0-9]{12,40}$'),
  nome      text not null check (char_length(nome) between 2 and 80),
  whatsapp  text check (whatsapp is null or whatsapp ~ '^[0-9]{10,13}$'),
  valor     numeric(10,2) not null default 9.90 check (valor > 0 and valor < 1000),
  criado_em timestamptz not null default now(),
  pago_em   timestamptz,
  vip_ate   date
);
create index if not exists pedidos_vip_aparelho on public.pedidos_vip (aparelho, criado_em desc);
alter table public.pedidos_vip enable row level security;
revoke all on public.pedidos_vip from public, anon;
grant select, delete on public.pedidos_vip to authenticated;
drop policy if exists "so admin pedidos vip" on public.pedidos_vip;
create policy "so admin pedidos vip" on public.pedidos_vip for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

create or replace function public.pedir_vip(p_aparelho text, p_nome text, p_whats text) returns text
language plpgsql security definer set search_path = public as $$
declare t text; n text := btrim(coalesce(p_nome, '')); w text := nullif(regexp_replace(coalesce(p_whats, ''), '\D', '', 'g'), '');
begin
  if p_aparelho is null or p_aparelho !~ '^[a-z0-9]{12,40}$' then return null; end if;
  if char_length(n) < 2 or char_length(n) > 80 then return null; end if;
  if w is not null and w !~ '^[0-9]{10,13}$' then w := null; end if;
  -- reaproveita o pedido em aberto deste celular (últimas 24h)
  select txid into t from public.pedidos_vip
   where aparelho = p_aparelho and pago_em is null and criado_em > now() - interval '1 day' order by criado_em desc limit 1;
  if t is not null then update public.pedidos_vip set nome = n, whatsapp = w where txid = t; return t; end if;
  -- limites contra abuso
  if (select count(*) from public.pedidos_vip where aparelho = p_aparelho and criado_em > now() - interval '1 day') >= 5 then return null; end if;
  if (select count(*) from public.pedidos_vip where pago_em is null and criado_em > now() - interval '1 hour') >= 300 then return null; end if;
  loop
    t := 'VIP' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8));
    begin
      insert into public.pedidos_vip (txid, aparelho, nome, whatsapp) values (t, p_aparelho, n, w);
      exit;
    exception when unique_violation then null;
    end;
  end loop;
  return t;
end $$;

-- O app pergunta: este celular tem VIP pago? até quando?
create or replace function public.status_vip(p_aparelho text) returns table (vip_ate date, pendente text)
language sql stable security definer set search_path = public as $$
  select (select max(v.vip_ate) from public.pedidos_vip v where v.aparelho = p_aparelho and v.pago_em is not null),
         (select v.txid from public.pedidos_vip v where v.aparelho = p_aparelho and v.pago_em is null
           and v.criado_em > now() - interval '1 day' order by v.criado_em desc limit 1)
   where p_aparelho ~ '^[a-z0-9]{12,40}$'
$$;

-- Administrador confirma o Pix: ativa 30 dias (somando se ainda tiver VIP) e lança no caixa
create or replace function public.confirmar_vip(p_txid text, p_forma text default 'pix') returns date
language plpgsql security definer set search_path = public as $$
declare pd public.pedidos_vip; base date; ate date;
begin
  if not public.is_admin() then raise exception 'Apenas o administrador pode confirmar pagamentos.'; end if;
  select * into pd from public.pedidos_vip where txid = p_txid for update;
  if not found then raise exception 'Pedido não encontrado.'; end if;
  if pd.pago_em is not null then return pd.vip_ate; end if;           -- já confirmado: não lança 2 vezes
  select greatest(current_date, coalesce(max(vip_ate), current_date)) into base
    from public.pedidos_vip where aparelho = pd.aparelho and pago_em is not null;
  ate := base + 30;
  update public.pedidos_vip set pago_em = now(), vip_ate = ate where txid = pd.txid;
  insert into public.pagamentos (tipo, cliente_nome, cliente_whatsapp, valor, referencia, forma, pago_em, obs)
  values ('vip', pd.nome, pd.whatsapp, pd.valor, to_char(current_date, 'YYYY-MM'), coalesce(nullif(p_forma, ''), 'pix'), current_date, 'Pedido ' || pd.txid);
  return ate;
end $$;
revoke execute on function public.pedir_vip(text, text, text), public.status_vip(text), public.confirmar_vip(text, text) from public, anon;
grant execute on function public.pedir_vip(text, text, text), public.status_vip(text) to anon, authenticated;
grant execute on function public.confirmar_vip(text, text) to authenticated;

-- A empresa vê só as PRÓPRIAS mensalidades (sem observações internas do administrador)
drop function if exists public.minhas_mensalidades();
create or replace function public.minhas_mensalidades(p_empresa uuid default null) returns table (referencia text, valor numeric, forma text, pago_em date)
language sql stable security definer set search_path = public as $$
  select p.referencia, p.valor, p.forma, p.pago_em
    from public.pagamentos p join public.empresas e on e.id = p.empresa_id
   where p.tipo = 'mensalidade' and e.id = public.loja_do_usuario(p_empresa)
   order by p.referencia desc limit 24
$$;
revoke execute on function public.minhas_mensalidades(uuid) from public, anon;
grant execute on function public.minhas_mensalidades(uuid) to authenticated;

-- Administrador: vendas (cupons) de UMA loja, para a ficha da empresa
create or replace function public.vendas_admin_empresa(p_empresa uuid, p_desde date)
returns table (codigo text, oferta_id uuid, criado_em timestamptz, usado_em timestamptz, valor numeric)
language sql stable security definer set search_path = public as $$
  select c.codigo, c.oferta_id, c.criado_em, c.usado_em, c.valor
    from public.cupons c
   where public.is_admin() and c.empresa_id = p_empresa
     and (c.criado_em >= p_desde or c.usado_em >= p_desde)
   order by coalesce(c.usado_em, c.criado_em) desc
   limit 500
$$;
revoke execute on function public.vendas_admin_empresa(uuid, date) from public, anon;
grant execute on function public.vendas_admin_empresa(uuid, date) to authenticated;

revoke execute on function public.registrar_evento(uuid,text,text), public.emitir_cupom(uuid,text),
  public.consultar_cupom(text,uuid), public.confirmar_cupom(text,numeric,uuid), public.metricas_empresa(date,uuid) from public, anon;
grant execute on function public.registrar_evento(uuid,text,text), public.emitir_cupom(uuid,text) to anon, authenticated;
grant execute on function public.consultar_cupom(text,uuid), public.confirmar_cupom(text,numeric,uuid), public.metricas_empresa(date,uuid) to authenticated;

-- ---------- FOTOS (Storage) ----------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('fotos', 'fotos', true, 2097152, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;

drop policy if exists "fotos enviar"  on storage.objects;
drop policy if exists "fotos trocar"  on storage.objects;
drop policy if exists "fotos apagar"  on storage.objects;
create policy "fotos enviar" on storage.objects for insert to authenticated
  with check (bucket_id = 'fotos' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "fotos trocar" on storage.objects for update to authenticated
  using (bucket_id = 'fotos' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "fotos apagar" on storage.objects for delete to authenticated
  using (bucket_id = 'fotos' and (storage.foldername(name))[1] = auth.uid()::text);

-- ---------- PONTOS E BRINDES (pontos gerais do Vitrine) ----------
-- O cliente só ganha pontos quando a LOJA confirma a compra no painel: 1 ponto por R$ 1
-- (nível Prata 1,5x, Ouro 2x e Vitrine VIP em dobro). Cada loja cadastra os brindes que
-- quer dar. O cliente troca os pontos por um brinde de qualquer loja e recebe um código
-- BR-XXXXXX; a loja do brinde confere o código e confirma a entrega.
create table if not exists public.pontos (
  id         bigint generated always as identity primary key,
  aparelho   text not null check (aparelho ~ '^[a-z0-9]{12,40}$'),
  empresa_id uuid references public.empresas on delete set null,
  tipo       text not null check (tipo in ('compra','bonus','resgate','estorno')),
  pontos     int  not null check (pontos between -1000000 and 1000000),
  ref        text check (ref is null or char_length(ref) <= 20),   -- código do cupom ou da troca
  criado_em  timestamptz not null default now()
);
create index if not exists pontos_aparelho on public.pontos (aparelho, criado_em desc);
create unique index if not exists pontos_1_bonus on public.pontos (aparelho) where tipo = 'bonus';
create unique index if not exists pontos_1_por_cupom on public.pontos (ref) where tipo = 'compra';
alter table public.pontos enable row level security;
revoke all on public.pontos from public, anon, authenticated;
grant select on public.pontos to authenticated;
drop policy if exists "admin ve pontos" on public.pontos;
create policy "admin ve pontos" on public.pontos for select to authenticated using (public.is_admin());

create table if not exists public.brindes (
  id         uuid primary key default gen_random_uuid(),
  empresa_id uuid not null references public.empresas on delete cascade,
  nome       text not null check (char_length(nome) between 2 and 60),
  descricao  text check (descricao is null or char_length(descricao) <= 140),
  pontos     int  not null check (pontos between 10 and 100000),
  estoque    int  check (estoque is null or estoque between 0 and 100000),   -- vazio = sem limite
  ativo      boolean not null default true,
  criado_em  timestamptz not null default now()
);
create index if not exists brindes_empresa on public.brindes (empresa_id);
alter table public.brindes enable row level security;
revoke all on public.brindes from public, anon;
grant select, insert, update, delete on public.brindes to authenticated;
drop policy if exists "dono gerencia brindes" on public.brindes;
create policy "dono gerencia brindes" on public.brindes for all to authenticated
  using (public.is_admin() or exists (select 1 from public.empresas e where e.id = empresa_id and e.dono = auth.uid()))
  with check (public.is_admin() or exists (select 1 from public.empresas e where e.id = empresa_id and e.dono = auth.uid()));
-- no máximo 20 brindes por loja
create or replace function public.limite_brindes() returns trigger language plpgsql security definer set search_path = public as $$
begin
  if (select count(*) from public.brindes where empresa_id = new.empresa_id) >= 20 then
    raise exception 'Cada loja pode ter até 20 brindes.';
  end if;
  return new;
end $$;
drop trigger if exists t_limite_brindes on public.brindes;
create trigger t_limite_brindes before insert on public.brindes for each row execute function public.limite_brindes();

create table if not exists public.resgates (
  id           uuid primary key default gen_random_uuid(),
  codigo       text not null unique check (codigo ~ '^BR-[A-Z0-9]{6}$'),
  aparelho     text not null check (aparelho ~ '^[a-z0-9]{12,40}$'),
  brinde_id    uuid references public.brindes on delete set null,
  empresa_id   uuid references public.empresas on delete set null,
  brinde_nome  text not null,
  pontos       int  not null check (pontos > 0),
  criado_em    timestamptz not null default now(),
  entregue_em  timestamptz,
  cancelado_em timestamptz
);
create index if not exists resgates_aparelho on public.resgates (aparelho, criado_em desc);
alter table public.resgates enable row level security;
revoke all on public.resgates from public, anon, authenticated;
grant select on public.resgates to authenticated;
drop policy if exists "loja e admin veem resgates" on public.resgates;
create policy "loja e admin veem resgates" on public.resgates for select to authenticated
  using (public.is_admin() or exists (select 1 from public.empresas e where e.id = empresa_id and e.dono = auth.uid()));

-- Uso interno: pontos de uma compra confirmada (chamada por confirmar_cupom)
create or replace function public.dar_pontos_compra(p_aparelho text, p_empresa uuid, p_ref text, p_valor numeric) returns int
language plpgsql security definer set search_path = public as $$
declare total int; mult numeric := 1; ganho int;
begin
  if p_aparelho is null or p_aparelho !~ '^[a-z0-9]{12,40}$' or p_valor is null or p_valor <= 0 then return 0; end if;
  select coalesce(sum(pontos), 0) into total from public.pontos where aparelho = p_aparelho and tipo in ('compra','bonus');
  mult := case when total >= 1500 then 2 when total >= 500 then 1.5 else 1 end;              -- níveis Ouro e Prata
  if exists (select 1 from public.pedidos_vip v where v.aparelho = p_aparelho and v.pago_em is not null and v.vip_ate >= current_date) then
    mult := mult * 2;                                                                        -- Vitrine VIP: em dobro
  end if;
  ganho := floor(p_valor * mult)::int;
  if ganho <= 0 then return 0; end if;
  insert into public.pontos (aparelho, empresa_id, tipo, pontos, ref) values (p_aparelho, p_empresa, 'compra', ganho, p_ref)
  on conflict do nothing;                                                                    -- 1 vez por cupom
  return ganho;
end $$;

-- App do cliente: saldo, extrato e brindes trocados deste celular
create or replace function public.meus_pontos(p_aparelho text) returns json
language sql stable security definer set search_path = public as $$
  select case when p_aparelho is null or p_aparelho !~ '^[a-z0-9]{12,40}$' then null else json_build_object(
    'saldo', (select coalesce(sum(pontos), 0) from public.pontos where aparelho = p_aparelho),
    'total', (select coalesce(sum(pontos), 0) from public.pontos where aparelho = p_aparelho and tipo in ('compra','bonus')),
    'hist', coalesce((select json_agg(h) from (
        select p.tipo, p.pontos, p.criado_em, coalesce(e.nome, '') as loja, p.ref
          from public.pontos p left join public.empresas e on e.id = p.empresa_id
         where p.aparelho = p_aparelho order by p.criado_em desc limit 30) h), '[]'::json),
    'resgates', coalesce((select json_agg(r) from (
        select x.codigo, x.brinde_nome, x.pontos, x.criado_em, x.entregue_em, x.cancelado_em, coalesce(e.nome, '') as loja
          from public.resgates x left join public.empresas e on e.id = x.empresa_id
         where x.aparelho = p_aparelho order by x.criado_em desc limit 20) r), '[]'::json)
  ) end
$$;

-- App do cliente: brindes das lojas aprovadas
create or replace function public.listar_brindes() returns table (id uuid, nome text, descricao text, pontos int, loja text, disponivel boolean)
language sql stable security definer set search_path = public as $$
  select b.id, b.nome, b.descricao, b.pontos, e.nome, (b.estoque is null or b.estoque > 0)
    from public.brindes b join public.empresas e on e.id = b.empresa_id
   where b.ativo and e.aprovada
   order by b.pontos limit 200
$$;

-- App do cliente: trocar pontos por um brinde (gera o código BR-XXXXXX)
create or replace function public.resgatar_brinde(p_aparelho text, p_brinde uuid) returns json
language plpgsql security definer set search_path = public as $$
declare b public.brindes; loja text; ok_loja boolean; saldo int; cod text;
begin
  if p_aparelho is null or p_aparelho !~ '^[a-z0-9]{12,40}$' then return json_build_object('ok', false, 'motivo', 'Aparelho inválido.'); end if;
  perform pg_advisory_xact_lock(hashtext('pontos:' || p_aparelho));                         -- uma troca por vez: não gasta o mesmo ponto 2 vezes
  select * into b from public.brindes where id = p_brinde for update;
  if not found or not b.ativo then return json_build_object('ok', false, 'motivo', 'Este brinde não está mais disponível.'); end if;
  select e.nome, e.aprovada into loja, ok_loja from public.empresas e where e.id = b.empresa_id;
  if not coalesce(ok_loja, false) then return json_build_object('ok', false, 'motivo', 'Este brinde não está mais disponível.'); end if;
  if b.estoque is not null and b.estoque <= 0 then return json_build_object('ok', false, 'motivo', 'Este brinde esgotou.'); end if;
  if (select count(*) from public.resgates where aparelho = p_aparelho and criado_em > now() - interval '1 day') >= 10 then
    return json_build_object('ok', false, 'motivo', 'Limite de 10 trocas por dia.');
  end if;
  select coalesce(sum(pontos), 0) into saldo from public.pontos where aparelho = p_aparelho;
  if saldo < b.pontos then return json_build_object('ok', false, 'motivo', 'Pontos insuficientes.'); end if;
  loop
    cod := 'BR-' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 6));
    exit when not exists (select 1 from public.resgates where codigo = cod);
  end loop;
  insert into public.resgates (codigo, aparelho, brinde_id, empresa_id, brinde_nome, pontos) values (cod, p_aparelho, b.id, b.empresa_id, b.nome, b.pontos);
  insert into public.pontos (aparelho, empresa_id, tipo, pontos, ref) values (p_aparelho, b.empresa_id, 'resgate', -b.pontos, cod);
  if b.estoque is not null then update public.brindes set estoque = estoque - 1 where id = b.id; end if;
  return json_build_object('ok', true, 'codigo', cod, 'brinde', b.nome, 'loja', loja, 'pontos', b.pontos);
end $$;

-- Área da Empresa: conferir o código do brinde (só brindes da PRÓPRIA loja)
drop function if exists public.consultar_resgate(text);
create or replace function public.consultar_resgate(p_codigo text, p_empresa uuid default null) returns json
language plpgsql security definer set search_path = public as $$
declare emp uuid; r public.resgates;
begin
  emp := public.loja_do_usuario(p_empresa);
  if emp is null then raise exception 'Cadastre sua loja primeiro.'; end if;
  if (select count(*) from public.tentativas where empresa_id = emp and criado_em > now() - interval '10 minutes') >= 60 then
    raise exception 'Muitas tentativas. Aguarde alguns minutos.';
  end if;
  insert into public.tentativas (empresa_id) values (emp);
  select * into r from public.resgates where codigo = upper(trim(p_codigo)) and empresa_id = emp;
  if not found then return json_build_object('ok', false); end if;
  return json_build_object('ok', true, 'brinde', r.brinde_nome, 'pontos', r.pontos, 'criado_em', r.criado_em, 'entregue_em', r.entregue_em, 'cancelado_em', r.cancelado_em);
end $$;

-- Área da Empresa: entregar o brinde (ou cancelar e devolver os pontos ao cliente)
drop function if exists public.confirmar_resgate(text, text);
create or replace function public.confirmar_resgate(p_codigo text, p_acao text, p_empresa uuid default null) returns json
language plpgsql security definer set search_path = public as $$
declare emp uuid; r public.resgates;
begin
  emp := public.loja_do_usuario(p_empresa, true);
  if emp is null then raise exception 'Só lojas aprovadas podem entregar brindes.'; end if;
  if p_acao not in ('entregar','cancelar') then raise exception 'Ação inválida.'; end if;
  select * into r from public.resgates where codigo = upper(trim(p_codigo)) and empresa_id = emp for update;
  if not found then return json_build_object('ok', false, 'motivo', 'Código não encontrado para a sua loja.'); end if;
  if r.entregue_em is not null then return json_build_object('ok', false, 'motivo', 'Este brinde já foi entregue.'); end if;
  if r.cancelado_em is not null then return json_build_object('ok', false, 'motivo', 'Esta troca foi cancelada.'); end if;
  if p_acao = 'entregar' then
    update public.resgates set entregue_em = now() where id = r.id;
  else
    update public.resgates set cancelado_em = now() where id = r.id;
    insert into public.pontos (aparelho, empresa_id, tipo, pontos, ref) values (r.aparelho, emp, 'estorno', r.pontos, r.codigo);
    update public.brindes set estoque = estoque + 1 where id = r.brinde_id and estoque is not null;
  end if;
  return json_build_object('ok', true);
end $$;

revoke execute on function public.dar_pontos_compra(text, uuid, text, numeric), public.meus_pontos(text), public.listar_brindes(),
  public.resgatar_brinde(text, uuid), public.consultar_resgate(text,uuid), public.confirmar_resgate(text,text,uuid), public.limite_brindes() from public, anon, authenticated;
grant execute on function public.meus_pontos(text), public.listar_brindes(), public.resgatar_brinde(text, uuid) to anon, authenticated;
grant execute on function public.consultar_resgate(text,uuid), public.confirmar_resgate(text,text,uuid) to authenticated;

-- =====================================================================
-- =====================================================================
--  VÁRIAS LOJAS DO ADM: passar uma loja cadastrada pelo ADM para o lojista
--  (o lojista cria a conta na Área da Empresa; o ADM informa o e-mail dele)
-- =====================================================================
create or replace function public.transferir_empresa(p_empresa uuid, p_email text) returns json
language plpgsql security definer set search_path = public as $$
declare u uuid;
begin
  if not public.is_admin() then raise exception 'Só o administrador pode passar lojas.'; end if;
  select id into u from auth.users where lower(email) = lower(trim(p_email)) limit 1;
  if u is null then return json_build_object('ok', false, 'motivo', 'Nenhuma conta com esse e-mail. Peça para a loja criar a conta na Área da Empresa primeiro.'); end if;
  if exists (select 1 from public.empresas where dono = u and not pelo_adm and id <> p_empresa) then
    return json_build_object('ok', false, 'motivo', 'Essa conta já tem uma loja cadastrada.');
  end if;
  update public.empresas set dono = u, pelo_adm = false where id = p_empresa;
  if not found then return json_build_object('ok', false, 'motivo', 'Loja não encontrada.'); end if;
  return json_build_object('ok', true);
end $$;
revoke execute on function public.transferir_empresa(uuid, text) from public, anon;
grant execute on function public.transferir_empresa(uuid, text) to authenticated;

-- DEPOIS de criar sua conta na Área da Empresa (empresa.html),
-- rode só a linha abaixo (com o SEU e-mail) para virar administrador:
--
-- insert into public.admins (user_id) select id from auth.users where email = 'SEU_EMAIL_AQUI';
-- =====================================================================
