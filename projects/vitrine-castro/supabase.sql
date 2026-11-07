-- =====================================================================
-- VITRINE CASTRO – Banco de dados v2
-- Cole TUDO no SQL Editor do Supabase e clique em RUN.
-- Pode rodar de novo sem perder dados (atualiza a versão 1 se você já tinha).
--
-- Regra de ouro de segurança: o navegador NUNCA decide pontos, VIP, plano
-- ou aprovação. Tudo isso é feito aqui, no banco, por funções protegidas.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0. AJUSTES DO NEGÓCIO (mude aqui e rode de novo)
-- ---------------------------------------------------------------------
-- Ofertas por semana de cada plano da empresa
create or replace function public.plano_limite_semana(p text) returns int
language sql immutable set search_path = '' as $$
  select case p when 'basico' then 3 when 'destaque' then 7 when 'premium' then 15 else 1 end
$$;
-- Planos pagos aparecem na vitrine principal (carrossel do topo)
create or replace function public.plano_tem_vitrine(p text) returns boolean
language sql immutable set search_path = '' as $$
  select p in ('basico','destaque','premium')
$$;
-- Horas que o VIP vê a oferta antes de todo mundo
create or replace function public.horas_vip_antes() returns int
language sql immutable set search_path = '' as $$ select 24 $$;

-- ---------------------------------------------------------------------
-- 1. LIMITE DE TENTATIVAS (contra robôs e força bruta)
-- ---------------------------------------------------------------------
create table if not exists public.limites (
  chave  text primary key,
  inicio timestamptz not null default now(),
  qtd    int not null default 0
);
alter table public.limites enable row level security;   -- sem políticas = ninguém de fora lê ou escreve
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
  if v > p_max then
    raise exception 'Muitas tentativas. Aguarde alguns minutos e tente de novo.' using errcode = 'P0001';
  end if;
end $$;

-- ---------------------------------------------------------------------
-- 2. ADMINISTRADORES (você)
-- ---------------------------------------------------------------------
create table if not exists public.admins (
  user_id uuid primary key references auth.users on delete cascade
);
alter table public.admins enable row level security;
drop policy if exists "admin ve a si mesmo" on public.admins;
create policy "admin ve a si mesmo" on public.admins for select using (user_id = auth.uid());

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.admins where user_id = auth.uid())
$$;

-- ---------------------------------------------------------------------
-- 3. CLIENTES (perfis)
-- ---------------------------------------------------------------------
create table if not exists public.perfis (
  id             uuid primary key references auth.users on delete cascade,
  nome           text not null default '' check (char_length(nome) <= 80),
  whatsapp       text check (char_length(whatsapp) <= 20),
  codigo         text not null unique default upper(substr(replace(gen_random_uuid()::text,'-',''),1,7)),
  indicado_por   uuid references public.perfis(id) on delete set null,
  bonus_liberado boolean not null default false,   -- bônus de boas-vindas e da indicação saem na 1ª compra
  vip_ate        timestamptz,
  criado_em      timestamptz not null default now()
);
alter table public.perfis enable row level security;
drop policy if exists "perfil ver"    on public.perfis;
drop policy if exists "perfil editar" on public.perfis;
create policy "perfil ver"    on public.perfis for select using (id = auth.uid() or public.is_admin());
create policy "perfil editar" on public.perfis for update to authenticated using (id = auth.uid() or public.is_admin());
-- (sem política de insert/delete: o perfil é criado pelo gatilho abaixo)

-- Cria o perfil quando alguém se cadastra (nome, WhatsApp e código de quem indicou)
create or replace function public.novo_usuario() returns trigger
language plpgsql security definer set search_path = '' as $$
declare ref uuid;
begin
  select p.id into ref from public.perfis p
   where p.codigo = upper(left(coalesce(new.raw_user_meta_data->>'ref',''), 12));
  insert into public.perfis (id, nome, whatsapp, indicado_por)
  values (new.id,
          left(coalesce(new.raw_user_meta_data->>'nome',''), 80),
          left(regexp_replace(coalesce(new.raw_user_meta_data->>'whatsapp',''), '[^0-9]', '', 'g'), 20),
          ref)
  on conflict (id) do nothing;
  return new;
end $$;
-- Quem já tinha conta antes desta versão também ganha perfil
insert into public.perfis (id) select id from auth.users on conflict (id) do nothing;
drop trigger if exists t_novo_usuario on auth.users;
create trigger t_novo_usuario after insert on auth.users for each row execute function public.novo_usuario();

-- O cliente só pode mudar nome e WhatsApp. VIP, código e indicação são protegidos.
create or replace function public.protege_perfil() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_admin() then
    new.id := old.id; new.codigo := old.codigo; new.indicado_por := old.indicado_por;
    new.bonus_liberado := old.bonus_liberado; new.vip_ate := old.vip_ate; new.criado_em := old.criado_em;
  end if;
  new.whatsapp := left(regexp_replace(coalesce(new.whatsapp,''), '[^0-9]', '', 'g'), 20);
  return new;
end $$;
drop trigger if exists t_protege_perfil on public.perfis;
create trigger t_protege_perfil before update on public.perfis for each row execute function public.protege_perfil();

create or replace function public.eh_vip() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.perfis where id = auth.uid() and vip_ate > now())
$$;

-- ---------------------------------------------------------------------
-- 4. EMPRESAS
-- ---------------------------------------------------------------------
create table if not exists public.empresas (
  id         uuid primary key default gen_random_uuid(),
  dono       uuid not null default auth.uid() references auth.users on delete cascade,
  nome       text not null check (char_length(nome) between 2 and 80),
  ramo       text not null default 'Outro' check (char_length(ramo) <= 60),
  whatsapp   text check (char_length(whatsapp) <= 20),
  endereco   text check (char_length(endereco) <= 150),
  logo_url   text,
  plano      text not null default 'gratis',
  aprovada   boolean not null default false,
  criado_em  timestamptz not null default now()
);
alter table public.empresas add column if not exists plano_ate timestamptz;
alter table public.empresas alter column plano set default 'gratis';
alter table public.empresas drop constraint if exists empresas_plano_check;
alter table public.empresas add constraint empresas_plano_check check (plano in ('gratis','basico','destaque','premium'));
create unique index if not exists empresas_um_por_dono on public.empresas(dono);

-- Plano que vale hoje (plano pago vencido volta a ser grátis)
create or replace function public.plano_efetivo(p_empresa uuid) returns text
language sql stable security definer set search_path = '' as $$
  select case when e.plano <> 'gratis' and e.plano_ate > now() then e.plano else 'gratis' end
  from public.empresas e where e.id = p_empresa
$$;

create or replace function public.protege_empresa() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_admin() then
    if tg_op = 'INSERT' then
      new.aprovada := false; new.plano := 'gratis'; new.plano_ate := null; new.dono := auth.uid();
    else
      new.aprovada := old.aprovada; new.plano := old.plano; new.plano_ate := old.plano_ate; new.dono := old.dono;
    end if;
  end if;
  if new.logo_url is not null and new.logo_url !~ '^https://' then new.logo_url := null; end if;
  return new;
end $$;
drop trigger if exists t_protege_empresa on public.empresas;
create trigger t_protege_empresa before insert or update on public.empresas
  for each row execute function public.protege_empresa();

alter table public.empresas enable row level security;
drop policy if exists "empresas ver"     on public.empresas;
drop policy if exists "empresas criar"   on public.empresas;
drop policy if exists "empresas editar"  on public.empresas;
drop policy if exists "empresas apagar"  on public.empresas;
create policy "empresas ver"    on public.empresas for select using (aprovada or dono = auth.uid() or public.is_admin());
create policy "empresas criar"  on public.empresas for insert to authenticated with check (dono = auth.uid());
create policy "empresas editar" on public.empresas for update to authenticated using (dono = auth.uid() or public.is_admin());
create policy "empresas apagar" on public.empresas for delete to authenticated using (public.is_admin());

-- ---------------------------------------------------------------------
-- 5. OFERTAS  (descontos permitidos: 10, 20, 30 ou 50%)
-- ---------------------------------------------------------------------
create table if not exists public.ofertas (
  id           uuid primary key default gen_random_uuid(),
  empresa_id   uuid not null references public.empresas on delete cascade,
  titulo       text not null,
  descricao    text not null check (char_length(descricao) <= 300),
  regras       text check (char_length(regras) <= 200),
  categoria    text not null default 'vest' check (char_length(categoria) <= 20),
  foto_url     text,
  validade     date,
  economia     numeric not null default 0 check (economia >= 0 and economia < 100000),
  ativa        boolean not null default true,
  destaque     boolean not null default false,   -- só admin
  banner       boolean not null default false,   -- vitrine principal (só planos pagos)
  banner_topo  text check (char_length(banner_topo) <= 20),
  criado_em    timestamptz not null default now()
);
alter table public.ofertas add column if not exists desconto     int not null default 20;
alter table public.ofertas add column if not exists desconto_vip int;
alter table public.ofertas add column if not exists preco        numeric(10,2);
alter table public.ofertas drop constraint if exists ofertas_titulo_check;
alter table public.ofertas add  constraint ofertas_titulo_check check (char_length(titulo) between 2 and 60);
alter table public.ofertas drop constraint if exists ofertas_desconto_check;
alter table public.ofertas add  constraint ofertas_desconto_check check (desconto in (10,20,30,50));
alter table public.ofertas drop constraint if exists ofertas_desconto_vip_check;
alter table public.ofertas add  constraint ofertas_desconto_vip_check check (desconto_vip is null or (desconto_vip > desconto and desconto_vip <= 70));
alter table public.ofertas drop constraint if exists ofertas_preco_check;
alter table public.ofertas add  constraint ofertas_preco_check check (preco is null or (preco > 0 and preco < 1000000));
create index if not exists ofertas_empresa on public.ofertas(empresa_id);

-- Registro de publicações: conta o limite semanal mesmo se a oferta for apagada depois
create table if not exists public.publicacoes (
  id         bigint generated always as identity primary key,
  empresa_id uuid not null references public.empresas on delete cascade,
  criado_em  timestamptz not null default now()
);
create index if not exists publicacoes_empresa on public.publicacoes(empresa_id, criado_em);
alter table public.publicacoes enable row level security;
revoke all on public.publicacoes from anon, authenticated;

-- Destaque só admin; vitrine só plano pago; limite de ofertas por semana conforme o plano
create or replace function public.protege_oferta() returns trigger
language plpgsql security definer set search_path = '' as $$
declare pl text; lim int; qtd int;
begin
  if new.foto_url is not null and new.foto_url !~ '^https://' then new.foto_url := null; end if;
  if public.is_admin() then return new; end if;
  pl := public.plano_efetivo(new.empresa_id);
  if tg_op = 'INSERT' then
    new.destaque := false; new.criado_em := now();
    lim := public.plano_limite_semana(pl);
    select count(*) into qtd from public.publicacoes
     where empresa_id = new.empresa_id and criado_em > now() - interval '7 days';
    if qtd >= lim then
      raise exception 'Seu plano permite % oferta(s) por semana. Aguarde a próxima semana ou mude de plano.', lim using errcode = 'P0001';
    end if;
    insert into public.publicacoes (empresa_id) values (new.empresa_id);
  else
    new.destaque := old.destaque; new.empresa_id := old.empresa_id; new.criado_em := old.criado_em;
  end if;
  if new.banner and not public.plano_tem_vitrine(pl) then new.banner := false; end if;
  return new;
end $$;
drop trigger if exists t_protege_oferta on public.ofertas;
create trigger t_protege_oferta before insert or update on public.ofertas
  for each row execute function public.protege_oferta();

-- Oferta "no ar" para quem está vendo (VIP vê as novas antes)
create or replace function public.oferta_visivel(o public.ofertas) returns boolean
language sql stable security definer set search_path = '' as $$
  select o.ativa
     and (o.validade is null or o.validade >= current_date)
     and exists (select 1 from public.empresas e where e.id = o.empresa_id and e.aprovada)
     and (o.criado_em <= now() - make_interval(hours => public.horas_vip_antes()) or public.eh_vip())
$$;

alter table public.ofertas enable row level security;
drop policy if exists "ofertas ver"     on public.ofertas;
drop policy if exists "ofertas criar"   on public.ofertas;
drop policy if exists "ofertas editar"  on public.ofertas;
drop policy if exists "ofertas apagar"  on public.ofertas;
create policy "ofertas ver" on public.ofertas for select using (
  public.oferta_visivel(ofertas)
  or exists (select 1 from public.empresas e where e.id = empresa_id and e.dono = auth.uid())
  or public.is_admin());
create policy "ofertas criar" on public.ofertas for insert to authenticated with check (
  exists (select 1 from public.empresas e where e.id = empresa_id and e.dono = auth.uid()) or public.is_admin());
create policy "ofertas editar" on public.ofertas for update to authenticated using (
  exists (select 1 from public.empresas e where e.id = empresa_id and e.dono = auth.uid()) or public.is_admin());
create policy "ofertas apagar" on public.ofertas for delete to authenticated using (
  exists (select 1 from public.empresas e where e.id = empresa_id and e.dono = auth.uid()) or public.is_admin());

-- ---------------------------------------------------------------------
-- 6. CUPONS, COMPRAS E PONTOS (só mudam pelas funções protegidas)
-- ---------------------------------------------------------------------
create table if not exists public.cupons (
  id         uuid primary key default gen_random_uuid(),
  cliente    uuid not null references public.perfis on delete cascade,
  oferta_id  uuid not null references public.ofertas on delete cascade,
  codigo     text not null unique,
  desconto   int  not null,
  vip        boolean not null default false,
  status     text not null default 'ativo' check (status in ('ativo','usado')),
  criado_em  timestamptz not null default now(),
  usado_em   timestamptz
);
create unique index if not exists cupons_um_ativo on public.cupons(cliente, oferta_id) where status = 'ativo';
alter table public.cupons enable row level security;
drop policy if exists "cupons ver" on public.cupons;
create policy "cupons ver" on public.cupons for select using (cliente = auth.uid() or public.is_admin());

create table if not exists public.compras (
  id            uuid primary key default gen_random_uuid(),
  cupom_id      uuid unique references public.cupons on delete set null,
  empresa_id    uuid not null references public.empresas on delete cascade,
  cliente       uuid references public.perfis on delete set null,
  cliente_nome  text,
  oferta_id     uuid references public.ofertas on delete set null,
  oferta_titulo text,
  valor         numeric(10,2) not null check (valor > 0 and valor <= 50000),
  desconto      int,
  pontos        int not null,
  confirmado_por uuid,
  criado_em     timestamptz not null default now()
);
create index if not exists compras_empresa on public.compras(empresa_id, criado_em desc);
alter table public.compras enable row level security;
drop policy if exists "compras ver" on public.compras;
create policy "compras ver" on public.compras for select using (
  cliente = auth.uid()
  or exists (select 1 from public.empresas e where e.id = empresa_id and e.dono = auth.uid())
  or public.is_admin());

create table if not exists public.pontos_mov (
  id        uuid primary key default gen_random_uuid(),
  cliente   uuid not null references public.perfis on delete cascade,
  delta     int not null,
  motivo    text not null check (char_length(motivo) <= 120),
  criado_em timestamptz not null default now()
);
create index if not exists pontos_cliente on public.pontos_mov(cliente, criado_em desc);
alter table public.pontos_mov enable row level security;
drop policy if exists "pontos ver" on public.pontos_mov;
create policy "pontos ver" on public.pontos_mov for select using (cliente = auth.uid() or public.is_admin());

-- ---------------------------------------------------------------------
-- 7. BRINDES (trocados com pontos)
-- ---------------------------------------------------------------------
create table if not exists public.brindes (
  id         uuid primary key default gen_random_uuid(),
  nome       text not null check (char_length(nome) between 2 and 60),
  empresa_id uuid references public.empresas on delete cascade,   -- quem entrega (vazio = Vitrine Castro)
  pontos     int  not null check (pontos > 0 and pontos <= 1000000),
  estoque    int  check (estoque is null or estoque >= 0),
  icone      text not null default 'gift' check (icone ~ '^[a-z]{2,12}$'),
  ativo      boolean not null default true,
  criado_em  timestamptz not null default now()
);
alter table public.brindes enable row level security;
drop policy if exists "brindes ver"   on public.brindes;
drop policy if exists "brindes admin" on public.brindes;
create policy "brindes ver"   on public.brindes for select using (ativo or public.is_admin());
create policy "brindes admin" on public.brindes for all to authenticated using (public.is_admin()) with check (public.is_admin());

create table if not exists public.trocas (
  id          uuid primary key default gen_random_uuid(),
  cliente     uuid not null references public.perfis on delete cascade,
  brinde_id   uuid references public.brindes on delete set null,
  brinde_nome text not null,
  pontos      int not null,
  codigo      text not null unique,
  status      text not null default 'pendente' check (status in ('pendente','retirado')),
  criado_em   timestamptz not null default now(),
  retirado_em timestamptz
);
alter table public.trocas enable row level security;
drop policy if exists "trocas ver" on public.trocas;
create policy "trocas ver" on public.trocas for select using (cliente = auth.uid() or public.is_admin());

-- ---------------------------------------------------------------------
-- 8. FUNÇÕES QUE O APP CHAMA  (supabase.rpc('nome', {...}))
-- ---------------------------------------------------------------------
create or replace function public.novo_codigo(prefixo text) returns text
language sql volatile set search_path = '' as $$
  select prefixo || upper(substr(replace(gen_random_uuid()::text,'-',''),1,8))
$$;

-- Cliente: saldo e total ganho
create or replace function public.meus_pontos() returns json
language sql stable security definer set search_path = '' as $$
  select json_build_object(
    'saldo', coalesce(sum(delta),0),
    'total', coalesce(sum(delta) filter (where delta > 0),0))
  from public.pontos_mov where cliente = auth.uid()
$$;

-- Cliente: pegar cupom (máx. 20 por dia)
create or replace function public.pegar_cupom(p_oferta uuid) returns json
language plpgsql security definer set search_path = '' as $$
declare o public.ofertas; c public.cupons; v boolean; d int;
begin
  if auth.uid() is null then raise exception 'Entre na sua conta para pegar o cupom.' using errcode = 'P0001'; end if;
  select * into o from public.ofertas where id = p_oferta;
  if not found or not public.oferta_visivel(o) then
    raise exception 'Esta oferta não está disponível.' using errcode = 'P0001';
  end if;
  select * into c from public.cupons where cliente = auth.uid() and oferta_id = p_oferta and status = 'ativo';
  if found then return json_build_object('codigo', c.codigo, 'desconto', c.desconto, 'vip', c.vip); end if;
  perform public.checar_limite('cupom:' || auth.uid(), 20, interval '1 day');
  v := public.eh_vip();
  d := case when v and o.desconto_vip is not null then o.desconto_vip else o.desconto end;
  insert into public.cupons (cliente, oferta_id, codigo, desconto, vip)
  values (auth.uid(), p_oferta, public.novo_codigo('VC'), d, v)
  returning * into c;
  return json_build_object('codigo', c.codigo, 'desconto', c.desconto, 'vip', c.vip);
end $$;

-- Empresa: empresa aprovada do usuário logado
create or replace function public.minha_empresa_id() returns uuid
language sql stable security definer set search_path = '' as $$
  select id from public.empresas where dono = auth.uid() and aprovada
$$;

-- Empresa: quantas ofertas ainda pode publicar nesta semana
create or replace function public.minha_cota() returns json
language sql stable security definer set search_path = '' as $$
  select json_build_object(
    'plano', public.plano_efetivo(e.id),
    'plano_ate', e.plano_ate,
    'limite', public.plano_limite_semana(public.plano_efetivo(e.id)),
    'usadas', (select count(*) from public.publicacoes p where p.empresa_id = e.id and p.criado_em > now() - interval '7 days'),
    'vitrine', public.plano_tem_vitrine(public.plano_efetivo(e.id)))
  from public.empresas e where e.dono = auth.uid()
$$;

-- Empresa: ver o cupom antes de confirmar (60 consultas a cada 10 minutos)
create or replace function public.consultar_cupom(p_codigo text) returns json
language plpgsql security definer set search_path = '' as $$
declare emp uuid; c public.cupons; o public.ofertas; nome text;
begin
  emp := public.minha_empresa_id();
  if emp is null then raise exception 'Só lojas aprovadas podem confirmar compras.' using errcode = 'P0001'; end if;
  perform public.checar_limite('scan:' || emp, 60, interval '10 minutes');
  select * into c from public.cupons where codigo = upper(trim(p_codigo));
  if found then select * into o from public.ofertas where id = c.oferta_id; end if;
  if not found or o.empresa_id <> emp then
    return json_build_object('ok', false, 'motivo', 'Código não encontrado para a sua loja.');
  end if;
  select split_part(p.nome,' ',1) into nome from public.perfis p where p.id = c.cliente;
  return json_build_object('ok', true, 'status', c.status, 'cliente', nome, 'oferta', o.titulo,
    'desconto', c.desconto, 'vip', c.vip, 'preco', o.preco, 'usado_em', c.usado_em,
    'vencida', (o.validade is not null and o.validade < current_date));
end $$;

-- Empresa: confirmar a compra e dar os pontos ao cliente
create or replace function public.confirmar_compra(p_codigo text, p_valor numeric) returns json
language plpgsql security definer set search_path = '' as $$
declare emp uuid; c public.cupons; o public.ofertas; p public.perfis; total int; mult numeric; pts int; nome text;
begin
  emp := public.minha_empresa_id();
  if emp is null then raise exception 'Só lojas aprovadas podem confirmar compras.' using errcode = 'P0001'; end if;
  if p_valor is null or p_valor <= 0 or p_valor > 50000 then
    raise exception 'Valor da compra inválido.' using errcode = 'P0001';
  end if;
  perform public.checar_limite('confirma:' || emp, 120, interval '1 hour');
  select * into c from public.cupons where codigo = upper(trim(p_codigo)) for update;   -- trava contra confirmação dupla
  if found then select * into o from public.ofertas where id = c.oferta_id; end if;
  if not found or o.empresa_id <> emp then raise exception 'Código não encontrado para a sua loja.' using errcode = 'P0001'; end if;
  if c.status <> 'ativo' then raise exception 'Este cupom já foi usado.' using errcode = 'P0001'; end if;
  if c.cliente = auth.uid() then raise exception 'O dono da loja não pode confirmar o próprio cupom.' using errcode = 'P0001'; end if;
  if o.validade is not null and o.validade < current_date then raise exception 'A oferta deste cupom já venceu.' using errcode = 'P0001'; end if;

  select * into p from public.perfis where id = c.cliente for update;
  select coalesce(sum(delta) filter (where delta > 0),0) into total from public.pontos_mov where cliente = c.cliente;
  mult := (case when total >= 1500 then 2 when total >= 500 then 1.5 else 1 end)
        * (case when p.vip_ate > now() then 2 else 1 end);
  pts := floor(p_valor * mult);
  nome := split_part(p.nome,' ',1);

  update public.cupons set status = 'usado', usado_em = now() where id = c.id;
  insert into public.compras (cupom_id, empresa_id, cliente, cliente_nome, oferta_id, oferta_titulo, valor, desconto, pontos, confirmado_por)
  values (c.id, emp, c.cliente, nome, o.id, o.titulo, round(p_valor,2), c.desconto, pts, auth.uid());
  insert into public.pontos_mov (cliente, delta, motivo)
  values (c.cliente, pts, left('Compra: ' || o.titulo, 120));

  -- 1ª compra libera o bônus de boas-vindas e os pontos de quem indicou (evita contas falsas)
  if not p.bonus_liberado then
    insert into public.pontos_mov (cliente, delta, motivo) values (c.cliente, 50, 'Bônus de boas-vindas');
    if p.indicado_por is not null then
      insert into public.pontos_mov (cliente, delta, motivo)
      values (p.indicado_por, 100, left('Indicação: ' || coalesce(nullif(nome,''),'amigo'), 120));
    end if;
    update public.perfis set bonus_liberado = true where id = p.id;
  end if;
  return json_build_object('ok', true, 'pontos', pts, 'cliente', nome);
end $$;

-- Cliente: trocar pontos por brinde (máx. 10 por dia)
create or replace function public.trocar_brinde(p_brinde uuid) returns json
language plpgsql security definer set search_path = '' as $$
declare b public.brindes; saldo int; t public.trocas;
begin
  if auth.uid() is null then raise exception 'Entre na sua conta.' using errcode = 'P0001'; end if;
  perform public.checar_limite('troca:' || auth.uid(), 10, interval '1 day');
  perform 1 from public.perfis where id = auth.uid() for update;   -- uma troca de cada vez
  select * into b from public.brindes where id = p_brinde and ativo for update;
  if not found then raise exception 'Brinde indisponível.' using errcode = 'P0001'; end if;
  if b.estoque is not null and b.estoque <= 0 then raise exception 'Este brinde acabou.' using errcode = 'P0001'; end if;
  select coalesce(sum(delta),0) into saldo from public.pontos_mov where cliente = auth.uid();
  if saldo < b.pontos then raise exception 'Pontos insuficientes.' using errcode = 'P0001'; end if;
  insert into public.pontos_mov (cliente, delta, motivo) values (auth.uid(), -b.pontos, left('Troca: ' || b.nome, 120));
  if b.estoque is not null then update public.brindes set estoque = estoque - 1 where id = b.id; end if;
  insert into public.trocas (cliente, brinde_id, brinde_nome, pontos, codigo)
  values (auth.uid(), b.id, b.nome, b.pontos, public.novo_codigo('BR')) returning * into t;
  return json_build_object('codigo', t.codigo, 'brinde', t.brinde_nome);
end $$;

-- Empresa/admin: conferir e entregar brinde
create or replace function public.entregar_brinde(p_codigo text, p_confirmar boolean default false) returns json
language plpgsql security definer set search_path = '' as $$
declare t public.trocas; b public.brindes; pode boolean; nome text;
begin
  if auth.uid() is null then raise exception 'Entre na sua conta.' using errcode = 'P0001'; end if;
  perform public.checar_limite('brinde:' || auth.uid(), 60, interval '10 minutes');
  select * into t from public.trocas where codigo = upper(trim(p_codigo)) for update;
  if found then select * into b from public.brindes where id = t.brinde_id; end if;
  pode := found and (public.is_admin() or (b.empresa_id is not null and b.empresa_id = public.minha_empresa_id()));
  if not coalesce(pode,false) then return json_build_object('ok', false, 'motivo', 'Código de brinde não encontrado para a sua loja.'); end if;
  select split_part(p.nome,' ',1) into nome from public.perfis p where p.id = t.cliente;
  if p_confirmar then
    if t.status <> 'pendente' then raise exception 'Este brinde já foi entregue.' using errcode = 'P0001'; end if;
    update public.trocas set status = 'retirado', retirado_em = now() where id = t.id;
    t.status := 'retirado';
  end if;
  return json_build_object('ok', true, 'status', t.status, 'brinde', t.brinde_nome, 'cliente', nome);
end $$;

-- Admin: liberar VIP (R$ 9,90) e planos das empresas depois do pagamento
create or replace function public.admin_buscar_cliente(p_email text) returns json
language plpgsql stable security definer set search_path = '' as $$
declare r json;
begin
  if not public.is_admin() then raise exception 'Só administrador.' using errcode = 'P0001'; end if;
  select json_build_object('id', p.id, 'nome', p.nome, 'whatsapp', p.whatsapp, 'vip_ate', p.vip_ate, 'codigo', p.codigo)
    into r from auth.users u join public.perfis p on p.id = u.id where lower(u.email) = lower(trim(p_email));
  return r;
end $$;

create or replace function public.admin_dar_vip(p_cliente uuid, p_dias int) returns timestamptz
language plpgsql security definer set search_path = '' as $$
declare ate timestamptz;
begin
  if not public.is_admin() then raise exception 'Só administrador.' using errcode = 'P0001'; end if;
  if p_dias < 0 or p_dias > 400 then raise exception 'Dias inválidos.' using errcode = 'P0001'; end if;
  update public.perfis set vip_ate = case when p_dias = 0 then null
         else greatest(coalesce(vip_ate, now()), now()) + make_interval(days => p_dias) end
   where id = p_cliente returning vip_ate into ate;
  return ate;
end $$;

create or replace function public.admin_plano(p_empresa uuid, p_plano text, p_dias int) returns timestamptz
language plpgsql security definer set search_path = '' as $$
declare ate timestamptz;
begin
  if not public.is_admin() then raise exception 'Só administrador.' using errcode = 'P0001'; end if;
  if p_plano not in ('gratis','basico','destaque','premium') or p_dias < 0 or p_dias > 400 then
    raise exception 'Plano ou dias inválidos.' using errcode = 'P0001';
  end if;
  update public.empresas set plano = p_plano,
         plano_ate = case when p_plano = 'gratis' then null else greatest(coalesce(plano_ate, now()), now()) + make_interval(days => p_dias) end
   where id = p_empresa returning plano_ate into ate;
  return ate;
end $$;

-- ---------------------------------------------------------------------
-- 9. PERMISSÕES DAS FUNÇÕES (quem pode chamar o quê)
-- ---------------------------------------------------------------------
revoke execute on function public.checar_limite(text,int,interval) from public, anon, authenticated;
revoke execute on function public.novo_usuario()   from public, anon, authenticated;
revoke execute on function public.protege_perfil() from public, anon, authenticated;
revoke execute on function public.protege_empresa() from public, anon, authenticated;
revoke execute on function public.protege_oferta() from public, anon, authenticated;
revoke execute on function public.novo_codigo(text) from public, anon, authenticated;
revoke execute on function public.meus_pontos(), public.pegar_cupom(uuid), public.consultar_cupom(text),
  public.confirmar_compra(text,numeric), public.trocar_brinde(uuid), public.entregar_brinde(text,boolean),
  public.admin_buscar_cliente(text), public.admin_dar_vip(uuid,int), public.admin_plano(uuid,text,int),
  public.minha_empresa_id(), public.minha_cota() from public, anon;
grant execute on function public.meus_pontos(), public.pegar_cupom(uuid), public.consultar_cupom(text),
  public.confirmar_compra(text,numeric), public.trocar_brinde(uuid), public.entregar_brinde(text,boolean),
  public.admin_buscar_cliente(text), public.admin_dar_vip(uuid,int), public.admin_plano(uuid,text,int),
  public.minha_empresa_id(), public.minha_cota() to authenticated;

-- ---------------------------------------------------------------------
-- 10. FOTOS (Storage): cada usuário só mexe na própria pasta, até 2 MB, só imagem
-- ---------------------------------------------------------------------
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

-- ---------------------------------------------------------------------
-- 11. BRINDES INICIAIS (só se a tabela estiver vazia; edite depois no painel do admin)
-- ---------------------------------------------------------------------
insert into public.brindes (nome, pontos, icone)
select * from (values ('Café expresso',150,'coffee'),('Vale-bônus R$ 10',1000,'ticket'),('Camiseta Vitrine Castro',1200,'shirt')) v(n,p,i)
where not exists (select 1 from public.brindes);

-- =====================================================================
-- DEPOIS de criar sua conta na Área da Empresa (empresa.html),
-- rode só a linha abaixo (com o SEU e-mail) para virar administrador:
--
-- insert into public.admins (user_id) select id from auth.users where email = 'SEU_EMAIL_AQUI';
-- =====================================================================
