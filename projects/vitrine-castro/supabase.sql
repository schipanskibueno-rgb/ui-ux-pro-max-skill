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
create unique index if not exists empresas_um_por_dono on public.empresas(dono);

-- Só você (admin) pode aprovar e mudar o plano
create or replace function public.protege_empresa() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    if tg_op = 'INSERT' then
      new.aprovada := false; new.plano := 'basico'; new.dono := auth.uid();
    else
      new.aprovada := old.aprovada; new.plano := old.plano; new.dono := old.dono;
    end if;
  end if;
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
create or replace function public.consultar_cupom(p_codigo text) returns json
language plpgsql security definer set search_path = public as $$
declare emp uuid; c public.cupons; tit text;
begin
  select id into emp from public.empresas where dono = auth.uid();
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
create or replace function public.confirmar_cupom(p_codigo text, p_valor numeric) returns json
language plpgsql security definer set search_path = public as $$
declare emp uuid; c public.cupons;
begin
  select id into emp from public.empresas where dono = auth.uid() and aprovada;
  if emp is null then raise exception 'Só lojas aprovadas podem confirmar compras.'; end if;
  if p_valor is null or p_valor <= 0 or p_valor > 50000 then raise exception 'Valor da compra inválido.'; end if;
  select * into c from public.cupons where codigo = upper(trim(p_codigo)) and empresa_id = emp for update;  -- trava contra confirmar 2 vezes
  if not found then return json_build_object('ok', false, 'motivo', 'Código não encontrado para a sua loja.'); end if;
  if c.usado_em is not null then return json_build_object('ok', false, 'motivo', 'Este cupom já foi usado.'); end if;
  update public.cupons set usado_em = now(), valor = round(p_valor, 2) where codigo = c.codigo;
  insert into public.eventos (oferta_id, empresa_id, tipo, aparelho, valor) values (c.oferta_id, emp, 'compra', c.aparelho, round(p_valor, 2));
  return json_build_object('ok', true);
end $$;

-- Área da Empresa: números da PRÓPRIA loja por oferta e por dia
create or replace function public.metricas_empresa(p_desde date) returns table (oferta_id uuid, tipo text, dia date, qtd bigint, valor numeric)
language sql stable security definer set search_path = public as $$
  select ev.oferta_id, ev.tipo, ev.dia, count(*), coalesce(sum(ev.valor), 0)
    from public.eventos ev join public.empresas e on e.id = ev.empresa_id
   where e.dono = auth.uid() and ev.dia >= p_desde
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
  public.consultar_cupom(text), public.confirmar_cupom(text,numeric), public.metricas_empresa(date) from public, anon;
grant execute on function public.registrar_evento(uuid,text,text), public.emitir_cupom(uuid,text) to anon, authenticated;
grant execute on function public.consultar_cupom(text), public.confirmar_cupom(text,numeric), public.metricas_empresa(date) to authenticated;

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

-- =====================================================================
-- DEPOIS de criar sua conta na Área da Empresa (empresa.html),
-- rode só a linha abaixo (com o SEU e-mail) para virar administrador:
--
-- insert into public.admins (user_id) select id from auth.users where email = 'SEU_EMAIL_AQUI';
-- =====================================================================
