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
