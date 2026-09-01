create table public.workspaces (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users not null,
  name text not null,
  created_at timestamptz default now()
);

create table public.profiles (
  id uuid primary key,
  email text not null,
  full_name text,
  stripe_customer_id text,
  is_admin boolean default false
);

create table public.audit_log (
  id bigserial primary key,
  actor uuid,
  action text
);

alter table public.profiles enable row level security;
alter table public.workspaces enable row level security;

create policy "profiles are viewable by everyone"
  on public.profiles for select
  to anon
  using (true);

create policy "anyone can write workspaces"
  on public.workspaces for all
  to anon
  using (true) with check (true);

create policy "admins via metadata"
  on public.profiles for update
  to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

create or replace function public.promote(target uuid)
returns void language plpgsql security definer as $$
begin
  update public.profiles set is_admin = true where id = target;
end;
$$;

create view public.workspace_overview as
  select w.id, w.name, p.email from public.workspaces w join public.profiles p on p.id = w.user_id;

grant insert, update on public.audit_log to anon;
