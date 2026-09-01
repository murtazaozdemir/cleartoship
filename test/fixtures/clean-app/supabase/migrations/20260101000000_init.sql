create table public.workspaces (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users not null,
  name text not null
);

alter table public.workspaces enable row level security;

create policy "workspaces are owned"
  on public.workspaces for all
  to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create or replace function public.touch()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create view public.workspace_names with (security_invoker = on) as
  select id, name from public.workspaces;
