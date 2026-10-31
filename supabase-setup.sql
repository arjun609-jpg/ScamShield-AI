-- ScamShield AI : Supabase setup
-- Run this ONCE in Supabase Dashboard > SQL Editor > New query > Run.
-- Safe to run again: it uses "if not exists" and "drop policy if exists".

-- ------------------------------------------------------------
-- 1. profiles: one row per user (name + email), created automatically at sign-up
-- ------------------------------------------------------------
create table if not exists public.profiles (
  id         uuid primary key references auth.users (id) on delete cascade,
  full_name  text not null default '',
  email      text,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own" on public.profiles
  for select to authenticated
  using ((select auth.uid()) = id);

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own" on public.profiles
  for update to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

-- No insert/delete policy on purpose: the trigger below creates the row,
-- and deleting an account is handled by Supabase Auth.

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name, email)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'full_name', ''), new.email);
  return new;
end;
$$;

revoke execute on function public.handle_new_user() from public, anon, authenticated;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ------------------------------------------------------------
-- 2. scans: each user's private scan history
-- ------------------------------------------------------------
create table if not exists public.scans (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null default auth.uid() references auth.users (id) on delete cascade,
  created_at timestamptz not null default now(),
  mode       text  not null check (mode in ('message', 'url')),
  input      text  not null check (char_length(input) <= 500),
  score      int   not null check (score between 0 and 100),
  level      text  not null check (level in ('low', 'moderate', 'high', 'critical')),
  indicators jsonb not null default '[]'::jsonb,
  links      int   not null default 0 check (links >= 0)
);

create index if not exists scans_user_created_idx on public.scans (user_id, created_at desc);

alter table public.scans enable row level security;

drop policy if exists "scans_select_own" on public.scans;
create policy "scans_select_own" on public.scans
  for select to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "scans_insert_own" on public.scans;
create policy "scans_insert_own" on public.scans
  for insert to authenticated
  with check ((select auth.uid()) = user_id);

drop policy if exists "scans_delete_own" on public.scans;
create policy "scans_delete_own" on public.scans
  for delete to authenticated
  using ((select auth.uid()) = user_id);

-- No update policy: scans are never edited.

-- ------------------------------------------------------------
-- 3. Keep only each user's latest 50 scans (matches the app's limit)
-- ------------------------------------------------------------
create or replace function public.prune_scans()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  delete from public.scans
  where user_id = new.user_id
    and id not in (
      select id from public.scans
      where user_id = new.user_id
      order by created_at desc
      limit 50
    );
  return null;
end;
$$;

revoke execute on function public.prune_scans() from public, anon, authenticated;

drop trigger if exists scans_prune on public.scans;
create trigger scans_prune
  after insert on public.scans
  for each row execute function public.prune_scans();

-- ------------------------------------------------------------
-- 4. Table permissions: signed-in users only. Visitors who are not logged in get nothing.
-- ------------------------------------------------------------
revoke all on public.profiles from anon;
revoke all on public.scans    from anon;
grant select, update         on public.profiles to authenticated;
grant select, insert, delete on public.scans    to authenticated;