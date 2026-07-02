-- Run this once in the Supabase SQL editor (or via supabase db push).

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  password_hash text not null,
  salt text not null,
  created_at timestamptz not null default now()
);

create table if not exists sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  device text,
  ip text,
  created_at timestamptz not null default now(),
  last_active timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked boolean not null default false
);

create table if not exists refresh_tokens (
  token_hash text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  used boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists push_subscriptions (
  endpoint text primary key,
  user_id uuid not null references users(id) on delete cascade,
  subscription jsonb not null,
  created_at timestamptz not null default now()
);

create index if not exists sessions_user_idx on sessions (user_id);
create index if not exists refresh_tokens_session_idx on refresh_tokens (session_id);
create index if not exists push_subscriptions_user_idx on push_subscriptions (user_id);

-- These tables are only ever touched by the server using the service-role
-- key, which bypasses RLS. Enabling RLS with no policies blocks any access
-- through the anon/public API.
alter table users enable row level security;
alter table sessions enable row level security;
alter table refresh_tokens enable row level security;
alter table push_subscriptions enable row level security;
