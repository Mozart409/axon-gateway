-- Server-side state for the OIDC login of the web UI.
--
-- `users` gains the authorization data of the last login: `groups` and
-- `is_admin` are refreshed from the ID token each time the user signs in.
--
-- `oidc_flows` holds a login between the redirect to the provider and the
-- callback: the PKCE verifier and nonce, keyed by the SHA-256 of the `state`
-- parameter. A row is consumed (deleted) by the callback and lives ten minutes
-- at most.
--
-- `sessions` holds a finished login. The browser carries a random token in a
-- cookie; only its SHA-256 is stored, so a dump of this table logs nobody in.
-- A session ends with its user (cascade), at `expires_at`, or after sitting
-- idle past the timeout the application enforces on `last_seen_at`.

alter table users
    add column groups text[] not null default '{}',
    add column is_admin boolean not null default false;

create table oidc_flows (
    state_hash text primary key,
    provider_id text not null,
    pkce_verifier text not null,
    nonce text not null,
    return_to text not null,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);

create index oidc_flows_expires_at_idx on oidc_flows (expires_at);

create table sessions (
    id bigint generated always as identity primary key,
    token_hash text not null unique,
    user_id uuid not null references users (id) on delete cascade,
    provider_id text not null,
    csrf_token text not null,
    id_token text,
    created_at timestamptz not null default now(),
    last_seen_at timestamptz not null default now(),
    expires_at timestamptz not null
);

create index sessions_expires_at_idx on sessions (expires_at);
create index sessions_user_id_idx on sessions (user_id);
