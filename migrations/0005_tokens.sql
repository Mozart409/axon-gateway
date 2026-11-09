-- Personal access tokens and service accounts, so agents can authenticate to
-- the MCP endpoint as a principal.
--
-- A service account is a `users` row with kind = 'service', so group
-- memberships, role bindings and tool opt-outs work for it unchanged. Only the
-- SHA-256 of a token's secret is stored; the public id is what the lookup uses.

alter table users
    add column kind        text not null default 'user' check (kind in ('user', 'service')),
    add column disabled_at timestamptz,
    add column description text;

create table api_tokens (
    id             uuid        primary key default gen_random_uuid(),
    public_id      text        not null unique,
    secret_hash    bytea       not null,
    owner_id       uuid        not null references users(id) on delete cascade,
    name           text        not null,
    scope_backends text[]      not null default '{}',
    scope_tools    text[]      not null default '{}',
    created_at     timestamptz not null default now(),
    expires_at     timestamptz not null,
    last_used_at   timestamptz,
    last_used_ip   text,
    revoked_at     timestamptz
);

create index api_tokens_owner on api_tokens (owner_id);
