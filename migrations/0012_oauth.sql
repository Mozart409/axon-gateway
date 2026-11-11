-- The MCP OAuth authorization server: registered clients, authorization
-- requests waiting for the dashboard login and consent, single-use codes,
-- grants (what the "Connected apps" page lists) and the access and refresh
-- tokens issued under a grant.
--
-- Client ID Metadata Document clients have no row: their metadata is fetched
-- and cached in memory, so `client_id` in the other tables is not a foreign
-- key. Only the SHA-256 of a code or a token secret is stored.

create table oauth_clients (
    client_id      text        primary key,
    client_name    text,
    redirect_uris  text[]      not null,
    grant_types    text[]      not null default '{authorization_code,refresh_token}',
    response_types text[]      not null default '{code}',
    created_at     timestamptz not null default now(),
    last_used_at   timestamptz
);

-- Registrations nobody used are deleted by their last sign of life
create index oauth_clients_activity on oauth_clients ((coalesce(last_used_at, created_at)));

create table oauth_requests (
    id             text        primary key,
    client_id      text        not null,
    client_name    text,
    redirect_uri   text        not null,
    code_challenge text        not null,
    state          text,
    scope          text        not null,
    resource       text        not null,
    created_at     timestamptz not null default now(),
    expires_at     timestamptz not null
);

create index oauth_requests_expires on oauth_requests (expires_at);

create table oauth_codes (
    code_hash      bytea       primary key,
    client_id      text        not null,
    client_name    text,
    redirect_uri   text        not null,
    code_challenge text        not null,
    user_id        uuid        not null references users(id) on delete cascade,
    scope          text        not null,
    resource       text        not null,
    created_at     timestamptz not null default now(),
    expires_at     timestamptz not null,
    -- Set when the code is redeemed; a second use finds it and revokes the grant
    grant_id       uuid
);

create index oauth_codes_expires on oauth_codes (expires_at);

create table oauth_grants (
    id           uuid        primary key default gen_random_uuid(),
    client_id    text        not null,
    client_name  text,
    user_id      uuid        not null references users(id) on delete cascade,
    scope        text        not null,
    resource     text        not null,
    created_at   timestamptz not null default now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);

create index oauth_grants_user on oauth_grants (user_id) where revoked_at is null;
create index oauth_grants_revoked on oauth_grants (revoked_at) where revoked_at is not null;

create table oauth_tokens (
    id          uuid        primary key default gen_random_uuid(),
    grant_id    uuid        not null references oauth_grants(id) on delete cascade,
    kind        text        not null check (kind in ('access', 'refresh')),
    public_id   text        not null unique,
    secret_hash bytea       not null,
    created_at  timestamptz not null default now(),
    expires_at  timestamptz not null,
    -- A refresh token is single use: set when it is exchanged
    used_at     timestamptz
);

create index oauth_tokens_grant on oauth_tokens (grant_id);
create index oauth_tokens_expires on oauth_tokens (expires_at);
