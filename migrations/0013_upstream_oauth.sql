-- OAuth client side: the gateway signs users in to backends that run their own
-- authorization server. Tokens are sealed like every other secret (see
-- `crypto`); the store never sees plaintext.

-- a client registered at a backend's authorization server, shared by every
-- user; a confidential registration keeps its secret sealed
create table upstream_oauth_clients (
    backend       text        not null,
    issuer        text        not null,
    client_id     text        not null,
    secret_kek_id text,
    secret_dek    bytea,
    secret_data   bytea,
    created_at    timestamptz not null default now(),
    primary key (backend, issuer),
    -- a sealed value is all there or not at all
    check (
        (secret_kek_id is null and secret_dek is null and secret_data is null)
        or (secret_kek_id is not null and secret_dek is not null and secret_data is not null)
    )
);

-- an authorization request waiting for the redirect back; taken once
create table upstream_oauth_requests (
    state          text        primary key,
    user_id        uuid        not null references users (id) on delete cascade,
    backend        text        not null,
    issuer         text        not null,
    client_id      text        not null,
    token_endpoint text        not null,
    redirect_uri   text        not null,
    pkce_verifier  text        not null,
    return_to      text,
    -- how the token endpoint is authenticated, chosen once from the server's
    -- metadata so neither the callback nor a refresh discovers again
    token_auth_method text     not null
        check (token_auth_method in ('none', 'client_secret_basic', 'client_secret_post')),
    -- whether the server returns `iss` on the redirect (RFC 9207)
    iss_supported  boolean     not null default false,
    created_at     timestamptz not null default now()
);

create index upstream_oauth_requests_created_at on upstream_oauth_requests (created_at);

-- one user's tokens for a backend; the sealed JSON holds the access token and
-- the refresh token when there is one
create table upstream_oauth_tokens (
    user_id        uuid        not null references users (id) on delete cascade,
    backend        text        not null,
    issuer         text        not null,
    client_id      text        not null,
    token_endpoint text        not null,
    scope          text,
    token_auth_method text     not null
        check (token_auth_method in ('none', 'client_secret_basic', 'client_secret_post')),
    secret_kek_id  text        not null,
    secret_dek     bytea       not null,
    secret_data    bytea       not null,
    expires_at     timestamptz not null,
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now(),
    last_error     text,
    last_error_at  timestamptz,
    primary key (user_id, backend)
);

-- the refresh token an identity provider gave at login, to get fresh subject
-- tokens for the passthrough grants
create table idp_refresh_tokens (
    user_id       uuid        not null references users (id) on delete cascade,
    provider      text        not null,
    secret_kek_id text        not null,
    secret_dek    bytea       not null,
    secret_data   bytea       not null,
    updated_at    timestamptz not null default now(),
    primary key (user_id, provider)
);

-- Change notification as for user_credentials in 0010. Insert and delete only:
-- a refresh rewrites the tokens about hourly and must not make replicas drop
-- the user's connections.
create function axon_notify_upstream_oauth_token() returns trigger
language plpgsql as $$
declare
    uid uuid;
begin
    if tg_op = 'DELETE' then
        uid := old.user_id;
    else
        uid := new.user_id;
    end if;
    perform pg_notify(
        'axon_changes',
        json_build_object('schema', current_schema(), 'kind', 'user', 'user', uid)::text
    );
    return null;
end;
$$;

create trigger upstream_oauth_tokens_notify_change
    after insert or delete on upstream_oauth_tokens
    for each row execute function axon_notify_upstream_oauth_token();
