-- Personal MCP backends, the admin catalog of backends users can connect, and
-- the credentials users store for catalog (or configured) backends. Secrets
-- are sealed by the gateway; the three secret_* columns hold the key id, the
-- wrapped data key and the ciphertext of one sealed value.

-- a backend one user added for themselves
create table personal_backends (
    id            uuid        primary key default gen_random_uuid(),
    owner_id      uuid        not null references users (id) on delete cascade,
    prefix        text        not null,
    url           text        not null,
    header_names  text[]      not null default '{}',
    secret_kek_id text,
    secret_dek    bytea,
    secret_data   bytea,
    enabled       boolean     not null default true,
    created_at    timestamptz not null default now(),
    updated_at    timestamptz not null default now(),
    last_ok_at    timestamptz,
    last_error_at timestamptz,
    last_error    text,
    unique (owner_id, prefix),
    -- a sealed value is all there or not at all
    check (
        (secret_kek_id is null and secret_dek is null and secret_data is null)
        or (secret_kek_id is not null and secret_dek is not null and secret_data is not null)
    )
);

-- a backend an admin offers to every user, who bring their own credentials
create table catalog_entries (
    name              text        primary key,
    description       text,
    url               text        not null,
    credential_fields jsonb       not null default '[]',
    enabled           boolean     not null default true,
    created_by        text,
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now()
);

-- one user's credentials for a backend; the backend is a catalog entry name or
-- a configured backend name, so it is not a foreign key
create table user_credentials (
    user_id       uuid        not null references users (id) on delete cascade,
    backend       text        not null,
    secret_kek_id text        not null,
    secret_dek    bytea       not null,
    secret_data   bytea       not null,
    created_at    timestamptz not null default now(),
    updated_at    timestamptz not null default now(),
    last_ok_at    timestamptz,
    last_error_at timestamptz,
    last_error    text,
    primary key (user_id, backend)
);

-- Change notifications, as in 0009. The triggers on update name the
-- configuration columns only: the last_* outcome columns change on every tool
-- call and must not make replicas drop the user's connections.

create function axon_notify_personal_backend() returns trigger
language plpgsql as $$
declare
    uid uuid;
begin
    if tg_op = 'DELETE' then
        uid := old.owner_id;
    else
        uid := new.owner_id;
    end if;
    perform pg_notify(
        'axon_changes',
        json_build_object('schema', current_schema(), 'kind', 'user', 'user', uid)::text
    );
    return null;
end;
$$;

create function axon_notify_user_credential() returns trigger
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

-- the catalog changed: every replica reloads it
create function axon_notify_catalog() returns trigger
language plpgsql as $$
begin
    perform pg_notify(
        'axon_changes',
        json_build_object('schema', current_schema(), 'kind', 'catalog')::text
    );
    return null;
end;
$$;

create trigger personal_backends_notify_change
    after insert or delete on personal_backends
    for each row execute function axon_notify_personal_backend();
create trigger personal_backends_notify_update
    after update of prefix, url, header_names, secret_kek_id, secret_dek, secret_data, enabled
    on personal_backends
    for each row execute function axon_notify_personal_backend();

create trigger user_credentials_notify_change
    after insert or delete on user_credentials
    for each row execute function axon_notify_user_credential();
create trigger user_credentials_notify_update
    after update of secret_kek_id, secret_dek, secret_data on user_credentials
    for each row execute function axon_notify_user_credential();

create trigger catalog_entries_notify
    after insert or update or delete or truncate on catalog_entries
    for each statement execute function axon_notify_catalog();
