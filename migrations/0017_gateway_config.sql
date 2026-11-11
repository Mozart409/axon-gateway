-- The gateway's configuration in the database: backends, gateway toolsets,
-- OIDC providers and the global settings. `spec` holds the config type as
-- JSON without secret values; the secrets of a row are sealed in the
-- `secret_*` columns (envelope encryption, like `catalog_entries`).

create table gateway_backends (
    name           text        primary key,
    spec           jsonb       not null,
    secret_kek_id  text,
    secret_dek     bytea,
    secret_data    bytea,
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now(),
    -- a sealed value is all there or not at all
    constraint gateway_backends_secret_whole check (
        (secret_kek_id is null and secret_dek is null and secret_data is null)
        or (
            secret_kek_id is not null
            and secret_dek is not null
            and secret_data is not null
        )
    )
);

-- gateway toolsets, not the per-user ones in `user_toolsets`
create table gateway_toolsets (
    name       text        primary key,
    spec       jsonb       not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- `position` orders the sign-in buttons and the issuer lookup
create table oidc_providers (
    id             text        primary key,
    position       integer     not null,
    spec           jsonb       not null,
    secret_kek_id  text,
    secret_dek     bytea,
    secret_data    bytea,
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now(),
    constraint oidc_providers_secret_whole check (
        (secret_kek_id is null and secret_dek is null and secret_data is null)
        or (
            secret_kek_id is not null
            and secret_dek is not null
            and secret_data is not null
        )
    )
);

-- one row at most; no row means the defaults
create table gateway_settings (
    id         smallint    primary key default 1 check (id = 1),
    spec       jsonb       not null,
    updated_at timestamptz not null default now()
);

-- a counter every replica can poll to notice a missed notification
create table gateway_config_state (
    id      smallint primary key default 1 check (id = 1),
    version bigint   not null
);

insert into gateway_config_state (id, version) values (1, 0);

-- the configuration changed: bump the version, every replica reloads it
create function axon_notify_config() returns trigger
language plpgsql as $$
begin
    update gateway_config_state set version = version + 1 where id = 1;
    perform pg_notify(
        'axon_changes',
        json_build_object('schema', current_schema(), 'kind', 'config')::text
    );
    return null;
end;
$$;

create trigger gateway_backends_notify
    after insert or update or delete or truncate on gateway_backends
    for each statement execute function axon_notify_config();
create trigger gateway_toolsets_notify
    after insert or update or delete or truncate on gateway_toolsets
    for each statement execute function axon_notify_config();
create trigger oidc_providers_notify
    after insert or update or delete or truncate on oidc_providers
    for each statement execute function axon_notify_config();
create trigger gateway_settings_notify
    after insert or update or delete or truncate on gateway_settings
    for each statement execute function axon_notify_config();
