-- SCIM 2.0 provisioning: an identity provider pushes users and groups to
-- /scim/v2/{provider}. One bearer token per provider, stored as a SHA-256.

create table scim_tokens (
    provider     text        primary key,
    token_hash   bytea       not null,
    created_at   timestamptz not null default now(),
    last_used_at timestamptz
);

-- a user as the provider pushed it; user_id is the login it was linked to
-- (by externalId or by userName = email), linked_by says which
create table scim_users (
    id              uuid        primary key default gen_random_uuid(),
    provider        text        not null,
    user_name       text        not null,
    external_id     text,
    display_name    text,
    given_name      text,
    family_name     text,
    name_formatted  text,
    emails          jsonb       not null default '[]',
    active          boolean     not null default true,
    user_id         uuid        references users (id) on delete set null,
    linked_by       text        check (linked_by in ('external_id', 'email')),
    -- SCIM disabled the linked user, so SCIM may enable it again; a user an
    -- admin disabled by hand is never enabled by SCIM
    disabled_by_scim boolean    not null default false,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    unique (provider, user_name)
);

create unique index scim_users_user_name_ci on scim_users (provider, lower(user_name));
create index scim_users_external_id on scim_users (provider, external_id);
create unique index scim_users_user on scim_users (user_id) where user_id is not null;

create table scim_groups (
    id           uuid        primary key default gen_random_uuid(),
    provider     text        not null,
    display_name text        not null,
    external_id  text,
    created_at   timestamptz not null default now(),
    updated_at   timestamptz not null default now(),
    unique (provider, display_name)
);

create unique index scim_groups_display_name_ci on scim_groups (provider, lower(display_name));
create index scim_groups_external_id on scim_groups (provider, external_id);

create table scim_group_members (
    group_id     uuid not null references scim_groups (id) on delete cascade,
    scim_user_id uuid not null references scim_users (id) on delete cascade,
    primary key (group_id, scim_user_id)
);

create index scim_group_members_user on scim_group_members (scim_user_id);

-- where users.groups comes from: the ID token's claims, or SCIM once a SCIM
-- user is linked (a login then leaves the groups alone)
alter table users
    add column groups_source text not null default 'claims'
        check (groups_source in ('claims', 'scim'));
