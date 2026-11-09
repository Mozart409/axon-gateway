-- Dashboard-managed RBAC: groups, IdP mappings, memberships, grants and role
-- bindings, plus an audit log of every change to them.
--
-- Grants and role bindings name their group without a foreign key: the group
-- may be declared in config rather than stored here, or be `authenticated`.
-- Deleting a stored group removes the grants and bindings that name it in code.

create table rbac_groups (
    name        text        primary key,
    description text,
    created_at  timestamptz not null default now()
);

create table rbac_group_idp_mappings (
    group_name text not null references rbac_groups(name) on delete cascade,
    provider   text not null,
    value      text not null,
    primary key (group_name, provider, value)
);

create table rbac_memberships (
    group_name text        not null references rbac_groups(name) on delete cascade,
    user_id    uuid        not null references users(id) on delete cascade,
    created_at timestamptz not null default now(),
    primary key (group_name, user_id)
);

create table rbac_grants (
    id         bigint      generated always as identity primary key,
    group_name text        not null,
    backend    text        not null,
    include    text[]      not null,
    exclude    text[]      not null default '{}',
    read_only  boolean     not null default false,
    mandatory  boolean     not null default false,
    created_at timestamptz not null default now()
);

create table rbac_role_bindings (
    id         bigint      generated always as identity primary key,
    role       text        not null check (role in ('admin', 'backend-admin', 'auditor', 'member')),
    group_name text,
    user_id    uuid        references users(id) on delete cascade,
    created_at timestamptz not null default now(),
    -- a binding names a group or a user, never both
    check ((group_name is null) <> (user_id is null))
);

create unique index rbac_role_bindings_group on rbac_role_bindings (role, group_name)
    where group_name is not null;
create unique index rbac_role_bindings_user on rbac_role_bindings (role, user_id)
    where user_id is not null;

create table audit_log (
    id            bigint      generated always as identity primary key,
    at            timestamptz not null default now(),
    -- null once the user is deleted; `actor` keeps the label
    actor_user_id uuid        references users(id) on delete set null,
    actor         text        not null,
    action        text        not null,
    target        text        not null,
    details       jsonb       not null default '{}'
);

create index audit_log_at on audit_log (at desc, id desc);
