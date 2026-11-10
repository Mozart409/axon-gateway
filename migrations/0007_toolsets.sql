-- Toolsets owned by a user, and tokens pinned to one.
--
-- A toolset is a named list of tool globs and backends, like a config
-- `[[toolsets]]` entry but private to its owner. It only ever narrows: what a
-- caller may use is still the intersection of the owner's grants, the token
-- scope and the toolset. A token pinned to a toolset reads the toolset's lists
-- on every request, so editing the toolset changes the token at once. An empty
-- list means no narrowing, as in a token scope.
--
-- `on delete restrict` keeps a toolset that a token still points at; the store
-- first clears the link of revoked and expired tokens, and refuses to delete a
-- toolset a live token pins.

create table user_toolsets (
    id          uuid        primary key default gen_random_uuid(),
    owner_id    uuid        not null references users(id) on delete cascade,
    name        text        not null,
    description text,
    tools       text[]      not null default '{}',
    backends    text[]      not null default '{}',
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now(),
    unique (owner_id, name)
);

alter table api_tokens
    add column toolset_id uuid references user_toolsets(id) on delete restrict;

create index api_tokens_toolset on api_tokens (toolset_id) where toolset_id is not null;
