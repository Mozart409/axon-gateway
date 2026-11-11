-- State that several gateway replicas share on one database: a rate-limit
-- counter, a job lease, MCP sessions and change notifications.

-- one counter per key and minute
create table rate_limit_windows (
    key          text        not null,
    window_start timestamptz not null,
    count        integer     not null,
    primary key (key, window_start)
);

-- when a periodic job last ran, so only one replica runs it per interval
create table job_runs (
    job         text        primary key,
    last_run_at timestamptz not null
);

-- MCP sessions, keyed by the sha-256 of the session id
create table mcp_sessions (
    id_hash      bytea       primary key,
    owner        text,
    state        jsonb,
    created_at   timestamptz not null default now(),
    last_seen_at timestamptz not null default now()
);

create index mcp_sessions_last_seen on mcp_sessions (last_seen_at);

-- Change notifications. The payload names the schema, because gateways in
-- different schemas may share one database and the channel is database-wide.

-- policy tables changed: every replica reloads its policy
create function axon_notify_policy() returns trigger
language plpgsql as $$
begin
    perform pg_notify(
        'axon_changes',
        json_build_object('schema', current_schema(), 'kind', 'policy')::text
    );
    return null;
end;
$$;

create trigger rbac_groups_notify
    after insert or update or delete or truncate on rbac_groups
    for each statement execute function axon_notify_policy();
create trigger rbac_group_idp_mappings_notify
    after insert or update or delete or truncate on rbac_group_idp_mappings
    for each statement execute function axon_notify_policy();
create trigger rbac_memberships_notify
    after insert or update or delete or truncate on rbac_memberships
    for each statement execute function axon_notify_policy();
create trigger rbac_grants_notify
    after insert or update or delete or truncate on rbac_grants
    for each statement execute function axon_notify_policy();
create trigger rbac_role_bindings_notify
    after insert or update or delete or truncate on rbac_role_bindings
    for each statement execute function axon_notify_policy();

-- one user's opt-outs changed
create function axon_notify_user_opt_out() returns trigger
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

-- one user's toolsets changed
create function axon_notify_user_toolset() returns trigger
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

create trigger tool_opt_outs_notify
    after insert or update or delete on tool_opt_outs
    for each row execute function axon_notify_user_opt_out();
create trigger user_toolsets_notify
    after insert or update or delete on user_toolsets
    for each row execute function axon_notify_user_toolset();
