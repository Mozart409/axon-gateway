-- Custom roles: named sets of permissions that admins define in the dashboard
-- or the API and bind like the built-in roles.
--
-- Role bindings name their role without a foreign key, like they name their
-- group: the role may be built in or declared in config rather than stored
-- here. A binding whose role is gone grants nothing. Deleting a stored role
-- removes the bindings that name it in code.

create table rbac_roles (
    name        text        primary key,
    description text,
    -- names of the permissions the role carries, never empty
    permissions text[]      not null check (cardinality(permissions) > 0),
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

alter table rbac_role_bindings drop constraint if exists rbac_role_bindings_role_check;

-- policy tables changed: every replica reloads its policy
create trigger rbac_roles_notify
    after insert or update or delete or truncate on rbac_roles
    for each statement execute function axon_notify_policy();
