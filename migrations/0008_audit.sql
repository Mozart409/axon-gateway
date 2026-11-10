-- Tool-call audit: who called which tool, and (optionally) with what.
--
-- `tool_calls` holds the metadata of every tool call, always: who, how they
-- authenticated, backend and tool, outcome, duration, trace id, client address.
-- The arguments live apart in `audit_arguments` with a shorter retention, and
-- are stored only when a capture rule (or the default from the tool's MCP
-- annotations) says so. Tool results are never stored.
--
-- `audit_capture_rules` are the admin's overrides per backend and tool glob:
-- `none`, `redacted` (values under keys that look like secrets are masked) or
-- `full`, plus keys to drop outright. `audit_settings` is a single row with the
-- retention of both tables, in days.
--
-- Compliance: arguments are personal data (GDPR: purpose limitation,
-- retention, data-subject requests). With a works council, logging per-employee
-- activity is co-determined (section 87(1) no. 6 BetrVG). Review `full`
-- capture with the council and the data protection officer before enabling it.

create table tool_calls (
    id bigserial primary key,
    at timestamptz not null default now(),
    -- Null once the user is deleted; `principal_label` keeps who it was.
    user_id uuid references users (id) on delete set null,
    principal_label text not null,
    -- No foreign key: a token row may be deleted while its calls stay.
    token_id uuid,
    auth_method text not null,
    backend text not null,
    -- The backend's own tool name, not the namespaced one.
    tool text not null,
    outcome text not null check (outcome in ('ok', 'error', 'tool_error')),
    error_code integer,
    error_message text,
    duration_ms integer not null,
    trace_id text,
    client_ip text,
    user_agent text
);

create index tool_calls_at_idx on tool_calls (at);
create index tool_calls_user_at_idx on tool_calls (user_id, at);
create index tool_calls_backend_tool_at_idx on tool_calls (backend, tool, at);

create table audit_arguments (
    call_id bigint primary key references tool_calls (id) on delete cascade,
    -- Copied from the call, so the purge needs no join.
    at timestamptz not null,
    capture text not null check (capture in ('redacted', 'full')),
    arguments jsonb not null
);

create index audit_arguments_at_idx on audit_arguments (at);

create table audit_capture_rules (
    id bigserial primary key,
    -- A backend name, or `*` for every backend.
    backend text not null,
    -- A glob on the original tool name, matched like grants are.
    tool_pattern text not null,
    mode text not null check (mode in ('none', 'redacted', 'full')),
    drop_keys text[] not null default '{}',
    created_at timestamptz not null default now(),
    created_by text
);

create table audit_settings (
    id boolean primary key default true check (id),
    arguments_retention_days integer not null default 30 check (arguments_retention_days > 0),
    metadata_retention_days integer not null default 365 check (metadata_retention_days > 0)
);

insert into audit_settings (id) values (true);
