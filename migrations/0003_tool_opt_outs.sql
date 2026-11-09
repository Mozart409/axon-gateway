-- Per-user tool opt-outs: the tools a user hides from their own tool list.
--
-- A row with tool = '' hides the whole backend; any other row hides one tool
-- by its original name. This is a view preference, not an access control: the
-- gateway does not refuse calls to a hidden tool.

create table tool_opt_outs (
    user_id     uuid        not null references users(id) on delete cascade,
    backend     text        not null,
    -- '' hides the whole backend; otherwise the tool's original name
    tool        text        not null default '',
    created_at  timestamptz not null default now(),
    primary key (user_id, backend, tool)
);
