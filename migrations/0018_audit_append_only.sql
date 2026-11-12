-- The admin audit log is append-only: no row is ever changed or deleted. Only
-- `audit_log` is covered; `tool_calls` and `audit_arguments` are purged by
-- retention and stay as they are.
--
-- One update stays legal: `audit_log.actor_user_id` references users with
-- `on delete set null`, so deleting a user updates the rows that name it, to
-- null only (`actor` keeps the label). Any other update, and every delete, is
-- refused. TRUNCATE does not fire row triggers.
--
-- This trigger is the in-database guard. Revoking UPDATE/DELETE on the table
-- from the application role is left to the operator, because the application
-- owns its tables and an owner can lift the revoke (or drop the trigger) itself.

create function audit_log_append_only() returns trigger
language plpgsql as $$
begin
    if tg_op = 'UPDATE'
       and new.actor_user_id is null
       and old.actor_user_id is not null
       and (new.id, new.at, new.actor, new.action, new.target, new.details)
           is not distinct from
           (old.id, old.at, old.actor, old.action, old.target, old.details)
    then
        return new;
    end if;
    raise exception 'audit_log is append-only';
end;
$$;

create trigger audit_log_append_only
    before update or delete on audit_log
    for each row execute function audit_log_append_only();
