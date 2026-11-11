-- Bindings of an IdP subject to a service account, so a JWT access token the
-- IdP issued for that subject (resource-server mode) acts as the service
-- account. A subject with no binding resolves to the human user with the same
-- issuer and subject, if any.

create table jwt_bindings (
    id                 uuid        primary key default gen_random_uuid(),
    service_account_id uuid        not null references users(id) on delete cascade,
    issuer             text        not null,
    subject            text        not null,
    created_at         timestamptz not null default now(),
    created_by         uuid        references users(id) on delete set null,
    unique (issuer, subject)
);

create index jwt_bindings_service_account on jwt_bindings (service_account_id);
