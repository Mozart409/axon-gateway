-- A user's identity is (issuer, subject) from the OIDC provider; email and
-- display_name are informational and may change between logins.
create table users (
    id uuid primary key default gen_random_uuid(),
    issuer text not null,
    subject text not null,
    email text,
    display_name text,
    created_at timestamptz not null default now(),
    last_login_at timestamptz,
    unique (issuer, subject)
);
