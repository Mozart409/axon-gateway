-- One-time codes for the break-glass admin login, for when the identity
-- provider is down.
--
-- `axon-gateway admin login-link` writes a row; opening the link and confirming
-- consumes it (delete) and starts a short admin session as the built-in
-- break-glass user, a `users` row with issuer `axon:break-glass`. Only the
-- SHA-256 of the code is stored, so a dump of this table opens nothing. A code
-- lives fifteen minutes at most.

create table break_glass_codes (
    code_hash text primary key,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);
