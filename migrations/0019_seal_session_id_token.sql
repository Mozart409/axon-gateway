-- The OIDC ID token of a session is kept sealed (see src/crypto.rs) and bound to
-- the session's token hash, not in plaintext. Sessions open before this lose
-- their logout hint; the logout still works without it.
alter table sessions
    drop column id_token,
    add column id_token_kek_id text,
    add column id_token_dek bytea,
    add column id_token_data bytea,
    -- a sealed value is all there or not at all
    add constraint sessions_id_token_whole check (
        (id_token_kek_id is null and id_token_dek is null and id_token_data is null)
        or (
            id_token_kek_id is not null
            and id_token_dek is not null
            and id_token_data is not null
        )
    );
