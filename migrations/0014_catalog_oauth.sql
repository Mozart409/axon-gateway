-- Catalog entries can sign users in with OAuth instead of asking for header
-- values. `oauth_client_id` and the sealed secret name a static client; without
-- them the gateway uses a client ID metadata document or registers itself.
alter table catalog_entries
    add column auth text not null default 'fields'
        check (auth in ('fields', 'oauth')),
    add column oauth_client_id text,
    add column oauth_scopes text[] not null default '{}',
    add column oauth_secret_kek_id text,
    add column oauth_secret_dek bytea,
    add column oauth_secret_data bytea,
    -- a sealed value is all there or not at all
    add constraint catalog_entries_oauth_secret_whole check (
        (oauth_secret_kek_id is null and oauth_secret_dek is null and oauth_secret_data is null)
        or (
            oauth_secret_kek_id is not null
            and oauth_secret_dek is not null
            and oauth_secret_data is not null
        )
    );
