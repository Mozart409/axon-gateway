# Bootstrap: the environment of database mode

Source: `src/bootstrap.rs` (and `crypto.rs` for the KEK). Database mode is
selected by `AXON_DATABASE_URL` being set; the gateway then reads no config
file and exits with an error if one is named.

| Variable | Default | Meaning |
| --- | --- | --- |
| `AXON_DATABASE_URL` | none | Postgres URL; setting it selects database mode |
| `AXON_KEK_FILE` or `AXON_KEK` | none, required | key-encryption key, a path or the text; secrets in the database are sealed with it. One line per KEK, `[id:]secret`, first line active, at least 32 characters; generate with `pwgen -s 48 1` |
| `AXON_BIND` | `0.0.0.0:8080` | listen address |
| `AXON_BASE_URL` | `http://localhost:8080` | public URL; OIDC redirects, session cookie (`__Host-` needs HTTPS), OAuth issuer/resource, links |
| `AXON_ALLOW_STDIO` | off | `true` or `1` lets stdio backends run; the only switch for it, the dashboard and API cannot |
| `AXON_OIDC_ISSUER` | none | with it, a bootstrap OIDC provider is configured (listed first, read-only in the UI, source `env`) |
| `AXON_OIDC_CLIENT_ID` | none | required when the issuer is set (else startup fails) |
| `AXON_OIDC_CLIENT_SECRET_FILE` | none | file with the client secret (content trimmed; empty file is an error); leave out for a public PKCE client |
| `AXON_OIDC_ADMIN_GROUPS` | none | comma-separated groups whose members are admins |
| `AXON_OIDC_SCOPES` | `openid,profile,email` | comma-separated; `openid` is always added first if missing |
| `AXON_OIDC_ID` | `sso` | the provider id, used in URLs |
| `AXON_OIDC_DISPLAY_NAME` | the id | login button label |

Values are trimmed; blank variables count as unset. A provider in the database
with the same id as the bootstrap one is ignored, with a warning.

## First start

```sh
export AXON_DATABASE_URL=postgres://axon:...@db.example.com/axon
export AXON_KEK_FILE=/run/secrets/axon-kek
export AXON_BASE_URL=https://axon.example.com
export AXON_OIDC_ISSUER=https://id.example.com
export AXON_OIDC_CLIENT_ID=axon
export AXON_OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc-secret
export AXON_OIDC_ADMIN_GROUPS=axon-admins
export AXON_OIDC_SCOPES=openid,profile,email,groups
axon-gateway
```

- Migrations run at startup; `/readyz` pings the database and answers 503 when
  it does not answer within 2 s.
- The IdP must send the groups claim for `admin_groups` to work (Pocket ID only
  with the `groups` scope; Entra needs the claim configured or app roles via
  `groups_claim = "roles"`).
- Without any OIDC provider the only way in is the break-glass link: run
  `axon-gateway admin login-link` with the same environment (needs
  `AXON_DATABASE_URL` and `AXON_BASE_URL`), open the printed URL within 15
  minutes, confirm, and get a one-hour admin session as "Break-glass admin".
  Turn it off afterwards by disabling that user on `/ui/admin/users`. Creating
  and using the link are audited.

## Container and Compose shape

`example/compose.yml` runs the published image
(`ghcr.io/mozart409/axon-gateway:latest`) with the config file mounted
read-only at `/app/config.toml` and passed as the command — that is standalone
mode. For database mode: mount no config, drop the `command`, and pass the
environment above instead (the Kubernetes Helm chart does exactly this; see
`deploy/helm/axon-gateway/README.md`).

- **Healthcheck:** the runtime image is the minimal Chainguard `wolfi-base`,
  which ships no HTTP client. The `compose.yml` healthcheck probes `/health`
  with `wget`, so the Dockerfile installs `apk add --no-cache wget`; keep that
  line in sync with the `healthcheck:` block if you edit either.
- **DNS:** the container fixes `/etc/resolv.conf` at start; pin a resolver
  (`dns:` in Compose or `--dns=<ip>`) or restart the container after the host's
  DNS setup changes, or hostname backends fail with name-resolution errors.
- The container runs as UID 65532 (wolfi `nonroot`): mounted secrets must be
  readable by that UID.

## Secret rotation (KEK)

The KEK value supports multiple lines to rotate without downtime:

1. Put the new key first, keep the old line below it, restart.
2. Run `axon-gateway admin rewrap-secrets` with the same environment (it
   re-wraps the data keys of personal backends, catalog credentials and the
   sealed secrets of backends and OIDC providers, and prints the counts).
3. Drop the old line, restart.

A secret that cannot be unsealed (a KEK that was dropped before the rewrap)
skips its row with a warning instead of stopping the gateway.
