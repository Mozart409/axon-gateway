# Admin UI and API: day-2 configuration

Sources: `e2e/lib/routes.ts` (the page list the coverage test enforces),
`src/server/admin_views.rs`, `config_views.rs`, `audit_views.rs`,
`usage_views.rs`, `personal_views.rs`, `tokens_views.rs`, `scim_admin.rs`, and
the `config_api.rs`/`admin_api.rs` route tables. The README documents the API
in full; this is the map.

## Admin pages (`/ui/admin` …)

The "Admin" link in the user bar is shown to users with `groups.manage` or
`audit.read`. Page by page:

| Page | Purpose | Permission to use |
| --- | --- | --- |
| `/ui/admin` | Hub: groups (detail `/ui/admin/groups/{name}`), grants, role bindings, audit log links | `groups.manage` / `audit.read` to see; writes `groups.manage` |
| `/ui/admin/roles` | Custom roles and bindings | reads `groups.manage`/`roles.manage`/`audit.read`; writes `roles.manage` + the role's permissions |
| `/ui/admin/users` | Disable/enable users | `users.manage` |
| `/ui/admin/service-accounts` | Service accounts, their tokens, JWT bindings | `service_accounts.manage` |
| `/ui/admin/scim` | SCIM tokens per provider (shown once, rotated by re-creating) | `users.manage` + `groups.manage` + every permission of any role bound to a group (an admin holds all) |
| `/ui/admin/personal-backends` | List/disable/delete anyone's personal servers | `users.manage` |
| `/ui/admin/audit` | Audit log | `audit.read` |
| `/ui/admin/tool-calls` (+ detail) | Tool-call records | `audit.read`; stored arguments need `audit.read_sensitive` |
| `/ui/admin/usage` (+ per-user) | Usage views | `audit.read` |
| `/ui/admin/audit-settings` | Retention (1–3650 days), capture rules | `audit.read` to see, `gateway.admin` to change |
| `/ui/admin/config/backends` (+ detail) | Shared backends and catalog entries | write `backends.manage`, read `backends.view`/`backends.manage` |
| `/ui/admin/config/toolsets` | Gateway toolsets (`[[toolsets]]`) | as the backends |
| `/ui/admin/config/oidc-providers` | OIDC providers | `gateway.admin` |
| `/ui/admin/config/settings` | Gateway settings (`rate_limit_per_minute`, `allowed_hosts`, `idle_timeout_secs`, `[personal_backends]`) | `gateway.admin` |

Users' own pages (no permission needed, just a session): `/ui` (dashboard),
`/ui/tools`, `/ui/toolsets`, `/ui/catalog`, `/ui/tokens`,
`/ui/me/apps` (connected apps), `/ui/me/backends`, `/ui/me/usage`.

## Config API (`/api/v1/admin/config/...`)

| Endpoint | Methods | Needs |
| --- | --- | --- |
| `/api/v1/admin/config/backends` | GET, POST | read `backends.view`/`backends.manage`; write `backends.manage` |
| `/api/v1/admin/config/backends/{name}` | GET, PUT, DELETE | as above |
| `/api/v1/admin/config/toolsets` | GET, POST | as the backends |
| `/api/v1/admin/config/toolsets/{name}` | GET, PUT, DELETE | as the backends |
| `/api/v1/admin/config/oidc-providers` | GET, POST | `gateway.admin` |
| `/api/v1/admin/config/oidc-providers/{id}` | GET, PUT, DELETE | `gateway.admin` |
| `/api/v1/admin/config/settings` | GET, PUT | `gateway.admin` |

Bodies use the TOML key names (`url`, `transport`, `enabled`, `headers`,
`oauth`, ...; `issuer`, `client_id`, `scopes`, `admin_groups`, ...;
`rate_limit_per_minute`, `allowed_hosts`, `idle_timeout_secs`,
`personal_backends`). Every write is validated against the whole configuration
before it is stored (a 400 carries the first problem) and audited in its
transaction (`backend.create|update|delete`, `toolset.*`,
`oidc_provider.*`, `settings.update`).

**Secrets are write-only**: responses carry only `auth_token_set`,
`oauth_client_secret_set`, `client_secret_set` and, for header/env maps, the
key names. On `PUT` a missing or `null` secret field keeps the stored value,
`""` clears it, anything else sets it. Changing where a backend or provider
connects (transport, URL, command, passthrough provider, OIDC issuer) is
refused unless its stored secrets are re-entered or cleared in the same
request.

A stdio backend can only be saved while the gateway runs with
`AXON_ALLOW_STDIO=true` (otherwise 400).

## How changes reach the replicas

Every accepted write fires a `config` notification (`NOTIFY axon_changes`);
every replica reloads from the database within seconds and restarts the
backends whose configuration changed. A 30-second poll of the stored config
version is the backstop. There is no file watcher and no "reload" button in
database mode. Two things need a restart: the `AXON_*` environment and the
`personal_backends` settings.

## RBAC/SCIM/personal API

The full endpoint tables are in the README (RBAC, SCIM provisioning, Personal
MCP servers). The ones you will reach for most:

- `/api/v1/groups*`, `/api/v1/grants*`, `/api/v1/role-bindings*` — RBAC writes
  (`groups.manage` / `roles.manage`, see the RBAC reference).
- `/api/v1/users`, `PATCH /api/v1/users/{id}` `{"disabled": true|false}` —
  `users.manage`.
- `/api/v1/service-accounts*` — `service_accounts.manage`; token creation
  answers 201 with `plaintext` once.
- `/api/v1/admin/scim` (list) and `/api/v1/admin/scim/{provider}/token`
  (POST/DELETE) — SCIM tokens; the SCIM base URL for the IdP is
  `<base_url>/scim/v2/<provider id>`.
- `/api/v1/catalog`, `/api/v1/me/backends`, `/api/v1/me/credentials`,
  `/api/v1/me/connections` — catalog and personal servers.

All of these need the dashboard session cookie and, for writes, the
`X-CSRF-Token` header from the session; they answer 404 outside database mode.
