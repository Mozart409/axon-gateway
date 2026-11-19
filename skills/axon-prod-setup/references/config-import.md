# `admin import-config` and the TOML surface

Source: README (sections "Configuration", "Authentication", "RBAC") and
`axon-gateway admin import-config --help`. The same TOML is what a standalone gateway reads, minus the sections a
standalone file refuses (`[database]`, `[[auth.oidc]]`, `[rbac]`, per-user
backends).

## The command

```sh
axon-gateway admin import-config <file> [--dry-run] [--no-tokens]
# flags in any order; the file path is required
```

- Runs with the **same environment as the gateway**: `AXON_DATABASE_URL` and
  the KEK (`AXON_KEK_FILE`/`AXON_KEK`). The file's `${VAR}` placeholders, the
  `.env` next to it and `client_secret_env` references must resolve where you
  run it.
- One transaction; the file wins: creates what is missing, updates what
  differs, removes nothing.
- `--dry-run` rolls the transaction back and only reports.
- `--no-tokens` creates the service accounts without minting tokens (the Helm
  import Job always runs this way, so no token reaches a pod log); each created
  account is named on stderr.
- **stdout carries only new tokens**, one per line, `name<TAB>axon_pat_...`,
  shown once and never again — capture it. New tokens expire after the
  service-token lifetime (365 days); plan rotation.
- Every `[[tokens]]` entry becomes a service account; its
  `allowed_tools`/`allowed_backends` are **not** carried over — what it may
  call comes from its groups after the import.
- Not imported (environment-only, warned about): `[gateway]` `bind`,
  `base_url`, `auth_token`, `allow_stdio`; `[database]`. Set `AXON_BIND`,
  `AXON_BASE_URL`, `AXON_ALLOW_STDIO`, `AXON_DATABASE_URL` instead.
- A real run records one `config.import` audit entry with the counts.
- Imported: gateway settings (`rate_limit_per_minute`, `allowed_hosts`,
  `idle_timeout_secs`), `[personal_backends]`, `[[backends]]` with secrets,
  `[[toolsets]]`, `[[auth.oidc]]` providers, and the `[rbac]` parts: groups
  with IdP mappings and `service_accounts`, grants, custom roles, role
  bindings.

## Complete worked example

A file that brings up backends, providers and RBAC in one import:

```toml
# [gateway] is optional here; bind/base_url/allow_stdio are environment
# variables in database mode. rate_limit_per_minute, allowed_hosts and
# idle_timeout_secs are imported as stored settings.
[gateway]
rate_limit_per_minute = 100
allowed_hosts = ["axon.example.com"]
idle_timeout_secs = 300

# Shared backends: one connection each, with the backend's own credentials.
[[backends]]
name = "files"
url = "https://files.example.com/mcp"
transport = "http"
enabled = true
auth_token = "${FILES_TOKEN}"          # resolved at import, sealed with the KEK

[[backends]]
name = "reports"
url = "https://reports.example.com/mcp"
transport = "http"
enabled = true
credential_mode = "per_user"           # a catalog entry; users bring a value
[[backends.credential_fields]]
name = "api_token"
label = "API token"
header = "Authorization"
prefix = "Bearer "

# Gateway toolsets: endpoint prefixes, /mcp/toolset/{name}.
[[toolsets]]
name = "readonly"
tools = ["*_read", "*_list", "*_get"]
description = "Read-only operations"

# Dashboard-login providers. Register {base_url}/auth/callback as the
# redirect URI. The client secret is resolved and sealed at import.
[[auth.oidc]]
id = "pocket"
display_name = "Pocket ID"
issuer = "https://id.example.com"
client_id = "axon"
client_secret_env = "AXON_OIDC_POCKET_SECRET"
scopes = ["openid", "profile", "email", "groups"]
admin_groups = ["axon-admins"]

# RBAC: groups with IdP claim mappings, grants, custom roles, bindings.
[[rbac.groups]]
name = "it"
description = "IT staff"
idp = [{ provider = "pocket", value = "it-staff" }]
service_accounts = ["backup-agent"]    # account created if missing, then member

[[rbac.groups]]
name = "helpdesk"

[[rbac.roles]]
name = "log-reader"
description = "Read audit and usage"
permissions = ["audit.read", "backends.view"]

[[rbac.grants]]
group = "it"
backend = "files"
include = ["*"]
exclude = ["delete_*"]

[[rbac.grants]]
group = "authenticated"                # everyone logged in
backend = "reports"
read_only = true

[[rbac.role_bindings]]
role = "auditor"
group = "helpdesk"

[[rbac.role_bindings]]
role = "log-reader"
group = "it"
```

Validation is strict: group names `[a-z0-9_-]+` (1–64 chars), role names not a
built-in name, at least one permission per custom role, grants must name a
declared group or `authenticated` and a declared backend, mappings a declared
provider. The import fails (nothing written) on a name that violates these or
a binding to an unknown role.

## Related admin commands

| Command | Does |
| --- | --- |
| `admin login-link` | Break-glass: prints a one-time, 15-minute URL that starts a one-hour admin session (needs `AXON_DATABASE_URL`, `AXON_BASE_URL`) |
| `admin rewrap-secrets` | Re-wraps every sealed secret under the first KEK line, during a key rotation |
| `admin import-config` | The import above |

All three take no config file — they read the database mode environment.
