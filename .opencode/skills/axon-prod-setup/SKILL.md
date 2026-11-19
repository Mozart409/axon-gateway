---
name: axon-prod-setup
license: MIT
description: Set up and configure axon-gateway end to end — discover the user's situation, first-run bootstrap, IdP registration, RBAC (groups, roles, permissions, IdP claim mappings), backends, `admin import-config`, connecting MCP clients, verification, troubleshooting. Use whenever the user wants to set up, install or get started with axon, deploy axon, connect Claude Code or another MCP client to axon, configure permissions/groups/toolsets/backends/tokens/service accounts/SCIM/audit, or hits a login loop, "no tools showing", or other production problems, even if they don't say "production".
---

# axon-gateway setup

You are helping someone set up axon-gateway, mostly in database mode (the
multi-user mode with RBAC). Work from the real files in this repo; the
references hold the details, this body holds the order of operations. Verify
every claim against the source before repeating it: `src/bootstrap.rs`,
`src/import.rs`, `src/policy.rs`, `src/config.rs` and `README.md` are the truth.

Read before acting:

- [references/bootstrap.md](references/bootstrap.md) — the environment
  variables of database mode, the Compose/Kubernetes shape, first start,
  break-glass login, KEK and secret rotation.
- [references/rbac.md](references/rbac.md) — the permission model: built-in
  roles, all 12 permissions, grants, IdP mappings, role bindings, and who may
  hand out what.
- [references/config-import.md](references/config-import.md) — the TOML surface
  `admin import-config` reads, a complete worked example, flags and behaviour.
- [references/admin-ui.md](references/admin-ui.md) — every admin page and API
  route, with the permission each needs, plus UI gotchas to tell users. Use it
  to answer "where do I click / which endpoint?".
- [references/troubleshooting.md](references/troubleshooting.md) — symptom,
  cause, fix. Check it first when something does not work.

## 0. Discover before acting

Ask the user once, in a single batch, and record the answers:

- Deployment target: Docker/Podman Compose, Kubernetes (Helm chart
  `deploy/helm/axon-gateway`), NixOS, or a bare binary.
- Mode: **standalone** (one `config.toml`, no database, one person or static
  tokens; README "Quick Start", "Authentication") or **database mode**
  (`AXON_DATABASE_URL`: multi-user, RBAC, OIDC, catalog, personal servers; the
  main path of this skill). Recommend standalone only for a single person with
  no SSO need; otherwise database mode.
- Public URL, and whether TLS terminates in front (a reverse proxy).
- The IdP (Pocket ID, Entra ID, Keycloak, Authentik, other) and who can change
  its app registration.
- An existing `config.toml` to import.
- The MCP backends to aggregate: URL, transport (http/sse/stdio), and auth
  (none, static bearer, per-user header, OAuth, identity passthrough).
- Which MCP clients will connect: Claude Code, Claude Desktop, editors,
  scripts/CI.

## 1. First-run bootstrap

Database mode is chosen by `AXON_DATABASE_URL` being set. The gateway then
reads **no config file** — a file argument or `AXON_GATEWAY_CONFIG` is an error.
Migrations run at startup.

1. Provision Postgres and set `AXON_DATABASE_URL`.
2. Set `AXON_KEK_FILE` (a file) or `AXON_KEK` (the text); generate it with
   `pwgen -s 48 1` (at least 32 characters). The gateway refuses to start
   without one, and whoever holds it and the database holds every secret —
   treat it accordingly. Generate every other secret with `pwgen -s 48 1` too.
3. Set `AXON_BASE_URL` to exactly the URL users type in the browser, over
   HTTPS. It drives OIDC redirects, session cookies and OAuth metadata. The
   session cookies (`__Host-axon_session`, `__Host-axon_login`) are always
   `Secure` (`src/server/session.rs`), so plain `http://` works only on
   `localhost`; anywhere else the login loops back to the login page.
4. Set `AXON_BIND` if the default `0.0.0.0:8080` is wrong.
5. Configure the bootstrap OIDC provider with `AXON_OIDC_*` (issuer, client id,
   optional secret file, `AXON_OIDC_ADMIN_GROUPS`) after doing section 2.
6. Start the gateway. Members of the admin groups are admins; without any
   provider, the only way in is the break-glass link (`axon-gateway admin
   login-link`, same environment — see the bootstrap reference).

Do not weaken the security posture while "fixing" access problems: the CSRF
middleware (`reject_cross_site_middleware` + `require_csrf`), the strict CSP
and the missing CORS layer are deliberate — see `docs/threat-model.md`. There
is no `CorsLayer::permissive()` and none should be added.

## 2. IdP side checklist

Values to register at the provider (hand this list to whoever owns it):

- **Redirect URI:** `{base_url}/auth/callback`, one for all providers.
- **Post-logout redirect URI:** `{base_url}/`.
- **Scopes:** `openid,profile,email` by default; add `groups` for Pocket ID.
  Entra: a groups claim (object ids) or app roles with `groups_claim =
  "roles"`.
- **The issuer string is part of every user's identity.** Users are unique on
  `(issuer, subject)` (`migrations/0001_users.sql`). Pick the canonical issuer
  URL once. Changing its spelling (`localhost` vs `127.0.0.1`, a trailing
  slash) creates a second, empty user for everyone; tokens, personal servers
  and memberships stay with the old one. The symptom: `/ui/admin/users` lists
  the same email twice, with two issuer spellings.
- **Catalog backends with `credential_mode = "oauth"`:** the upstream callback
  is `{base_url}/oauth/upstream/callback`, the client metadata document
  `{base_url}/oauth/upstream/client.json`.

## 3. Configure RBAC first, backends second

Access is groups → grants → roles. The order that works:

1. Create groups (name `[a-z0-9_-]+`), bind their IdP claim mappings
   (`{ provider, value }` — the value must match what the IdP puts in the
   claim; for Entra that is the group object id).
2. Add tool grants per group (`backend`, optional `include`/`exclude` globs
   over original tool names, `read_only`, `mandatory`).
3. Bind roles. Everyone is `member`; admins come from `admin_groups`; four
   built-in roles (`admin`, `backend-admin`, `auditor`, `member`) exist and
   custom roles are made of the 12 permissions in the RBAC reference.
4. Create service accounts for agents/scripts (no login), add them to groups,
   issue their tokens.

**Admins need grants too.** `admin` holds every permission, but a grant is
still needed before a backend's tools appear for them. Quick start: one grant
per backend for the built-in group `authenticated` on `/ui/admin` → Grants.

Admin rights from `admin_groups` are decided at login from the IdP claim. They
show as the `admin` badge in the header and the ADMIN column on
`/ui/admin/users`, but not as a role binding (the `admin` row on
`/ui/admin/roles` shows Bindings 0) and not under "Your groups" on `/ui/tools`.
That is expected, not a bug.

The IdP must actually send the groups claim (Pocket ID needs the `groups`
scope; Entra needs a groups claim or app roles, and omits it past ~200 groups —
`graph_overage` or SCIM are the answers). SCIM can push users and groups so
they exist before the first login.

## 4. Backends

Add them on `/ui/admin/config/backends` (name, transport, URL, allowed tools,
timeouts, health check, breaker, idle timeout, bearer token, headers). stdio
needs `AXON_ALLOW_STDIO=true` at startup. Per-user, OAuth and passthrough
backends, and the OAuth client, cannot be fully edited in the form: use
`PUT /api/v1/admin/config/backends/{name}` or `admin import-config`. Those
backends become catalog entries; each user connects on `/ui/catalog`. Tool
names are namespaced `<backend>_<tool>` (README "How Tool Namespacing Works").

## 5. Import an existing config file (if there is one)

`axon-gateway admin import-config <file> [--dry-run] [--no-tokens]` writes a
standalone `config.toml` into the database in one transaction — run it with the
same environment (database URL + KEK) as the gateway, with the file's `${VAR}`
secrets set. `--dry-run` reports and writes nothing; `--no-tokens` creates the
service accounts without minting tokens (the Helm import Job always runs this
way). After the import, start the gateway **without** the file. Full TOML
surface and worked example: [references/config-import.md](references/config-import.md).

## 6. Connect clients

The MCP endpoint is `{base_url}/mcp` (shown with a copy button on `/` and on
the Overview `/ui`).

- **Interactive clients** (Claude Code, Claude Desktop, editors) use MCP OAuth:
  add the URL. The client discovers it from the 401 `WWW-Authenticate` →
  `/.well-known/oauth-protected-resource`, registers itself (DCR), and the user
  approves on the consent page. Grants are listed and revoked on `/ui/me/apps`.
- **Scripts/CI** send `Authorization: Bearer <token>`: a personal access token
  from `/ui/tokens` (default 30 days, max 90; suspended after 90 days without
  a dashboard login) or a service account token from
  `/ui/admin/service-accounts` (default 30, max 365 days).
- A toolset narrows a client to `{base_url}/mcp/toolset/<name>`.

```sh
claude mcp add --transport http axon https://axon.example.com/mcp
claude mcp add --transport http axon https://axon.example.com/mcp \
  --header "Authorization: Bearer axon_pat_..."
```

## 7. Verify (before reporting done)

1. `curl -fsS {base_url}/health` and `curl -fsS {base_url}/readyz` (database
   mode: 503 when the database does not answer within 2 s).
2. Log in: the header shows the user, and the `admin` badge for admins.
3. `/ui` Overview shows a card per shared backend with its state and tool
   count. It lists backends whether or not the viewer has a grant, and
   catalog entries (OAuth, passthrough, per-user) appear on `/ui/catalog`
   instead, so it proves the backend is up, not that anyone can use it.
4. `/ui/tools` lists the backend with its tools, not "No access — ask an
   admin". This is the check for grants.
5. From a client: `claude mcp list` should report the server as connected,
   and `/mcp` inside Claude Code lists its tools as `<backend>_<tool>`
   (initialize plus `tools/list` over streamable HTTP is awkward with curl).
   After a first call, check `/ui/admin/tool-calls`.

## 8. Day-2 configuration

Admins manage everything at `/ui/admin` (pages: roles, users, groups,
service accounts, SCIM, personal backends, audit, tool-calls, usage,
audit-settings, and the config tabs backends/toolsets/oidc-providers/settings)
or through `/api/v1/...` with the session cookie and `X-CSRF-Token`. Every
write is validated against the whole configuration before it is stored and
audited in its transaction. Config changes fan out to every replica within
seconds (database `NOTIFY`, 30 s poll as backstop); only the `AXON_*`
environment and the `[personal_backends]` settings need a restart.

Tell the user which permission each page needs before sending them there —
the mapping is in [references/admin-ui.md](references/admin-ui.md). A page
they cannot see is usually a missing role binding, not a bug.

## 9. Troubleshooting

Symptom table: [references/troubleshooting.md](references/troubleshooting.md).

## Reporting

When the task ends, state exactly what was created or changed (groups, grants,
bindings, accounts), the permissions involved, and anything that still needs a
human (IdP-side claim configuration, secret distribution, token rotation dates).
