---
name: axon-prod-setup
license: MIT
description: Deploy and operate axon-gateway in production: first-run bootstrap (database, KEK, base URL), IdP/OIDC registration, RBAC (groups, roles, grants), backends, importing a config.toml, connecting MCP clients, verification, day-2 admin and troubleshooting. Use when the user wants to deploy, install, set up or operate axon or axon-gateway (container image, Helm chart, Compose, NixOS), connect Claude Code or another MCP client to axon, or hits a login loop, "no tools showing", redirect_uri errors or a missing admin role.
---

# axon-gateway setup for operators

You are helping an operator deploy and run axon-gateway, mostly in database
mode (the multi-user mode with OIDC and RBAC). The references hold the
details; this body holds the order of operations.

## Source of truth

You may not have the source tree, and that is fine. The truth is the README of
the version that runs: <https://github.com/Mozart409/axon-gateway/blob/main/README.md>
(check the image tag against it), plus `axon-gateway admin --help` where the
binary is available (for the container:
`docker run --rm ghcr.io/mozart409/axon-gateway admin --help`). If the source
happens to be checked out, it may be read too. When this skill and the README
disagree, the README of the running version wins; say so to the user.

Threat model, for questions about why something is locked down:
<https://github.com/Mozart409/axon-gateway/blob/main/docs/threat-model.md>.

References (read as needed): [bootstrap](references/bootstrap.md) for the
environment, containers, first start and KEK rotation; [rbac](references/rbac.md)
for roles, the 12 permissions, grants and mappings; [config-import](references/config-import.md)
for `admin import-config`; [admin-ui](references/admin-ui.md) for every page and
API route with its permission; [troubleshooting](references/troubleshooting.md)
for symptom, cause, fix (check it first when something fails).

## 0. Discover before acting

Ask the operator once, in a single batch, and record the answers:

- Deployment target: Compose/Podman, Kubernetes (Helm chart
  `deploy/helm/axon-gateway` in the repo), NixOS, or a bare binary. The image
  is `ghcr.io/mozart409/axon-gateway`; pin a version tag, not `latest`.
- Mode: **standalone** (one `config.toml`, no database, one person or static
  tokens) or **database mode** (`AXON_DATABASE_URL`: multi-user, RBAC, OIDC,
  catalog, personal servers; the main path here). Recommend standalone only
  for a single person with no SSO need.
- Public URL, and whether TLS terminates in a reverse proxy in front.
- The IdP (Pocket ID, Entra ID, Keycloak, Authentik, other) and who can change
  its app registration.
- An existing `config.toml` to import.
- The MCP backends to aggregate: URL, transport (http/sse/stdio), and auth
  (none, static bearer, per-user header, OAuth, identity passthrough).
- Which MCP clients will connect: Claude Code, Claude Desktop, editors,
  scripts/CI.

## 1. First-run bootstrap

Database mode is chosen by `AXON_DATABASE_URL` being set. The gateway then
reads **no config file**: a file argument or `AXON_GATEWAY_CONFIG` is an
error. Migrations run at startup.

1. Provision Postgres and set `AXON_DATABASE_URL`.
2. Set `AXON_KEK_FILE` (a file) or `AXON_KEK` (the text); generate it with
   `pwgen -s 48 1` or an equivalent (at least 32 random characters). The
   gateway refuses to start without one, and whoever holds it and the database
   holds every stored secret.
3. Set `AXON_BASE_URL` to exactly the URL users type in the browser, over
   HTTPS, no path prefix. It drives OIDC redirects, session cookies and OAuth
   metadata. The session cookies are always `Secure`, so plain `http://` works
   only on `localhost`; anywhere else the login loops back to the login page.
4. Set `AXON_BIND` if the default `0.0.0.0:8080` is wrong.
5. Register the app at the IdP (section 2), then set the bootstrap provider
   with `AXON_OIDC_*` (issuer, client id, optional secret file,
   `AXON_OIDC_ADMIN_GROUPS`). More providers are added later in the UI.
6. Start the gateway. Members of the admin groups are admins. Without any
   provider the only way in is the break-glass link (`axon-gateway admin
   login-link`, same environment; see the bootstrap reference).

**Proxy rule.** Serve the gateway at the root of its own HTTPS host. Do not put
it behind anything that rewrites `Origin` or `Host`, serves it under a path
prefix, or terminates TLS and forwards plain HTTP without passing the original
host and scheme. Do not "fix" CSRF, CSP or cross-site (403) errors by loosening
the proxy or adding CORS headers; fix `AXON_BASE_URL` so it equals the public
URL.

## 2. IdP side checklist

The OIDC providers page (`/ui/admin/config/oidc-providers`) shows "Values for
your identity provider" with copy buttons. Before the UI is reachable, hand
this list to whoever owns the IdP:

- **Redirect URI:** `{base_url}/auth/callback`, one for all providers.
- **Post-logout redirect URI:** `{base_url}/`.
- **Upstream OAuth callback** (only for catalog backends with
  `credential_mode = "oauth"`): `{base_url}/oauth/upstream/callback`. Its
  client metadata document is `{base_url}/oauth/upstream/client.json`.
- **Scopes:** `openid,profile,email` by default; add `groups` for Pocket ID.
  Entra: a groups claim (object ids) or app roles with `groups_claim =
  "roles"`.
- **The issuer string is part of every user's identity.** Users are unique on
  `(issuer, subject)`. Pick the canonical issuer URL once. Changing its
  spelling (`localhost` vs `127.0.0.1`, a trailing slash) creates a second,
  empty user for everyone; tokens, personal servers and memberships stay with
  the old one. The Users page flags the result as "duplicate".

## 3. Follow the setup checklist

After the first admin login, the Overview (`/ui`) shows gateway admins a "Set
up the gateway" checklist until all five steps are done:

1. a sign-in provider,
2. an admin group,
3. the first backend,
4. the first grant,
5. a connected client.

Use it as the progress view and tell the operator which item is open. The
order below matches it.

## 4. Configure RBAC first, backends second

Access is groups, grants, roles. The order that works:

1. Create groups (name `[a-z0-9_-]+`) and bind their IdP claim mappings
   (`{ provider, value }`; the value must match what the IdP puts in the
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
per backend for the built-in group `authenticated` on `/ui/admin#grants`. "My
tools" shows an admin without a grant "No grant yet" with an "Add a grant"
link to that place.

Admin rights from `admin_groups` are decided at login from the IdP claim. They
show as the `admin` badge in the header, as "admin - from your identity
provider" under "Your groups" on "My tools", and, under the `admin` role on
the Roles page, as the providers' admin groups.

The IdP must actually send the groups claim (Pocket ID needs the `groups`
scope; Entra needs a groups claim or app roles, and omits it past about 200
groups: use `graph_overage` or SCIM). SCIM can push users and groups so they
exist before the first login.

## 5. Backends

Add them on `/ui/admin/config/backends`. The form edits every credential mode:
shared, per user, OAuth (with an optional static client) and identity
passthrough, plus transport, URL, allowed tools, timeouts, health check,
breaker and idle timeout. The table has a Mode column. stdio needs
`AXON_ALLOW_STDIO=true` at startup. Per-user, OAuth and passthrough backends
become catalog entries; each user connects them on `/ui/catalog`. Tool names
are namespaced `<backend>_<tool>` (README "How Tool Namespacing Works").
Automation can use `PUT /api/v1/admin/config/backends/{name}` or
`admin import-config`.

## 6. Import an existing config file (if there is one)

`axon-gateway admin import-config <file> [--dry-run] [--no-tokens]` writes a
standalone `config.toml` into the database in one transaction. Run it with the
same environment (database URL and KEK) as the gateway, with the file's
`${VAR}` secrets set. `--dry-run` reports and writes nothing; `--no-tokens`
creates service accounts without minting tokens (the Helm import Job always
does this). Afterwards start the gateway **without** the file. Details and a
worked example: [references/config-import.md](references/config-import.md).

## 7. Connect clients

The MCP endpoint is `{base_url}/mcp` (shown with a copy button on `/` and on
the Overview).

- **Interactive clients** (Claude Code, Claude Desktop, editors) use MCP OAuth:
  add the URL. The client discovers it from the 401 `WWW-Authenticate` and
  `/.well-known/oauth-protected-resource`, registers itself, and the user
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

opencode and other clients: use their remote (streamable HTTP) MCP server
setting with the same URL; the client must support MCP OAuth or a static
header.

## 8. Verify before reporting done

1. `curl -fsS {base_url}/health` and `curl -fsS {base_url}/readyz` (database
   mode: 503 when the database does not answer within 2 s).
2. Log in: the header shows the user, and the `admin` badge for admins.
3. The Overview shows a card per shared backend with state and tool count. It
   proves the backend is up, not that anyone may use it; catalog entries
   appear on `/ui/catalog` instead.
4. "My tools" (`/ui/tools`) lists the backend with its tools, not "No grant
   yet". This is the check for grants.
5. From a client: `claude mcp list` reports the server as connected and `/mcp`
   inside Claude Code lists its tools as `<backend>_<tool>`. After a first
   call, check `/ui/admin/tool-calls`.
6. The setup checklist on the Overview is complete.

## 9. Day-2 operation

Admins manage everything at `/ui/admin` (roles, users, groups, service
accounts, SCIM, personal backends, audit, tool calls, usage, audit settings,
and the config tabs backends, "Gateway toolsets", OIDC providers, settings)
or through `/api/v1/...` with the session cookie and `X-CSRF-Token`. Every
write is validated against the whole configuration before it is stored and
audited. Config changes reach every replica within seconds; only the `AXON_*`
environment and the `[personal_backends]` settings need a restart.

Tell the operator which permission a page needs before sending them there; the
mapping is in [references/admin-ui.md](references/admin-ui.md). A page they
cannot see is usually a missing role binding, not a bug.

Upgrades: read the release notes (`CHANGELOG.md` in the repo), bump the image
tag, restart; migrations run at startup. Back up the database and the KEK
together; a database without its KEK cannot unseal stored secrets.

## Reporting

When the task ends, state exactly what was created or changed (groups, grants,
bindings, accounts), the permissions involved, and anything that still needs a
human (IdP-side claim configuration, secret distribution, token rotation
dates).

Sources: README sections "Quick Start", "Authentication", "RBAC", "SCIM
provisioning", "Personal MCP servers", "Gateway Settings".
