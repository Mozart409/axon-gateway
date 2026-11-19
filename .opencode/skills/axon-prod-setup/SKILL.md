---
name: axon-prod-setup
license: MIT
description: Set up and configure a production axon-gateway — first-run bootstrap, `admin import-config`, RBAC (groups, roles, permissions, IdP claim mappings), toolsets, backends, tokens, service accounts, SCIM, audit. Use whenever the user mentions deploying axon, configuring permissions/groups/toolsets, or production setup/troubleshooting, even if they don't say "production".
---

# axon-gateway production setup

You are helping someone run axon-gateway in production (database mode — the
multi-user mode with RBAC). Work from the real files in this repo; the
references hold the details, this body holds the order of operations. Verify
every claim against the source before repeating it: `src/bootstrap.rs`,
`src/import.rs`, `src/policy.rs`, `src/config.rs` and `README.md` are the truth.

## 0. Read before acting

- [references/bootstrap.md](references/bootstrap.md) — the environment
  variables of database mode, the Compose/Kubernetes shape, first start,
  break-glass login, KEK and secret rotation.
- [references/rbac.md](references/rbac.md) — the permission model: built-in
  roles, all 12 permissions, grants, IdP mappings, role bindings, and who may
  hand out what.
- [references/config-import.md](references/config-import.md) — the TOML surface
  `admin import-config` reads, a complete worked example, flags and behaviour.
- [references/admin-ui.md](references/admin-ui.md) — every admin page and API
  route, with the permission each needs. Use it to answer "where do I click /
  which endpoint?".

## 1. First-run bootstrap

Database mode is chosen by `AXON_DATABASE_URL` being set. The gateway then
reads **no config file** — a file argument or `AXON_GATEWAY_CONFIG` is an error.
Migrations run at startup.

1. Provision Postgres and set `AXON_DATABASE_URL`.
2. Set `AXON_KEK_FILE` (a file) or `AXON_KEK` (the text); generate it with
   `pwgen -s 48 1` (at least 32 characters). The gateway refuses to start
   without one, and whoever holds it and the database holds every secret —
   treat it accordingly.
3. Set `AXON_BASE_URL` to the public URL (it drives OIDC redirects, session
   cookies and OAuth metadata; the `__Host-` session cookie requires HTTPS).
4. Set `AXON_BIND` if the default `0.0.0.0:8080` is wrong.
5. Configure the bootstrap OIDC provider with `AXON_OIDC_*` (issuer, client id,
   optional secret file, `AXON_OIDC_ADMIN_GROUPS`). Register
   `{base_url}/auth/callback` as the redirect URI at the provider.
6. Start the gateway. Members of the admin groups are admins; without any
   provider, the only way in is the break-glass link (`axon-gateway admin
   login-link`, same environment — see the bootstrap reference).

Do not weaken the security posture while "fixing" access problems: the CSRF
middleware (`reject_cross_site_middleware` + `require_csrf`), the strict CSP
and the missing CORS layer are deliberate — see `docs/threat-model.md`. There
is no `CorsLayer::permissive()` and none should be added.

## 2. Configure RBAC first, backends second

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

The identity provider must actually send the groups claim (Pocket ID needs the
`groups` scope; Entra needs a groups claim or app roles, and omits it past ~200
groups — `graph_overage` or SCIM are the answers). SCIM provisioning can push
users and groups so they exist before the first login.

## 3. Import an existing config file (if there is one)

`axon-gateway admin import-config <file> [--dry-run] [--no-tokens]` writes a
standalone `config.toml` into the database in one transaction — run it with the
same environment (database URL + KEK) as the gateway, with the file's `${VAR}`
secrets set. `--dry-run` reports and writes nothing; `--no-tokens` creates the
service accounts without minting tokens (the Helm import Job always runs this
way). After the import, start the gateway **without** the file. Full TOML
surface and worked example: [references/config-import.md](references/config-import.md).

## 4. Day-2 configuration

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

## Reporting

When the task ends, state exactly what was created or changed (groups, grants,
bindings, accounts), the permissions involved, and anything that still needs a
human (IdP-side claim configuration, secret distribution, token rotation dates).
