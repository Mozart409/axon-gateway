# RBAC: groups, roles, permissions

Source: `src/policy.rs` (`Permission`, `Role`), `src/rbac.rs` (the admin
service behind `/api/v1` and the admin pages), `README.md` section "RBAC".

## The model

- A user is in the built-in group `authenticated` (everyone logged in), in
  every group whose IdP mapping matches one of their claim values at the login
  provider, and in every group they were added to by hand. Service accounts
  have only their explicit memberships (no `authenticated`).
- A **grant** lets a group use a backend's tools: globs over the *original*
  tool name (`include`, default `["*"]`; `exclude` removes from `include`),
  optional `read_only` (only tools with `readOnlyHint: true` pass) and
  `mandatory` (users cannot hide these on "My tools").
- A **role** is a named set of permissions; a **role binding** gives it to a
  group or a single user. Users the provider marks in `admin_groups` are
  `admin` (everything); everyone else is at least `member`.

## Built-in roles (fixed, read-only)

| Role | Permissions |
| --- | --- |
| `admin` | every permission |
| `backend-admin` | `backends.view`, `backends.manage`, `catalog.manage` |
| `auditor` | `audit.read`, `backends.view` |
| `member` | `personal_backends.create` |

## All permissions (`Permission::ALL`, `as_str()` names)

| Permission | Allows |
| --- | --- |
| `gateway.admin` | Gateway settings, OIDC providers, break-glass operations |
| `backends.view` | See shared backends and their status |
| `backends.manage` | Create, edit and disable shared backends and gateway toolsets |
| `catalog.manage` | Publish and edit catalog templates |
| `personal_backends.create` | Add personal MCP servers |
| `users.manage` | Disable users, assign roles, see users |
| `groups.manage` | Groups, IdP mappings, memberships and grants |
| `roles.manage` | Custom roles |
| `service_accounts.manage` | Service accounts and their tokens |
| `tokens.manage_all` | List and revoke any user's tokens |
| `audit.read` | Audit log and usage views (metadata only) |
| `audit.read_sensitive` | Read recorded tool arguments (audited as `audit.arguments_read`) |

Custom roles need at least one permission and a name matching
`[a-z0-9][a-z0-9_-]{0,62}` that is not a built-in role name.

## IdP claim mappings

A mapping is `{ provider, value }`: `provider` is the id of a configured OIDC
provider, `value` a claim value that puts the holder in the group. Entra sends
group **object ids**, so mappings and `admin_groups` use object ids there (or
app roles with `groups_claim = "roles"`). With SCIM, both the group's
`externalId` and its `displayName` count as claim values.

## Who may hand out what

No one can delegate more than they hold:

- Creating or editing a role needs `roles.manage` **and every permission the
  role carries**.
- Binding any role (built-in or custom) to a group or user needs
  `roles.manage` **and every permission of that role**; removing a binding
  needs only `roles.manage`.
- Adding an IdP mapping or a member to a group also requires every permission
  of the roles bound to that group.

An admin holds everything, so the rule only limits delegates.

## Where each thing is managed

| Task | API | Page |
| --- | --- | --- |
| Groups, mappings, members, grants | `/api/v1/groups*`, `/api/v1/grants*` | `/ui/admin/groups/{name}` (grants list on `/ui/admin`) |
| Custom roles, bindings | `/api/v1/admin/roles*`, `/api/v1/admin/permissions`, `/api/v1/role-bindings*` | `/ui/admin/roles` |
| Users (disable/enable) | `/api/v1/users*` | `/ui/admin/users` |
| Service accounts, their tokens | `/api/v1/service-accounts*` | `/ui/admin/service-accounts` |
| Any user's tokens | — | `/ui/tokens` pages / token API |

Reads of roles need `groups.manage`, `roles.manage` or `audit.read`; writes
need the permission named above. All `/api/v1` routes need a dashboard session
cookie, and writes need its `X-CSRF-Token` header; outside database mode they
answer 404. Every change is audited in the same transaction.

A deleted custom role's bindings grant nothing; `DELETE /api/v1/admin/roles/{name}`
answers 409 while bindings remain unless `?force=true` is passed.
