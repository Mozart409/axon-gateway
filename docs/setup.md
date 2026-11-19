# Setting up axon-gateway

This walkthrough stands up a development environment for the gateway: what to
install, what `just axon-dev` starts, which ports the dev stack owns, and which
gates a change has to pass. It complements the [README](../README.md) (features,
runtime configuration and API) and [AGENTS.md](../AGENTS.md) (code style and the
full rule list — read it, this page does not restate it). The security
reasoning behind the defaults is in [threat-model.md](threat-model.md).

Where commands run from: in the yggdrasil monorepo, `just` runs from the repo
root (each axon recipe carries its own `working-directory`, so
`just axon-dev` works from anywhere in the checkout). This project's own
`flake.nix` exists for the standalone GitHub export; in the monorepo the root
flake consumes it as a subflake and pins its inputs to the root lock.

## Prerequisites

Everything comes from Nix. direnv loads the dev shell in the checkout, so the
tools are simply on `PATH`; run `nix develop` in the checkout as the fallback.
The yggdrasil root dev shell has all of it: the Rust toolchain (fenix stable
from `flake.lock`, no version literal), `cargo`, `bacon`, `just`, `podman` and
`podman-compose` (the dev stack runs in Podman), `pg_isready`, `tailwindcss`
(v4), Node for the e2e suite, and `lychee` for the link check.

A standalone clone of the exported GitHub repo has its own smaller
`flake.nix` (toolchain, `bacon`, `tailwindcss_4`, `podman-compose`,
`cargo-audit`, `cargo-deny`, `cocogitto`). There, Podman and Node are host
packages, and the e2e suite installs its Chromium with
`npx playwright install --with-deps chromium`, as CI does.

## Dev stack

```bash
just axon-dev
```

is the whole thing. The recipe is `axon-up` followed by `bacon run-long`:

- `axon-up` runs `podman compose -f example/compose.local.yml up -d`, then
  waits up to 60 s for both services to answer: `pg_isready` on 127.0.0.1:5437
  and a `curl` of the mock provider's discovery document on 127.0.0.1:4011. If
  one does not come up, it prints the last 20 log lines of that container and
  exits non-zero.
- `bacon run-long` runs `cargo run` on the host (no container for the gateway)
  and restarts it on every change (`on_change_strategy = "kill_then_restart"`),
  so saving a file rebuilds and restarts the gateway. The environment of the
  job is the whole configuration — there is no dev config file and no seed
  script. From `bacon.toml`: `AXON_BIND=127.0.0.1:8080`,
  `AXON_BASE_URL=http://localhost:8080`,
  `AXON_DATABASE_URL=postgres://axon:axon-dev@127.0.0.1:5437/axon`, a dev-only
  KEK, `AXON_OIDC_ISSUER=http://127.0.0.1:4011/default` with client id
  `axon-dev`, admin group `axon-admins`, scopes
  `openid,profile,email,offline_access`, and `AXON_DEV_AUTO_CONSENT=1` so an
  MCP client completes the OAuth flow without a consent click.

The UI is at http://127.0.0.1:8080 (the dashboard at `/ui`). The mock OIDC
provider (navikt `mock-oauth2-server`) logs every sign-in in without a login
page as user `dev`, a member of `axon-admins` — and therefore an admin. Every
value is a public dev value; keep the stack on localhost. `just axon-down`
tears the compose stack down with its volumes, which resets the database.

## Ports

| Port | What |
| --- | --- |
| 8080 | The gateway (UI at `/ui`, MCP at `/mcp`, metrics at `/metrics`) |
| 5437 | Dev Postgres (`compose.local.yml`; it is 5432 inside the container) |
| 4011 | Mock OIDC provider |
| 3003 | Demo backend (`examples/oidc_backend.rs`), only when you start it |

Port collisions are a real concern in yggdrasil, where gates run in parallel:
the sibling projects' test databases take 5433 (lanternd), 5434
(internal-dashboard), 5435 (hofvarpnir tests), 5436 (countdown), and 5437 here.
Axon's own *test* database uses no host port at all — see
[Database-backed tests](#database-backed-tests).

## Demo backends

```bash
just axon-oidc-backend
```

runs `cargo run --example oidc_backend`, a demo MCP backend on 127.0.0.1:3003
that accepts only tokens the mock OIDC provider issued. It serves three MCP
endpoints: `/oauth/mcp`, `/passthrough/mcp`, and `/open/mcp` (no token). How to
register the first two in the dev database — and the egress-allow and grant
steps they need — is listed in the README under
["Demo backends"](../README.md#demo-backends); `/open/mcp` is registered as a
plain shared backend without credentials. The e2e suite needs this backend
running (it seeds `e2e-open` against `/open/mcp`).

## Gates

A change passes these before it is committed:

- **Formatting** — `cargo fmt`.
- **Lint** — `cargo clippy --all-targets --locked -- -D warnings`
  (same as `just axon-clippy`). Never add `-D clippy::pedantic` on the
  command line: the `[lints.clippy]` table in `Cargo.toml` enables pedantic and
  owns the per-lint allows, and a CLI flag would override them.
- **Tests** — `cargo test --locked`. The database-backed tests need Postgres,
  so run them as `just axon-with-db axon-test`: the recipe starts a throwaway
  tmpfs Postgres (`scripts/test-pg.sh`, unix socket only, no host port), runs
  the recipes, and stops it again — also on failure or Ctrl-C. A Postgres that
  is already up is used and left alone, and a second `-with-db` run waits for
  the first one (`flock` on a lock file), so nothing removes the database under
  a running test. A gate needs no running database and no host port.
- **Full gate** — `just axon-ci` = format check, clippy, the
  Docker-build-context type check (`axon-docker-context`), `cargo deny`,
  `cargo audit`, and the DB tests through `-with-db`. It matches
  `.github/workflows/ci.yml`.

Pre-commit (lefthook) runs `cargo fmt`, clippy and `typos`; pre-push runs the
tests. Commits are single-line conventional commits scoped by area
(`feat(axon)`, `fix(axon)`, `docs(axon)`), verified by `cog verify`.

## E2E suite

`e2e/` is a Playwright (TypeScript) property-test suite. It runs against a
live dev stack, so all of this must be up first:

```bash
just axon-dev            # compose stack + bacon run-long
just axon-oidc-backend   # demo backend on 127.0.0.1:3003
just axon-e2e            # from rust/axon-gateway/e2e in the root justfile
```

The `seed` setup step creates what the pages need through the admin API —
shared backend `e2e-open` on the demo backend's `/open/mcp`, toolset
`e2e-readers`, group `e2e-team` — idempotently, so re-running is fine. If the
seed cannot see the backend come up it names the missing
`just axon-oidc-backend`.

`E2E_RUNS` (default 4) and `E2E_SEED` tune the fast-check property runs —
`E2E_SEED=<seed>` reproduces a failure. Everything else on the command line
goes to `playwright test` (a filter like `just axon-e2e -- tests/a11y.spec.ts`
works). `AXON_E2E_BASE_URL` moves the target off `http://localhost:8080`.

The suite checks properties, not pages: no horizontal scroll, nothing rendered
outside the viewport, no overlapping blocks, navigation reachable, icons
resolvable, axe accessibility rules, a clean console, and the CSP intact — on
every page in `e2e/lib/routes.ts`, across fixed breakpoints and fast-check
generated viewports and themes. Locators select by role, label and attribute,
never by CSS class. **Coverage rule:** every UI page must be listed in
`e2e/lib/routes.ts`; a coverage test fails until a new page is added there.

The Node side comes from the dev shell, and `PLAYWRIGHT_BROWSERS_PATH` points
at `AXON_E2E_BROWSERS` from the root flake (nixpkgs' Playwright browser
revision); `@playwright/test` in `e2e/package.json` must stay at that version
or the browsers are not found. The recipe runs `npm ci` first if
`node_modules` is missing.

## Link checking

```bash
just axon-links
```

runs lychee over this project's markdown, examples, compose files, workflows
and the e2e library files, with `lychee.toml` as the configuration: plain mode
(no cache) and all private hosts excluded, because the docs deliberately link
to the dev stack on 127.0.0.1. Extra flags go straight to lychee
(`just axon-links -- -v`).

If `just` says lychee is missing after the flake gained it, reload direnv once
(`direnv reload` or open a new shell): the dev shell is cached per directory.

## CSS pipeline

The UI styles are Tailwind v4: `styles/input.css` is the source,
`styles/output.css` the compiled file the gateway serves; both are committed,
so a change to the templates must end with a recompiled `output.css` — lefthook
does not rebuild it. Two watchers exist:

- `just axon-css` — `tailwindcss -i styles/input.css -o styles/output.css --watch`.
- `bacon css-watch` — the same, plus `--minify`, watching `src/` and `styles/`.

Run one of them in a second terminal while working on the UI; both watch
`src/` and `styles/`, including `input.css` itself.

## For agents

The workflow rules for coding agents, beyond what [AGENTS.md](../AGENTS.md)
already fixes:

- **No direnv?** If the shell has not loaded the dev shell, run every tool as
  `nix develop <path-to-repo-root> -c <one simple command>` — one command per
  invocation, no compound lines.
- **Keep shell commands single and simple.** No chained `&&` command lines in
  one shell call; one command, its arguments, done.
- **Never run a bare `nix flake check`.** It evaluates every host in the
  monorepo and has been OOM-killed. If an evaluation is actually wanted,
  evaluate the specific attribute (`nix eval --raw .#<attr>.drvPath`) — and
  only when the task asks for it.
- **No automatic nix builds or evaluations.** `nix build`, `nix eval`,
  `colmena build`, deployment recipes: never unless the task says so. Format
  the changed files and stop there.
- **Push to Forgejo only.** The canonical repo lives on Forgejo; GitHub is a
  public mirror that only the export job pushes to, so an agent never adds a
  GitHub remote or pushes there. Never deploy — no `colmena apply`, no
  `just deploy*` — the user runs deployments.
- **Commits:** single-line conventional commits, no body, no trailers, scoped
  by area: `feat(axon)`, `fix(axon)`, `docs(axon)`, `chore(infra)`.
- The full coding rules — imports, naming, actor patterns, error types, test
  layout — are in [AGENTS.md](../AGENTS.md). This page does not restate them.
