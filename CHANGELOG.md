# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

- - -
## v0.8.1 - 2026-11-20
#### Features
- (**deps**) upgrade flake - (fbacce8) - Amadeus Mader
#### Bug Fixes
- (**axon**) mark forwarded mcp results as complete for 2026-07-28 clients - (611d384) - Amadeus Mader

- - -
## v0.8.0 - 2026-11-19
#### Features
- (**axon**) confirm a backend credential mode switch in a dialog and refuse an unconfirmed one - (f83c9b5) - Amadeus Mader
- (**axon**) guide first-run setup in the dashboard and edit every backend credential mode in the form - (d2408fe) - Amadeus Mader
- (**axon**) list every admin and audit page in the sidebar instead of a button row - (ed29607) - Amadeus Mader
- (**axon**) add the axon-prod-setup skill for repo users - (0057fcd) - Amadeus Mader
#### Bug Fixes
- (**axon**) make the access matrix cells links to their grant or a prefilled add form instead of toggle look-alikes - (81929df) - Amadeus Mader
- (**axon**) skip homelab, tailscale and cluster hosts in the link check - (d1783fa) - Amadeus Mader
- (**axon**) add the lychee config the links recipe expects - (7bebf34) - Amadeus Mader
#### Documentation
- (**axon**) ship the setup skill to operators under skills/ with install steps in the README - (e630be1) - Amadeus Mader
- (**axon**) extend the setup skill with discovery, IdP checklist, client setup, verification and troubleshooting - (58194ef) - Amadeus Mader
- (**axon**) fix the dead rmcp and spec links in goals - (3fcca1b) - Amadeus Mader
- (**axon**) add the dev setup guide for humans and agents - (34238b2) - Amadeus Mader

- - -
## v0.7.0 - 2026-11-18
#### Features
- (**axon**) broadcast a usage_changed SSE ping with live usage regions and a cross-replica audit-tail poller - (ef30dea) - Amadeus Mader
- (**deps**) upgrade flake - (1d2c04c) - Amadeus Mader
#### Miscellaneous Chores
- (**deps**) ignore RUSTSEC-2026-0543 (unmaintained chrono) in deny configs - (34aeab6) - Amadeus Mader
- (**axon**) bump the helm chart to 0.6.0 and keep it in sync with releases via a cog pre-bump hook and an axon-deploy-check guard - (537c7e2) - Amadeus Mader

- - -
## v0.6.0 - 2026-11-16
#### Features
- (**axon**) add a property-based Playwright e2e suite for every UI page, with Node and Nix Chromium in the dev shell - (6b70fa3) - Amadeus Mader
- (**axon**) port every UI page to the themed design with drawer forms, SVG usage charts and a grants matrix - (03677bd) - Amadeus Mader
- (**axon**) add the themed sidebar shell with Geist fonts, Lucide icons and a theme cookie - (a257a4b) - Amadeus Mader
- (**axon**) add a token-checking demo MCP backend for the dev OAuth and passthrough flows - (9addb90) - Amadeus Mader
- (**axon**) run the dev gateway in database mode against the mock OIDC provider and drop config.toml - (42f7af7) - Amadeus Mader
- (**axon**) add dev auto-consent flag and mock-OIDC compose stack - (1a33325) - Amadeus Mader
- (**deps**) upgrade flake - (8c173b9) - Amadeus Mader
#### Bug Fixes
- (**axon**) bump the wolfi-base digest for the glibc and brotli CVE fixes - (f3d3e37) - Amadeus Mader
- (**axon**) give the overview backend tile link a 24px tap target - (73cecca) - Amadeus Mader
- (**axon**) cap the page width on wide screens and fix the accessibility findings of the e2e suite - (5d36ddd) - Amadeus Mader
- (**axon**) scan only src for Tailwind classes so cargo builds no longer retrigger the css watcher - (d66ca74) - Amadeus Mader
- (**axon**) pad the groups card and card the empty state on the my tools page - (99dfa0f) - Amadeus Mader
- (**axon**) advertise the openid scope in the demo backend's resource metadata - (52a802a) - Amadeus Mader
- (**axon**) pin every checked address so egress connections fall back from IPv6 to IPv4 - (5124627) - Amadeus Mader
- (**axon**) mount the dev Postgres volume at /var/lib/postgresql and name the service that fails to start - (f8d6459) - Amadeus Mader
- (**axon**) match the dockerfile rust image to the flake's 1.100.0 - (664f04a) - Amadeus Mader
#### Documentation
- (**axon**) note the grant, sign-in order and restart the demo backends need - (872caaf) - Amadeus Mader
- (**vault**) fix markdownlint findings - (83933d2) - Amadeus Mader
#### Tests
- (**axon**) seed a backend, toolset and group for the e2e detail pages and check all drawers in one test - (13f1e7b) - Amadeus Mader
#### Continuous Integration
- (**axon**) run the CI workflow, e2e included, on pushes to main as well - (ab4d523) - Amadeus Mader
- (**axon**) run the Playwright e2e suite against the compose stack on pull requests - (83a54f8) - Amadeus Mader
#### Miscellaneous Chores
- (**axon**) drop the unused moka dependency and the redundant homepage field - (bf305da) - Amadeus Mader
- (**axon**) keep the e2e suite and its node_modules out of the docker build context - (ee63432) - Amadeus Mader
- (**axon**) rebuild the Tailwind output for the redesigned pages - (93398a6) - Amadeus Mader
- (**axon**) address the dev mock OIDC issuer as 127.0.0.1 - (d09b2f6) - Amadeus Mader
- (**axon**) remove comments and local container dev build - (73af476) - Amadeus Mader
- (**axon**) ignore .playwright-mcp - (a24b9e9) - Amadeus Mader

- - -
## v0.5.3 - 2026-11-12
#### Features
- (**axon**) drop the gateway status button from the landing page and show the user's groups as pills in the user bar - (2491ddf) - Amadeus Mader

- - -
## v0.5.2 - 2026-11-12
#### Features
- (**axon**) add AXON_OIDC_SCOPES so the bootstrap provider can request the groups scope that admin groups need - (8d86f84) - Amadeus Mader

- - -
## v0.5.1 - 2026-11-12
#### Bug Fixes
- (**axon**) copy the vendored static scripts into the image build stage that embeds them - (2f50d66) - Amadeus Mader

- - -
## v0.5.0 - 2026-11-12
#### Features
- (**axon**) move the configuration into the database with env-only startup, a config admin api and ui, live reload across replicas and admin import-config - (04f3752) - Amadeus Mader
- (**axon**) add scim 2.0 provisioning, custom roles and the entra groups-overage graph lookup - (c70e5a3) - Amadeus Mader
- (**axon**) connect catalog backends with upstream oauth and pass the caller's identity through by token exchange - (571a0b8) - Amadeus Mader
- (**axon**) accept idp access tokens and add an mcp oauth authorization server - (0ef7427) - Amadeus Mader
- (**axon**) add per-user, auth, pool and oidc metrics, trace context in mcp _meta, a usage page, a helm chart and grafana and prometheus assets - (0d67b66) - Amadeus Mader
- (**axon**) add personal mcp backends, a per-user credential catalog, envelope encryption, an egress guard, idle timeouts and per-user quotas - (e28d1e7) - Amadeus Mader
- (**axon**) run several replicas on one database with notify fan-out, shared sessions and rate limits, and singleton jobs - (0748553) - Amadeus Mader
- (**axon**) serve mcp over spec-compliant streamable http with list_changed, progress and cancellation passthrough - (8b76aa3) - Amadeus Mader
- (**axon**) add user toolsets with token pinning and a tool-call audit with capture rules and retention - (c41c7e0) - Amadeus Mader
- (**deps**) upgrade flake - (ee15c75) - Amadeus Mader
- (**axon**) map legacy tokens to config service accounts, add user disable, token client ip and break-glass login link - (7671030) - Amadeus Mader
- (**axon**) add personal access tokens and service accounts with per-principal tool enforcement on mcp - (437579f) - Amadeus Mader
- (**axon**) add admin dashboard pages for rbac groups, grants, role bindings and the audit log - (827462c) - Amadeus Mader
- (**axon**) add managed rbac groups, grants and role bindings with an audited admin api - (508e606) - Amadeus Mader
- (**axon**) add rbac groups, tool grants, per-user opt-outs and a my tools page, rename tool groups to toolsets - (fd045d0) - Amadeus Mader
- (**axon**) add multi-provider oidc login, sessions and csrf protection for the dashboard - (1c1dc0f) - Amadeus Mader
- (**axon**) add optional postgres store, otlp tracing and a database readiness check - (b1c8d91) - Amadeus Mader
- (**deps**) upgrade flake - (63bf9d2) - Amadeus Mader
- (**deps**) upgrade flake - (e725892) - Amadeus Mader
- (**deps**) upgrade flake - (f316a73) - Amadeus Mader
- (**rust**) run the rust-ci gate as cached crane checks - (83c2f69) - Amadeus Mader
- (**deps**) upgrade flake - (822dafb) - Amadeus Mader
- (**deps**) upgrade flake - (4422822) - Amadeus Mader
#### Bug Fixes
- (**axon**) bake the release commit into the image so the footer and /build show it instead of dev - (beca8ef) - Amadeus Mader
- (**axon**) harden the gateway with a strict csp, login and token-mint rate limits, ssrf, log, audit and session fixes and a threat model - (56f4456) - Amadeus Mader
- (**axon**) keep the helm import file in a secret and mint no tokens in the import job - (2e10595) - Amadeus Mader
- (**axon**) close the group escalation, serialize scim patches, fix the catalog auth switch, audit oauth connects and request the entra obo assertion for the gateway - (b79a8ef) - Amadeus Mader
- (**axon**) check upstream oauth endpoints off the backend's host against the egress policy - (066c7cb) - Amadeus Mader
- (**axon**) label service account tokens as service in principal_type - (b308b37) - Amadeus Mader
- (**axon**) refuse service account names taken by config tokens - (cd77c36) - Amadeus Mader
- (**axon**) keep the sqlx dependency on one line and ship migrations in the docker and nix builds - (77e1500) - Amadeus Mader
- (**axon**) keep the trust-auth test database socket per-user and owner-only - (55a58a0) - Amadeus Mader
- (**axon**) run backend calls concurrently instead of one at a time - (e072e60) - Amadeus Mader
- (**axon**) bump rmcp to 3.9.0 for RUSTSEC-2026-0462 - (989b444) - Amadeus Mader
#### Refactoring
- (**axon**) extract authz scope checks from the auth manager - (ba3bcdb) - Amadeus Mader
- (**axon**) split server into mcp, ui, api and auth modules and add livez and readyz - (b727786) - Amadeus Mader
#### Documentation
- (**axon**) explain pinning the container resolver for backends reached by hostname - (fef28b2) - Amadeus Mader
- (**axon**) mark phase 3a done in the multi-user plan and note where to resume - (cf5ec64) - Amadeus Mader
- (**axon**) split health into shared probes and passive per-user health - (1f91472) - Amadeus Mader
- (**axon**) default 5 min idle timeout and config-gated stdio in the plan - (722b6fa) - Amadeus Mader
- (**axon**) settle protocol versions, backend instances and metrics in the plan - (9eb00ef) - Amadeus Mader
- (**axon**) fold k8s, entra, views and audit decisions into the plan - (b8175a2) - Amadeus Mader
- (**axon**) plan multi-user oidc, rbac and observability - (5ed11a3) - Amadeus Mader
#### Tests
- (**axon**) cover a backend whose first connect fails and a later reconnect succeeds - (c885111) - Amadeus Mader
#### Continuous Integration
- (**axon**) keep the 5 newest releases on ghcr - (0052f9d) - Amadeus Mader
#### Miscellaneous Chores
- (**axon**) add tmpfs test database recipes and run axon-ci tests through them - (6555f50) - Amadeus Mader
- (**deps**) remove the remaining darwin support from subflakes, templates, hofvarpnir releases and docs - (ccf758a) - Amadeus Mader

- - -
## v0.4.2 - 2026-10-25
#### Features
- (**axon**) update cargo dependencies - (58bd006) - Amadeus Mader
- (**deps**) upgrade flake - (bbc9309) - Amadeus Mader
- (**deps**) upgrade flake - (6827a80) - Amadeus Mader
- (**deps**) upgrade flake - (d46ea63) - Amadeus Mader
#### Continuous Integration
- (**axon**) drop dependabot version updates on the github mirror - (866f42e) - Amadeus Mader
#### Miscellaneous Chores
- (**axon**) skip duplicate crates in cargo-deny - (52e2511) - Amadeus Mader
- (**axon**) update cargo dependencies - (70200b1) - Amadeus Mader
- (**axon**) bump setup-rust-toolchain to v2 and install-action - (1ebd6fd) - Amadeus Mader

- - -
## v0.4.1 - 2026-10-21
#### Bug Fixes
- (**axon**) match the dockerfile rust image to the flake's 1.99.1 - (a91b75e) - Amadeus Mader
- (**axon**) bump rustls, rustls-webpki and webpki-root-certs for RUSTSEC-2026-0346..0349, 0382 and 0383 - (7c4eb7b) - Amadeus Mader

- - -

## v0.4.0 - 2026-10-21
#### Features
- (**axon**) add lock-axon to pin the export lock to the root - (dabff76) - Amadeus Mader
- (**axon**) sync the dependency upgrade from github - (af5bc1e) - Amadeus Mader
- (**rust**) share one toolchain, wire axon, dashboard and surrealkit - (9839f22) - Amadeus Mader
#### Bug Fixes
- (**axon**) run the container as nonroot on a digest-pinned wolfi base - (55b8e2a) - Amadeus Mader
- (**axon**) answer JSON-RPC notifications with 202 and an empty body - (eda4fa2) - Amadeus Mader
- (**axon**) reject invalid custom backend headers in config validation - (70f54eb) - Amadeus Mader
- (**axon**) load config on the blocking pool during reloads - (4fcb17b) - Amadeus Mader
- (**axon**) rebuild auth tokens on config hot reload - (4806743) - Amadeus Mader
- (**axon**) drop permissive CORS and reject cross-site UI actions - (bdc02fb) - Amadeus Mader
- (**axon**) enforce token backend and tool ACLs on lists, resource reads and prompt gets - (4327cdf) - Amadeus Mader
- (**axon**) serve MCP requests outside the gateway actor so slow calls do not block it - (7ae0fae) - Amadeus Mader
- (**sync**) also push tags to all remotes - (0a7d5ea) - macbook-pro
#### Miscellaneous Chores
- (**axon**) move clippy pedantic and panic denies into a lints table - (ed35fc3) - Amadeus Mader
- (**axon**) drop stale notification bug todo - (32ffed3) - Amadeus Mader
- (**axon**) fold axon-gateway tooling into the root - (4f5eabb) - Amadeus Mader
- (**deps**) pin subflake locks to the root flake.lock revisions - (aebd49e) - Amadeus Mader
- (**repo**) pin subflake locks to the root lock with one lock-sub recipe and a drift guard - (38a25f2) - Amadeus Mader
- (**rust**) delete the dead woodpecker configs and axon sync-remotes - (70c5101) - Amadeus Mader

- - -

## v0.3.3 - 2026-09-03
#### Bug Fixes
- (**container**) added registry - (cb02a2b) - developmentbot
- (**deps**) patch h2 RUSTSEC-2026-0258, bump event-listener and chacha20 - (6431876) - developmentbot
#### Documentation
- correct kameo version in AGENTS.md - (904911a) - developmentbot
#### Build system
- (**deps**) bump taiki-e/install-action in the github-actions group - (bab57d1) - dependabot[bot]
#### Refactoring
- (**cog**) remove sed for cargo-edit - (90becec) - macbook-pro
#### Miscellaneous Chores
- (**deps**) upgrade to rust 1.96.1 - (e07b6d4) - Amadeus Mader
- (**tools**) add script for syncing remotes - (557ef55) - macbook-pro

- - -

## v0.3.2 - 2026-07-12
#### Bug Fixes
- (**tools**) add docker build before push - (9c09c2f) - Amadeus Mader
#### Documentation
- (**agents**) add check for rust versions everywhere - (180586d) - Amadeus Mader
- (**agents**) add a notch to llm to check rust versions - (29ad3ba) - Amadeus Mader
#### Continuous Integration
- (**deps**) upgrade rust version - (cbfa024) - Amadeus Mader
#### Miscellaneous Chores
- (**deps**) upgrade flake and docker rust versions - (cee113d) - Amadeus Mader

- - -

## v0.3.1 - 2026-07-12
#### Bug Fixes
- (**watcher**) use async channel + watch parent dir for reload - (dfcdd77) - Amadeus Mader
#### Miscellaneous Chores
- (**license**) delete license html - (8cad095) - Amadeus Mader

- - -

## v0.3.0 - 2026-07-11
#### Features
- (**cog**) update release script to include cog - (fc7c1ac) - Amadeus Mader
- (**tests**) add more tests - (aee6067) - Amadeus Mader
#### Bug Fixes
- (**deps**) upgrade deps - (46d3915) - Amadeus Mader
#### Documentation
- (**rate-limit**) add rate-limit explaination - (87546c1) - Amadeus Mader
#### Build system
- (**deps**) bump the cargo group with 4 updates - (64b599e) - dependabot[bot]
- (**deps**) bump actions/checkout in the github-actions group - (0520dc8) - dependabot[bot]

- - -

Changelog generated by [cocogitto](https://github.com/cocogitto/cocogitto).
