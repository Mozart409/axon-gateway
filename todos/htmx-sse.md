# HTMX + SSE Frontend Implementation Plan

## Phase 0 - Decisions and Prerequisites

- [x] Confirm SSR-first architecture with `axum` backend and `maud` templating.
- [x] Choose `htmx` + SSE approach over `datastar` for server-driven UI updates.
- [x] Install frontend tooling in dev environment (`tailwindcss_4` in `flake.nix`).
- [ ] Decide whether UI routes live in existing server module or a new `ui` module.

## Phase 1 - Backend UI Foundations

- [ ] Add UI routes: `GET /ui` (dashboard shell) and `GET /ui/partials/*` (HTML fragments).
- [ ] Create `maud` layout template with slots for header, backend cards, status, and notifications.
- [ ] Add route-level auth strategy for `/ui` (reuse bearer auth or allow local-only mode).
- [ ] Add typed view models for backend state, tool counts, and connection health.

## Phase 2 - SSE Event Pipeline

- [ ] Add SSE endpoint `GET /ui/events` returning `text/event-stream`.
- [ ] Define event types (e.g., `backend_status_changed`, `backend_tools_updated`, `config_reloaded`).
- [ ] Introduce broadcast channel for pushing gateway/backend updates to UI subscribers.
- [ ] Hook existing actor events/logical state changes into SSE publisher.
- [ ] Add keepalive/ping events and client reconnect behavior.

## Phase 3 - HTMX Integration

- [ ] Add `htmx` and SSE extension scripts to base `maud` layout.
- [ ] Wire dashboard sections to update via SSE-triggered swaps.
- [ ] Implement progressive enhancement: page renders fully without JavaScript.
- [ ] Add action forms/buttons (reconnect, enable/disable backend, reload config) using `hx-post`.
- [ ] Return fragment responses for HTMX actions and surface success/error banners.

## Phase 4 - Styling with Tailwind CSS v4

- [ ] Create Tailwind input CSS and build pipeline output (dev + production modes).
- [ ] Build a consistent design token layer (color, spacing, typography) for the dashboard.
- [ ] Style primary UI modules: backend cards, health badges, event feed, and action bar.
- [ ] Add responsive behavior for mobile and tablet breakpoints.
- [ ] Verify contrast/accessibility and keyboard focus states.

## Phase 5 - Observability and Reliability

- [ ] Add structured logs around SSE connect/disconnect and event fanout errors.
- [ ] Add basic metrics: connected UI clients, events sent, dropped events.
- [ ] Handle stale/disconnected clients cleanly and prevent unbounded memory growth.
- [ ] Add graceful degradation messaging when SSE stream fails.

## Phase 6 - Testing and Validation

- [ ] Unit-test SSE event serialization and template fragment rendering.
- [ ] Integration-test key flows: initial page load, SSE updates, HTMX action round-trips.
- [ ] Manual test with multiple backends (up/down/flapping) and config reloads.
- [ ] Run `cargo fmt`, `cargo clippy -- -W clippy::pedantic`, and `cargo test`.

## Phase 7 - Documentation and Rollout

- [ ] Document frontend architecture and route map in `README.md`.
- [ ] Add configuration notes for UI auth and any SSE-related settings.
- [ ] Add local development instructions (tailwind watch/build + server run).
- [ ] Prepare follow-up backlog (filters, search, grouped views, live logs, pagination).
