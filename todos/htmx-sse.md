# HTMX + SSE Frontend Implementation Plan

## Phase 0 - Decisions and Prerequisites

- [x] Confirm SSR-first architecture with `axum` backend and `maud` templating.
- [x] Choose `htmx` + SSE approach over `datastar` for server-driven UI updates.
- [x] Install frontend tooling in dev environment (`tailwindcss_4` in `flake.nix`).
- [x] Decide whether UI routes live in existing server module or a new `ui` module.

## Phase 1 - Backend UI Foundations

- [x] Add UI routes: `GET /ui` (dashboard shell) and `GET /ui/partials/*` (HTML fragments).
- [x] Create `maud` layout template with slots for header, backend cards, status, and notifications.
- [x] Add route-level auth strategy for `/ui` (reuse bearer auth or allow local-only mode).
- [ ] Add typed view models for backend state, tool counts, and connection health.

## Phase 2 - SSE Event Pipeline

- [x] Add SSE endpoint `GET /ui/events` returning `text/event-stream`.
- [x] Define event types (e.g., `backend_status_changed`, `backend_tools_updated`, `config_reloaded`).
- [x] Introduce broadcast channel for pushing gateway/backend updates to UI subscribers.
- [x] Hook existing actor events/logical state changes into SSE publisher.
- [x] Add keepalive/ping events and client reconnect behavior.

## Phase 3 - HTMX Integration

- [x] Add `htmx` and SSE extension scripts to base `maud` layout.
- [x] Wire dashboard sections to update via SSE-triggered swaps.
- [x] Implement progressive enhancement: page renders fully without JavaScript.
- [x] Add action forms/buttons (reconnect, enable/disable backend, reload config) using `hx-post`.
- [x] Return fragment responses for HTMX actions and surface success/error banners.

## Phase 4 - Styling with Tailwind CSS v4

- [x] Create Tailwind input CSS and build pipeline output (dev + production modes).
- [ ] Build a consistent design token layer (color, spacing, typography) for the dashboard.
- [x] Style primary UI modules: backend cards, health badges, event feed, and action bar.
- [x] Add responsive behavior for mobile and tablet breakpoints.
- [x] Verify contrast/accessibility and keyboard focus states.

## Phase 5 - Observability and Reliability

- [x] Add structured logs around SSE connect/disconnect and event fanout errors.
- [x] Add basic metrics: connected UI clients, events sent, dropped events.
- [x] Handle stale/disconnected clients cleanly and prevent unbounded memory growth.
- [x] Add graceful degradation messaging when SSE stream fails.

## Phase 6 - Testing and Validation

- [x] Unit-test SSE event serialization and template fragment rendering.
- [x] Integration-test key flows: initial page load, SSE updates, HTMX action round-trips.
- [ ] Manual test with multiple backends (up/down/flapping) and config reloads.
- [x] Run `cargo fmt`, `cargo clippy -- -W clippy::pedantic`, and `cargo test`.

## Phase 7 - Documentation and Rollout

- [x] Document frontend architecture and route map in `README.md`.
- [x] Add configuration notes for UI auth and any SSE-related settings.
- [x] Add local development instructions (tailwind watch/build + server run).
- [x] Prepare follow-up backlog (filters, search, grouped views, live logs, pagination).
