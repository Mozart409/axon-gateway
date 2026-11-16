// Shared types of the e2e suite. Every check is a property: an invariant that
// must hold for any page, viewport and theme, judged from geometry, roles and
// attributes, never from CSS class names.
import type { Page } from "@playwright/test";

export type Viewport = { width: number; height: number };

/** Where a property is being checked. */
export type CheckContext = { path: string; viewport: Viewport; theme: string };

/** One broken invariant, with enough detail to find the element. */
export type Violation = { property: string; detail: string };

export type Property = {
  name: string;
  check: (page: Page, ctx: CheckContext) => Promise<Violation[]>;
};

/** A UI page. `detailPattern` matches the links on it that lead to its detail pages. */
export type Route = { path: string; detailPattern?: RegExp };
