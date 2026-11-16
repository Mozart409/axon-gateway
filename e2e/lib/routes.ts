import type { Page } from "@playwright/test";
import type { Route } from "./types";

export const ROUTES: Route[] = [
  { path: "/ui", detailPattern: /^\/ui\/backends\/[^/]+$/ },
  { path: "/ui/tools" },
  { path: "/ui/toolsets" },
  { path: "/ui/catalog" },
  { path: "/ui/tokens" },
  { path: "/ui/me/apps" },
  { path: "/ui/me/backends" },
  { path: "/ui/me/usage" },
  { path: "/ui/admin", detailPattern: /^\/ui\/admin\/groups\/[^/]+$/ },
  { path: "/ui/admin/audit" },
  { path: "/ui/admin/audit-settings" },
  {
    path: "/ui/admin/config/backends",
    detailPattern: /^\/ui\/admin\/config\/backends\/[^/]+$/,
  },
  {
    path: "/ui/admin/config/oidc-providers",
    detailPattern: /^\/ui\/admin\/config\/oidc-providers\/[^/]+$/,
  },
  { path: "/ui/admin/config/settings" },
  {
    path: "/ui/admin/config/toolsets",
    detailPattern: /^\/ui\/admin\/config\/toolsets\/[^/]+$/,
  },
  { path: "/ui/admin/personal-backends" },
  { path: "/ui/admin/roles" },
  { path: "/ui/admin/scim" },
  { path: "/ui/admin/service-accounts" },
  {
    path: "/ui/admin/tool-calls",
    detailPattern: /^\/ui\/admin\/tool-calls\/[^/]+$/,
  },
  {
    path: "/ui/admin/usage",
    detailPattern: /^\/ui\/admin\/usage\/[^/]+$/,
  },
  { path: "/ui/admin/users" },
];

/** Path prefixes that are not pages (actions, partials, streams, assets). */
export const IGNORED_PATH_PREFIXES = [
  "/ui/actions/",
  "/ui/partials/",
  "/ui/events",
  "/auth/",
  "/static/",
  "/styles/",
];

/**
 * Detail page links found in `main` of the already loaded page of `route`:
 * distinct paths (query and hash stripped) matching `route.detailPattern`.
 */
export async function discoverDetailPaths(
  page: Page,
  route: Route,
  limit = 2,
): Promise<string[]> {
  const pattern = route.detailPattern;
  if (!pattern) return [];
  const hrefs = await page
    .locator("main a[href]")
    .evaluateAll((els) => els.map((a) => a.getAttribute("href") ?? ""));
  const found = new Set<string>();
  for (const href of hrefs) {
    const path = href.split(/[?#]/)[0] ?? "";
    if (pattern.test(path)) found.add(path);
    if (found.size >= limit) break;
  }
  return [...found];
}

/** True for a listed route path or a path matching a route's detail pattern. */
export function matchesKnownRoute(path: string): boolean {
  return ROUTES.some((r) => r.path === path || r.detailPattern?.test(path));
}
