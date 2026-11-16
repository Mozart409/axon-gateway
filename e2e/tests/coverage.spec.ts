// Properties checked: every UI page reachable by links from ROUTES is itself
// matched by ROUTES (so no page escapes the other suites) and answers 200.
import { expect, expectClean, openPage, test } from "../lib/fixtures";
import {
  IGNORED_PATH_PREFIXES,
  ROUTES,
  matchesKnownRoute,
} from "../lib/routes";

const MAX_PAGES = 80;

test("every reachable UI page is covered by ROUTES", async ({
  page,
  issues,
}) => {
  test.setTimeout(300_000);
  await openPage(page, ROUTES[0].path, {
    viewport: { width: 1280, height: 800 },
    theme: "system",
  });

  const queue = ROUTES.map((r) => r.path);
  const seen = new Set<string>(queue);
  const visited: string[] = [];
  const uncovered: string[] = [];
  const badStatus: string[] = [];

  while (queue.length > 0 && visited.length < MAX_PAGES) {
    const path = queue.shift() as string;
    visited.push(path);
    const response = await page.goto(path, { waitUntil: "domcontentloaded" });
    const status = response?.status() ?? 0;
    if (status !== 200) badStatus.push(`${path} answered ${status}`);
    if (!matchesKnownRoute(path)) uncovered.push(path);

    const found = await page.evaluate(() =>
      Array.from(document.querySelectorAll("a[href]")).flatMap((a) => {
        try {
          const url = new URL((a as HTMLAnchorElement).href, location.href);
          return url.origin === location.origin ? [url.pathname] : [];
        } catch {
          return [];
        }
      }),
    );
    for (const href of found) {
      if (!href.startsWith("/ui")) continue;
      if (href === "/auth/logout") continue;
      if (IGNORED_PATH_PREFIXES.some((p) => href.startsWith(p))) continue;
      if (seen.has(href)) continue;
      seen.add(href);
      queue.push(href);
    }
  }

  expect(badStatus, "pages that did not answer 200").toEqual([]);
  expect(uncovered, "add these pages to e2e/lib/routes.ts").toEqual([]);
  expectClean(issues, "crawl");
});
