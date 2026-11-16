// Properties checked: every route holds the layout properties at the named
// breakpoints and at generated viewport/theme pairs, passes axe at mobile and
// desktop in light and dark, and its detail pages hold the layout properties.
import fc from "fast-check";
import {
  expect,
  expectClean,
  formatViolations,
  openPage,
  test,
  themeIds,
} from "../lib/fixtures";
import { AXE_PROPERTY } from "../lib/a11y";
import {
  BREAKPOINTS,
  fcParams,
  themeArb,
  viewportArb,
} from "../lib/arbitraries";
import { checkProperties } from "../lib/properties";
import { ROUTES, discoverDetailPaths } from "../lib/routes";
import type { Violation } from "../lib/types";

test.describe.configure({ mode: "parallel" });

const DESKTOP = { width: 1280, height: 800 };
const MOBILE = { width: 390, height: 844 };

for (const route of ROUTES) {
  test.describe(route.path, () => {
    test("holds the layout properties at every breakpoint", async ({
      page,
      issues,
    }) => {
      test.setTimeout(120_000);
      const all: Violation[] = [];
      for (const viewport of BREAKPOINTS) {
        await openPage(page, route.path, { viewport, theme: "system" });
        const found = await checkProperties(page, {
          path: route.path,
          viewport,
          theme: "system",
        });
        const label = `${viewport.width}x${viewport.height}`;
        for (const v of found) {
          all.push({ ...v, detail: `[${label}] ${v.detail}` });
        }
      }
      expect(all, formatViolations(all)).toEqual([]);
      expectClean(issues, route.path);
    });

    test("holds the layout properties for generated viewports and themes", async ({
      page,
      issues,
    }) => {
      test.setTimeout(300_000);
      await openPage(page, route.path, { viewport: DESKTOP, theme: "system" });
      const ids = await themeIds(page);
      await fc.assert(
        fc.asyncProperty(viewportArb, themeArb(ids), async (viewport, theme) => {
          await openPage(page, route.path, { viewport, theme });
          const found = await checkProperties(page, {
            path: route.path,
            viewport,
            theme,
          });
          if (found.length) {
            throw new Error(formatViolations(found));
          }
        }),
        fcParams(),
      );
      expectClean(issues, route.path);
    });

    test("passes axe at mobile and desktop", async ({ page }) => {
      test.setTimeout(120_000);
      const all: Violation[] = [];
      for (const viewport of [MOBILE, DESKTOP]) {
        for (const theme of ["light", "dark"]) {
          await openPage(page, route.path, { viewport, theme });
          const found = await AXE_PROPERTY.check(page, {
            path: route.path,
            viewport,
            theme,
          });
          const label = `${viewport.width}x${viewport.height} ${theme}`;
          for (const v of found) {
            all.push({ ...v, detail: `[${label}] ${v.detail}` });
          }
        }
      }
      expect(all, formatViolations(all)).toEqual([]);
    });

    if (route.detailPattern) {
      test("detail pages hold the layout properties", async ({
        page,
        issues,
      }) => {
        test.setTimeout(180_000);
        await openPage(page, route.path, {
          viewport: DESKTOP,
          theme: "system",
        });
        const details = await discoverDetailPaths(page, route, 2);
        test.skip(details.length === 0, `no detail pages under ${route.path}`);
        const all: Violation[] = [];
        for (const path of details) {
          for (const viewport of [MOBILE, DESKTOP, { width: 2560, height: 1440 }]) {
            await openPage(page, path, { viewport, theme: "system" });
            const found = await checkProperties(page, {
              path,
              viewport,
              theme: "system",
            });
            const label = `${path} ${viewport.width}x${viewport.height}`;
            for (const v of found) {
              all.push({ ...v, detail: `[${label}] ${v.detail}` });
            }
          }
        }
        expect(all, formatViolations(all)).toEqual([]);
        expectClean(issues, route.path);
      });
    }
  });
}
