import { test as base, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import type { Violation, Viewport } from "./types";

export const BASE_URL = process.env.AXON_E2E_BASE_URL ?? "http://localhost:8080";

/**
 * `issues` collects console errors, page errors, CSP violations and failed
 * same-origin responses of the `page` fixture. It is not asserted
 * automatically; specs call `expectClean(issues, label)`.
 */
export const test = base.extend<{ issues: string[] }>({
  issues: [
    async ({ page }, use) => {
      const issues: string[] = [];
      const origin = new URL(BASE_URL).origin;
      const noise = (text: string) =>
        text.includes("/ui/events") || text.includes("net::ERR_ABORTED");

      await page.addInitScript(() => {
        document.addEventListener("securitypolicyviolation", (e) => {
          console.error("CSP violation: " + e.violatedDirective + " " + e.blockedURI);
        });
      });
      page.on("console", (msg) => {
        if (msg.type() !== "error") return;
        const text = msg.text();
        if (!noise(text)) issues.push(text);
      });
      page.on("pageerror", (err) => {
        issues.push("pageerror: " + err.message);
      });
      page.on("response", (res) => {
        const url = res.url();
        if (!url.startsWith(origin) || res.status() < 400) return;
        if (new URL(url).pathname === "/ui/events") return;
        issues.push(`HTTP ${res.status()} ${url}`);
      });

      await use(issues);
    },
    { auto: true, scope: "test" },
  ],
});

export { expect };

/** Fails the test when `issues` is not empty, listing every issue. */
export function expectClean(issues: string[], label: string): void {
  expect(
    issues,
    `${label}: ${issues.length} browser issue(s):\n${issues.join("\n")}`,
  ).toEqual([]);
}

/** Loads `path` at the given viewport and theme and waits for fonts. */
export async function openPage(
  page: Page,
  path: string,
  opts: { viewport: Viewport; theme: string },
): Promise<void> {
  await page.setViewportSize(opts.viewport);
  await page.context().addCookies([
    {
      name: "axon_theme",
      value: opts.theme,
      url: new URL(path, BASE_URL).origin,
    },
  ]);
  // Never wait for networkidle: /ui/events is a long-lived SSE stream.
  const response = await page.goto(path, { waitUntil: "load" });
  expect(response?.status(), `GET ${path}`).toBe(200);
  await page.evaluate(() => document.fonts.ready.then(() => undefined));
}

/** Theme ids offered by the shell's theme select. Needs a loaded page. */
export async function themeIds(page: Page): Promise<string[]> {
  return page
    .getByRole("combobox", { name: "Theme" })
    .evaluate((el) =>
      Array.from((el as HTMLSelectElement).options).map((o) => o.value),
    );
}

/** One line per violation, `[property] detail`. */
export function formatViolations(v: Violation[]): string {
  return v.map((x) => `[${x.property}] ${x.detail}`).join("\n");
}
