// Properties checked: every drawer opens inside the viewport with a focusable
// control and closes on Escape; the mobile menu exposes every main navigation
// link; a chosen theme is applied and persists across pages.
import {
  expect,
  expectClean,
  openPage,
  test,
  themeIds,
} from "../lib/fixtures";
import { ROUTES } from "../lib/routes";

test.describe.configure({ mode: "parallel" });

const DESKTOP = { width: 1280, height: 800 };
const MOBILE = { width: 390, height: 844 };

for (const route of ROUTES) {
  test(`drawers on ${route.path}`, async ({ page, issues }) => {
    test.setTimeout(120_000);
    let opened = 0;
    for (const viewport of [MOBILE, DESKTOP]) {
      await openPage(page, route.path, { viewport, theme: "system" });
      const buttons = page.locator(
        'main button[popovertarget]:not([popovertargetaction="hide"])',
      );
      const ids = new Set<string>();
      for (const button of await buttons.all()) {
        if (!(await button.isVisible())) continue;
        const id = await button.getAttribute("popovertarget");
        if (id) ids.add(id);
      }
      for (const id of ids) {
        const trigger = page
          .locator(
            `main button[popovertarget="${id}"]:not([popovertargetaction="hide"])`,
          )
          .locator("visible=true")
          .first();
        await trigger.click();
        const popover = page.locator(`[id="${id}"]`);
        await expect(popover, `${id} opens`).toBeVisible();
        const box = await popover.boundingBox();
        expect(box, `${id} has a box`).not.toBeNull();
        if (box) {
          const label = `${id} at ${viewport.width}x${viewport.height}`;
          expect(box.x, `${label}: left edge`).toBeGreaterThanOrEqual(-1);
          expect(box.y, `${label}: top edge`).toBeGreaterThanOrEqual(-1);
          expect(box.x + box.width, `${label}: right edge`).toBeLessThanOrEqual(
            viewport.width + 1,
          );
          expect(box.y + box.height, `${label}: bottom edge`).toBeLessThanOrEqual(
            viewport.height + 1,
          );
        }
        const focusable = popover.locator(
          "a[href], button, input, select, textarea, [tabindex]:not([tabindex='-1'])",
        );
        expect(
          await focusable.count(),
          `${id} contains a focusable control`,
        ).toBeGreaterThan(0);
        await page.keyboard.press("Escape");
        await expect(popover, `${id} closes on Escape`).toBeHidden();
        opened += 1;
      }
    }
    expectClean(issues, route.path);
    test.skip(opened === 0, `no drawers on ${route.path}`);
  });
}

test("the menu exposes every main navigation link on small screens", async ({
  page,
  issues,
}) => {
  await openPage(page, "/ui", { viewport: MOBILE, theme: "system" });
  const hrefs = await page
    .locator('nav[aria-label="Main"] a[href]')
    .evaluateAll((els) => els.map((el) => el.getAttribute("href") ?? ""));
  expect(hrefs.length, "the sidebar has links").toBeGreaterThan(0);

  await page.getByRole("button", { name: "Open menu" }).click();
  const links = page.locator("[popover]:popover-open a[href]");
  await expect(links.first()).toBeVisible();
  const shown = await links.evaluateAll((els) =>
    els
      .filter((el) => el.checkVisibility())
      .map((el) => el.getAttribute("href") ?? ""),
  );
  const missing = hrefs.filter((h) => !shown.includes(h));
  expect(missing, "links missing from the menu").toEqual([]);

  await page.getByRole("button", { name: "Close menu" }).click();
  await expect(page.locator("[popover]:popover-open")).toHaveCount(0);

  await openPage(page, "/ui", { viewport: DESKTOP, theme: "system" });
  await expect(page.locator('nav[aria-label="Main"]')).toBeVisible();
  await expect(page.getByRole("button", { name: "Open menu" })).toBeHidden();
  expectClean(issues, "/ui menu");
});

test("choosing a theme applies it and keeps it across pages", async ({
  page,
  issues,
}) => {
  await openPage(page, "/ui", { viewport: DESKTOP, theme: "system" });
  const ids = (await themeIds(page)).filter((id) => id !== "system");
  test.skip(ids.length === 0, "no theme besides system");
  const id = ids[ids.length - 1];
  const select = page.getByRole("combobox", { name: "Theme" });
  try {
    await select.selectOption(id);
    await expect(page.locator("html")).toHaveAttribute("data-theme", id);
    await page.goto("/ui/tools");
    await expect(page.locator("html")).toHaveAttribute("data-theme", id);
  } finally {
    await page.goto("/ui");
    await page.getByRole("combobox", { name: "Theme" }).selectOption("system");
    await expect(page.getByRole("combobox", { name: "Theme" })).toHaveValue(
      "system",
    );
  }
  expectClean(issues, "theme choice");
});
