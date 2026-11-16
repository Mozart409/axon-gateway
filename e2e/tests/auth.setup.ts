import { test as setup, expect } from "@playwright/test";

setup("log in as the dev user", async ({ page }) => {
  // The mock OIDC provider logs in without a form and lands back on /ui.
  await page.goto("/ui");
  await page.waitForURL(/\/ui$/);
  await expect(page.getByRole("main")).toBeVisible();
  await page.context().storageState({ path: "./.auth/dev.json" });
});
