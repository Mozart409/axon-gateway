// Seeds the data the detail pages link to (a shared backend, a toolset and a
// group) through the admin API; 409 means a previous run already created it.
import { test as setup, expect } from "@playwright/test";

setup("seed the data the pages link to", async ({ page, baseURL }) => {
  setup.setTimeout(120_000);
  await page.goto("/ui");
  await expect(page.getByRole("main")).toBeVisible();
  const csrf = await page
    .locator('meta[name="csrf-token"]')
    .getAttribute("content");
  expect(csrf, "the page carries a csrf token").toBeTruthy();
  const headers = {
    "x-csrf-token": csrf ?? "",
    origin: new URL(baseURL ?? page.url()).origin,
  };

  const seeds: Array<[string, Record<string, unknown>]> = [
    [
      "/api/v1/admin/config/backends",
      {
        name: "e2e-open",
        url: "http://127.0.0.1:3003/open/mcp",
        transport: "http",
      },
    ],
    [
      "/api/v1/admin/config/toolsets",
      {
        name: "e2e-readers",
        tools: ["e2e-open_*"],
        description: "Read-only tools of the e2e backend",
      },
    ],
    [
      "/api/v1/groups",
      { name: "e2e-team", description: "Group created by the e2e suite" },
    ],
  ];
  for (const [path, data] of seeds) {
    const response = await page.request.post(path, { data, headers });
    expect(
      [201, 409],
      `POST ${path} returned ${response.status()}: ${await response.text()}`,
    ).toContain(response.status());
  }

  const deadline = Date.now() + 60_000;
  let up = false;
  while (!up && Date.now() < deadline) {
    const response = await page.request.get("/ui");
    up = (await response.text()).includes('href="/ui/backends/e2e-open"');
    if (!up) await page.waitForTimeout(1_000);
  }
  expect(
    up,
    "the shared backend e2e-open never came up: is `just axon-oidc-backend` running on 127.0.0.1:3003?",
  ).toBe(true);
});
