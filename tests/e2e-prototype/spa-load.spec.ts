import { test, expect } from "@playwright/test";

// Trivial page-load: proves the SPA is served through the Aspire app tier on the runner.
test("SPA serves the landing page", async ({ page }) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "authn-authz walking skeleton" }).first(),
  ).toBeVisible();
});
