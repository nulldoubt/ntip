import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { resolve } from "node:path";
import { clearFaults, fixtureSnapshot, loginAs, resetFixture, resetMetrics, setFault, useReducedMotion } from "./support";

test.beforeEach(async ({ page }) => {
  await resetFixture();
  await useReducedMotion(page);
});

test("activity polling retains stale data and never exceeds two background requests", async ({ page }) => {
  await loginAs(page, "operator");
  await page.getByRole("link", { name: "Activity", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Activity", exact: true, level: 2 })).toBeVisible();
  await resetMetrics();
  await setFault({ path: "/api/v1/events", status: 503, delayMilliseconds: 600, remaining: 1 });
  await setFault({ path: "/api/v1/connectivity-checks", delayMilliseconds: 600, remaining: 1 });
  await setFault({ path: "/api/v1/audit", delayMilliseconds: 600, remaining: 1 });
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByText("Injected fixture fault", { exact: true })).toBeVisible();
  await expect(page.getByText("london-relay moved from online to suspect", { exact: true })).toBeVisible();

  const snapshot = await fixtureSnapshot();
  expect(snapshot.maximumConcurrentRequests).toBe(2);
  await clearFaults();
});

test("the desktop guard switches exactly at 1024 pixels", async ({ page }) => {
  await loginAs(page, "viewer");
  await page.setViewportSize({ width: 1023, height: 900 });
  await expect(page.getByRole("heading", { name: "A desktop-sized window is required" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Network overview" })).toBeHidden();

  await page.setViewportSize({ width: 1024, height: 900 });
  await expect(page.getByRole("heading", { name: "A desktop-sized window is required" })).toBeHidden();
  await expect(page.getByRole("heading", { name: "Network overview" })).toBeVisible();
});

test("topology keyboard inspection and its table expose equivalent relationships", async ({ page }) => {
  await loginAs(page, "viewer");
  await page.getByRole("link", { name: "Topology" }).click();
  await expect(page.getByRole("heading", { name: "Topology", exact: true, level: 2 })).toBeVisible();
  const mapEntity = page.locator('[data-topology-entity][aria-label="node: berlin-gateway"]');
  await mapEntity.focus();
  await mapEntity.press("Enter");
  await expect(page.locator("#inspector-title")).toHaveText("berlin-gateway");

  const table = page.getByRole("region", { name: "Accessible topology table" });
  for (const value of ["berlin-edge", "london-core", "berlin-gateway", "london-relay", "warehouse-sensor", "192.0.2.0/24"]) {
    await expect(table.getByText(value).first()).toBeVisible();
  }
  const warehouseRow = table.getByRole("row").filter({ hasText: "warehouse-sensor" });
  await warehouseRow.focus();
  await warehouseRow.press("Enter");
  await expect(page.locator("#inspector-title")).toHaveText("warehouse-sensor");
});

test("login and authenticated overview pass WCAG 2.2 AA automated checks", async ({ page }) => {
  await page.goto("/login");
  let results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(results.violations).toEqual([]);

  await loginAs(page, "viewer");
  results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(results.violations).toEqual([]);
});

test("captures approved Direction A overview evidence in light and dark modes", async ({ page }) => {
  await loginAs(page, "viewer");
  await page.setViewportSize({ width: 1440, height: 900 });
  const theme = page.getByRole("button", { name: /^Theme:/ });
  await theme.click();
  await expect(theme).toHaveAccessibleName("Theme: light. Switch to dark.");
  await page.screenshot({
    path: resolve(import.meta.dirname, "../../../../output/playwright/direction-a-overview-light.png"),
    animations: "disabled",
    fullPage: true,
  });
  await theme.click();
  await expect(theme).toHaveAccessibleName("Theme: dark. Switch to system.");
  await page.screenshot({
    path: resolve(import.meta.dirname, "../../../../output/playwright/direction-a-overview-dark.png"),
    animations: "disabled",
    fullPage: true,
  });
});
