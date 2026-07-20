import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import { fixtureSnapshot, loginAs, resetFixture, useReducedMotion } from "./support";

test.beforeEach(async ({ page }) => {
  await resetFixture();
  await useReducedMotion(page);
});

test("superuser provisions a one-time account secret without fixture-log exposure", async ({ page }) => {
  await loginAs(page, "superuser");
  await page.getByRole("link", { name: "Users" }).click();
  await expect(page.getByRole("heading", { name: "Management users" })).toBeVisible();
  await page.getByRole("button", { name: "Add user" }).click();
  await page.getByLabel("Username").fill("e2e-viewer");
  await page.getByRole("button", { name: "Create user" }).click();
  await expect(page.getByRole("heading", { name: "Temporary password generated" })).toBeVisible();
  const secret = await page.getByRole("textbox", { name: "e2e-viewer", exact: true }).inputValue();
  expect(secret).toMatch(/^ntip-temp-/);

  const downloadStarted = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download" }).click();
  const download = await downloadStarted;
  const path = await download.path();
  expect(path).not.toBeNull();
  expect(await readFile(path!, "utf8")).toContain(secret);

  const snapshot = await fixtureSnapshot();
  expect(snapshot.counts.users).toBe(5);
  expect(JSON.stringify(snapshot)).not.toContain(secret);
  await page.getByRole("button", { name: "I stored it securely" }).click();
  await expect(page.getByText("e2e-viewer", { exact: true })).toBeVisible();
});

test("superuser reviews all sessions and revokes another browser session", async ({ page }) => {
  await loginAs(page, "superuser");
  await page.getByRole("link", { name: "Sessions" }).click();
  await page.getByRole("tab", { name: "All users" }).click();
  await expect(page.getByText("Firefox fixture", { exact: true })).toBeVisible();
  const operatorRow = page.getByRole("row").filter({ hasText: "Firefox fixture" });
  await operatorRow.getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByRole("heading", { name: "Revoke web session" })).toBeVisible();
  await page.getByRole("button", { name: "Revoke session" }).click();
  await expect(page.getByRole("heading", { name: "Revoke web session" })).toHaveCount(0);
});

test("superuser commits settings and accepts audited service restart", async ({ page }) => {
  await loginAs(page, "superuser");
  await page.getByRole("link", { name: "Settings" }).click();
  await expect(page.getByRole("heading", { name: "Settings", exact: true, level: 2 })).toBeVisible();
  await page.getByRole("button", { name: "Edit settings" }).click();
  await page.getByLabel("Inner MTU").fill("1320");
  await page.getByLabel("Confirm your password").fill("superuser-password-2026");
  await page.getByLabel("Type settings").fill("settings");
  await page.getByRole("button", { name: "Commit revision" }).click();
  await expect(page.getByRole("heading", { name: /Revision #3 committed/ })).toBeVisible();
  await page.getByRole("button", { name: "Done" }).click();

  await page.getByRole("button", { name: "Restart service" }).click();
  await expect(page.getByRole("heading", { name: "Restart NTIP service" })).toBeVisible();
  await page.getByLabel("Confirm your password").fill("superuser-password-2026");
  await page.getByLabel("Type restart").fill("restart");
  await page.getByRole("button", { name: "Restart service", exact: true }).click();
  await expect(page.getByText("Restart accepted", { exact: true })).toBeVisible();
  // The fixture forces readiness failures, and the component can only publish
  // recovery after observing one. Do not race the intentionally transient
  // intermediate notice on a fast local runner.
  await expect(page.getByText("Service recovered", { exact: true })).toBeVisible({ timeout: 10_000 });

  await page.getByRole("button", { name: "Shutdown service" }).click();
  await expect(page.getByRole("heading", { name: "Shut down NTIP service" })).toBeVisible();
  await page.getByLabel("Confirm your password").fill("superuser-password-2026");
  await page.getByLabel("Type shutdown").fill("shutdown");
  await page.getByRole("button", { name: "Shut down service" }).click();
  await expect(page.getByText("Shutdown accepted", { exact: true })).toBeVisible();

  const snapshot = await fixtureSnapshot();
  const settingsMutation = snapshot.requests.find((record) => record.method === "PATCH" && record.path === "/api/v1/settings");
  const restartMutation = snapshot.requests.find((record) => record.method === "POST" && record.path === "/api/v1/operations/restart");
  const shutdownMutation = snapshot.requests.find((record) => record.method === "POST" && record.path === "/api/v1/operations/shutdown");
  expect(settingsMutation?.headers["if-match"]).toMatch(/^"settings:/);
  expect(restartMutation?.headers["if-match"]).toMatch(/^"service:/);
  expect(restartMutation?.headers["idempotency-key"]).toBe("<redacted>");
  expect(shutdownMutation?.headers["if-match"]).toMatch(/^"service:/);
  expect(shutdownMutation?.headers["idempotency-key"]).toBe("<redacted>");
});
