import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { credentials, fixtureSnapshot, loginAs, resetFixture, useReducedMotion } from "./support";

test.beforeEach(async ({ page }) => {
  await resetFixture();
  await useReducedMotion(page);
});

test("anonymous access redirects and temporary credentials force a password change", async ({ page }) => {
  await page.goto("/overview");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();

  await loginAs(page, "temporary");
  await expect(page.getByRole("heading", { name: "Choose a permanent password" })).toBeVisible();
  const permanentPassword = "Permanent-password-2026!";
  await page.getByLabel("New password", { exact: true }).fill(permanentPassword);
  await page.getByLabel("Confirm new password").fill(permanentPassword);
  await page.getByRole("button", { name: "Save password and continue" }).click();
  await page.waitForURL("**/overview");
  await expect(page.getByRole("heading", { name: "Network overview" })).toBeVisible();

  const snapshot = await fixtureSnapshot();
  const serialized = JSON.stringify(snapshot);
  expect(serialized).not.toContain(credentials.temporary.password);
  expect(serialized).not.toContain(permanentPassword);
  expect(snapshot.requests.some((record) => record.path === "/api/v1/auth/change-password" && record.body !== null)).toBe(true);
});

test("the fixture enforces mutation framing and leaves unknown routes explicit", async ({ page }) => {
  const publicOrigin = "https://127.0.0.1:3443";
  const missingOrigin = await page.request.post("/api/v1/auth/login", {
    data: credentials.viewer,
    headers: { "Idempotency-Key": "missing-origin" },
  });
  expect(missingOrigin.status()).toBe(403);
  expect((await missingOrigin.json()).error.code).toBe("origin_forbidden");

  const missingIdempotency = await page.request.post("/api/v1/auth/login", {
    data: credentials.viewer,
    headers: { Origin: publicOrigin },
  });
  expect(missingIdempotency.status()).toBe(400);
  expect((await missingIdempotency.json()).error.code).toBe("idempotency_required");

  const unmatched = await page.request.get("/api/v1/not-a-route");
  expect(unmatched.status()).toBe(401);
  await loginAs(page, "viewer");
  const authenticatedUnmatched = await page.request.get("/api/v1/not-a-route");
  expect(authenticatedUnmatched.status()).toBe(501);
});

test("Next preview compatibility cookies are rejected before routing", async ({ context, page }) => {
  const manifest = JSON.parse(
    await readFile(new URL("../../.next/prerender-manifest.json", import.meta.url), "utf8"),
  ) as { preview?: { previewModeId?: unknown } };
  expect(typeof manifest.preview?.previewModeId).toBe("string");
  await context.addCookies([{
    name: "__prerender_bypass",
    value: manifest.preview?.previewModeId as string,
    url: "https://127.0.0.1:3443",
    secure: true,
  }]);

  const rejected = await page.goto("/login");
  expect(rejected?.status()).toBe(400);
  await expect(page.locator("body")).toContainText("preview modes are unavailable");
  expect((await context.cookies()).some((cookie) => cookie.name === "__prerender_bypass")).toBe(false);

  const recovered = await page.goto("/login");
  expect(recovered?.status()).toBe(200);
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});

test("viewer navigation exposes read models but no privileged controls", async ({ page }) => {
  await loginAs(page, "viewer");
  await expect(page.getByRole("heading", { name: "Network overview" })).toBeVisible();
  const navigation = page.getByRole("navigation");
  const rail = page.getByRole("complementary", { name: "Primary navigation" });
  for (const name of ["Overview", "VNRs", "Nodes", "Topology", "Activity", "Sessions"]) {
    await expect(navigation.getByRole("link", { name })).toBeVisible();
  }
  await expect(rail.getByRole("link", { name: "Settings" })).toBeVisible();
  await expect(navigation.getByRole("link", { name: "Users" })).toHaveCount(0);

  await navigation.getByRole("link", { name: "VNRs" }).click();
  await expect(page.getByRole("heading", { name: "Virtual network ranges" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create VNR" })).toHaveCount(0);

  await navigation.getByRole("link", { name: "Nodes" }).click();
  await expect(page.getByRole("heading", { name: "Nodes", exact: true, level: 2 })).toBeVisible();
  await expect(page.getByRole("button", { name: "Add Node" })).toHaveCount(0);

  await rail.getByRole("link", { name: "Settings" }).click();
  await expect(page.getByRole("heading", { name: "Settings", exact: true, level: 2 })).toBeVisible();
  await expect(page.getByRole("button", { name: "Edit settings" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Service control" })).toHaveCount(0);
});
