import { expect, test } from "@playwright/test";
import { fixtureSnapshot, loginAs, resetFixture, useReducedMotion } from "./support";

test.beforeEach(async ({ page }) => {
  await resetFixture();
  await useReducedMotion(page);
});

test("operator creates inventory and starts a bounded connectivity check", async ({ page }) => {
  await loginAs(page, "operator");
  await page.getByRole("link", { name: "VNRs" }).click();
  await page.getByRole("button", { name: "Create VNR" }).click();
  await page.getByLabel("Name").fill("e2e-lab");
  await page.getByLabel("IPv4 CIDR").fill("10.77.0.0/24");
  await page.getByRole("button", { name: "Create VNR", exact: true }).click();
  await page.waitForURL("**/vnrs/e2e-lab");
  await expect(page.getByRole("heading", { name: "e2e-lab" })).toBeVisible();
  await expect(page.getByText("10.77.0.0/24", { exact: true })).toBeVisible();

  await page.getByRole("link", { name: "Activity" }).click();
  await page.getByRole("tab", { name: "Connectivity checks" }).click();
  await page.getByRole("button", { name: "Run check" }).click();
  await page.getByLabel("Timeout in milliseconds").fill("1200");
  await page.getByRole("button", { name: "Start check" }).click();
  await expect(page.getByText("queued", { exact: true })).toBeVisible();

  const snapshot = await fixtureSnapshot();
  expect(snapshot.counts.vnrs).toBe(3);
  expect(snapshot.counts.checks).toBe(2);
  const mutations = snapshot.requests.filter((record) => record.method === "POST" && ["/api/v1/vnrs", "/api/v1/connectivity-checks"].includes(record.path));
  expect(mutations).toHaveLength(2);
  for (const mutation of mutations) {
    expect(mutation.headers.origin).toBe("https://127.0.0.1:3443");
    expect(mutation.headers["x-csrf-token"]).toBe("<redacted>");
    expect(mutation.headers["idempotency-key"]).toBe("<redacted>");
  }
});

test("resource updates require a fresh If-Match precondition", async ({ page }) => {
  await loginAs(page, "operator");
  const auth = await (await page.request.get("/api/v1/auth/me")).json();
  const common = {
    Origin: "https://127.0.0.1:3443",
    "X-CSRF-Token": auth.csrfToken as string,
  };
  const missing = await page.request.patch("/api/v1/vnrs/berlin-edge", {
    data: { cidr: "10.44.0.0/24" },
    headers: common,
  });
  expect(missing.status()).toBe(428);
  expect((await missing.json()).error.code).toBe("precondition_required");

  const stale = await page.request.patch("/api/v1/vnrs/berlin-edge", {
    data: { cidr: "10.44.0.0/24" },
    headers: { ...common, "If-Match": '"stale"' },
  });
  expect(stale.status()).toBe(412);
  expect((await stale.json()).error.code).toBe("precondition_failed");
});
