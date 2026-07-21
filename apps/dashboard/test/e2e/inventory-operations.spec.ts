import AxeBuilder from "@axe-core/playwright";
import { expect, test, type APIResponse, type Page } from "@playwright/test";
import { clearFaults, credentials, fixtureSnapshot, loginAs, resetFixture, setFault, useReducedMotion } from "./support";

const publicOrigin = "https://127.0.0.1:3443";

async function expectViolation(
  response: APIResponse,
  expected: Readonly<{ status: number; errorCode: string; field: string; violationCode: string }>,
): Promise<void> {
  expect(response.status()).toBe(expected.status);
  const payload = await response.json() as {
    error: { code: string; violations?: Array<{ field: string; code: string; message: string }> };
  };
  expect(payload.error.code).toBe(expected.errorCode);
  expect(payload.error.violations).toEqual([
    expect.objectContaining({ field: expected.field, code: expected.violationCode }),
  ]);
}

function requireResponseHeader(response: APIResponse, name: string): string {
  const value = response.headers()[name.toLowerCase()];
  if (value === undefined) throw new Error(`Expected response header ${name}`);
  return value;
}

async function selectSegment(page: Page, label: string, value: number): Promise<void> {
  await page.getByRole("combobox", { name: label, exact: true }).click();
  await page.getByRole("option", { name: String(value), exact: true }).click();
}

async function reauthenticateFixtureSession(page: Page, idempotencyKey: string): Promise<string> {
  const auth = await (await page.request.get("/api/v1/auth/me")).json() as { csrfToken: string };
  const response = await page.request.post("/api/v1/auth/reauth", {
    data: { password: credentials.superuser.password },
    headers: {
      Origin: publicOrigin,
      "X-CSRF-Token": auth.csrfToken,
      "Idempotency-Key": idempotencyKey,
    },
  });
  expect(response.status()).toBe(200);
  return auth.csrfToken;
}

test.beforeEach(async ({ page }) => {
  await resetFixture();
  await useReducedMotion(page);
});

test("operator creates inventory and starts a bounded connectivity check", async ({ page }) => {
  await loginAs(page, "operator");
  await page.getByRole("link", { name: "VNRs" }).click();
  await page.getByRole("button", { name: "Create VNR" }).click();
  await page.getByLabel("Name").fill("e2e-lab");
  await selectSegment(page, "VNR IPv4 CIDR, octet 1 of 4", 10);
  await selectSegment(page, "VNR IPv4 CIDR, octet 2 of 4", 77);
  await expect(page.getByRole("combobox", { name: "VNR IPv4 CIDR, octet 3 of 4" })).toBeEnabled();
  await expect(page.getByRole("combobox", { name: "VNR IPv4 CIDR, octet 4 of 4" })).toBeDisabled();
  await expect(page.getByRole("combobox", { name: "VNR IPv4 CIDR, prefix length" })).toHaveText("24");
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

test("operator selects a canonical route prefix with fixed and selectable octets", async ({ page }) => {
  await loginAs(page, "operator");
  await page.getByRole("link", { name: "Nodes", exact: true }).click();
  await page.getByRole("link", { name: "berlin-gateway", exact: true }).click();
  await page.getByRole("button", { name: "Add route" }).click();

  await selectSegment(page, "Route IPv4 prefix, octet 1 of 4", 198);
  await selectSegment(page, "Route IPv4 prefix, octet 2 of 4", 51);
  await selectSegment(page, "Route IPv4 prefix, octet 3 of 4", 100);
  await selectSegment(page, "Route IPv4 prefix, prefix length", 24);
  await expect(page.getByRole("combobox", { name: "Route IPv4 prefix, octet 3 of 4" })).toBeEnabled();
  await expect(page.getByRole("combobox", { name: "Route IPv4 prefix, octet 4 of 4" })).toBeDisabled();

  const dialog = page.getByRole("dialog", { name: "Add route" });
  await dialog.getByRole("button", { name: "Add route", exact: true }).click();
  await expect(page.getByText("198.51.100.0/24", { exact: true })).toBeVisible();
  expect((await fixtureSnapshot()).counts.routes).toBe(2);
});

test("Node creation selects the lowest free address and recovers from an allocation race", async ({ page }) => {
  await loginAs(page, "operator");
  await page.getByRole("link", { name: "Nodes", exact: true }).click();
  await page.getByRole("button", { name: "Add Node" }).click();
  const dialog = page.getByRole("dialog", { name: "Create Node" });

  await expect(dialog.getByText("Ask a superuser to open the new Node and generate its setup code.", { exact: false })).toBeVisible();

  await expect(dialog.getByRole("combobox", { name: "VNR" })).toHaveText(/berlin-edge/);
  await expect(dialog.getByRole("combobox", { name: "Node IPv4 address, octet 1 of 4" })).toBeDisabled();
  await expect(dialog.getByRole("combobox", { name: "Node IPv4 address, octet 2 of 4" })).toBeDisabled();
  await expect(dialog.getByRole("combobox", { name: "Node IPv4 address, octet 3 of 4" })).toBeDisabled();
  const hostOctet = dialog.getByRole("combobox", { name: "Node IPv4 address, octet 4 of 4" });
  await expect(hostOctet).toBeEnabled();
  await expect(hostOctet).toHaveText("3");
  await expect(dialog.getByText("10.42.0.3 is the current lowest compatible free address.")).toBeVisible();
  await dialog.getByLabel("Name").fill("race-loser");

  const auth = await (await page.request.get("/api/v1/auth/me")).json() as { csrfToken: string };
  const winner = await page.request.post("/api/v1/nodes", {
    data: { name: "race-winner", address: "10.42.0.3", vnrName: "berlin-edge" },
    headers: {
      Origin: publicOrigin,
      "X-CSRF-Token": auth.csrfToken,
      "Idempotency-Key": "inventory-e2e-race-winner",
    },
  });
  expect(winner.status()).toBe(201);

  await dialog.getByRole("button", { name: "Create Node", exact: true }).click();
  await expect(dialog.getByRole("alert").filter({
    hasText: "Address 10.42.0.3 was allocated concurrently. The selection moved to 10.42.0.4; review it and submit again.",
  })).toBeVisible();
  await expect(dialog.getByText("10.42.0.4 is the current lowest compatible free address.")).toBeVisible();
  await expect(hostOctet).toHaveText("4");

  await dialog.getByRole("button", { name: "Create Node", exact: true }).click();
  await page.waitForURL("**/nodes/*");
  await expect(page.getByRole("heading", { name: "race-loser" })).toBeVisible();
  await expect(page.getByText("10.42.0.4", { exact: true })).toBeVisible();

  const snapshot = await fixtureSnapshot();
  expect(snapshot.counts.nodes).toBe(5);
  const nodeMutations = snapshot.requests.filter((record) =>
    record.method === "POST" && record.path === "/api/v1/nodes"
  );
  expect(nodeMutations.map((record) => record.body)).toEqual([
    expect.objectContaining({ name: "race-winner", address: "10.42.0.3" }),
    expect.objectContaining({ name: "race-loser", address: "10.42.0.3" }),
    expect.objectContaining({ name: "race-loser", address: "10.42.0.4" }),
  ]);
});

test("superuser creates, safeguards, replaces, and revokes a one-time Node setup invitation", async ({ page }) => {
  await loginAs(page, "superuser");
  await page.getByRole("link", { name: "Nodes", exact: true }).click();
  await page.getByRole("button", { name: "Add Node" }).click();
  const createDialog = page.getByRole("dialog", { name: "Create Node" });
  await expect(createDialog.getByRole("combobox", { name: "VNR" })).toHaveText(/berlin-edge/);
  await createDialog.getByLabel("Name", { exact: true }).fill("bootstrap-lab");
  await createDialog.getByLabel("Current password").fill(credentials.superuser.password);
  await createDialog.getByLabel("Type “bootstrap-lab”").fill("bootstrap-lab");
  await createDialog.getByRole("button", { name: "Create Node and setup code" }).click();

  await expect(createDialog.getByRole("heading", { name: "Install bootstrap-lab" })).toBeFocused();
  const command = createDialog.getByLabel("Installation command; select to copy manually");
  await expect(command).toHaveValue(/--http1\.1/);
  await expect(command).toHaveValue(/--pinnedpubkey/);
  await expect(command).toHaveValue(/\/enrollment\//);
  await expect(command).not.toHaveValue(/ABC-DEF-GHJ/);
  const secretCode = createDialog.getByLabel("Secret setup code; select to copy manually");
  await expect(secretCode).toHaveValue("ABC-DEF-GHJ");

  await page.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: async () => { throw new DOMException("denied", "NotAllowedError"); } },
    });
  });
  await createDialog.getByRole("button", { name: "Copy command" }).click();
  await expect(createDialog.getByText(
    "Clipboard access was unavailable. Select the command manually.",
    { exact: true },
  )).toBeAttached();
  await command.focus();
  expect(await command.evaluate((element) => {
    if (!(element instanceof HTMLTextAreaElement)) throw new Error("Expected a command textarea");
    return [element.selectionStart, element.selectionEnd, element.value.length];
  })).toEqual([0, (await command.inputValue()).length, (await command.inputValue()).length]);
  await secretCode.focus();
  expect(await secretCode.evaluate((element) => {
    if (!(element instanceof HTMLInputElement)) throw new Error("Expected a setup-code input");
    return [element.selectionStart, element.selectionEnd, element.value.length];
  })).toEqual([0, 11, 11]);
  const accessibility = await new AxeBuilder({ page })
    .include('[role="dialog"]')
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(accessibility.violations).toEqual([]);

  await page.keyboard.press("Escape");
  await expect(createDialog).toBeVisible();
  await createDialog.getByLabel("I saved it securely.").check();
  await createDialog.getByRole("button", { name: "Done" }).click();
  await page.waitForURL("**/nodes/*");
  await expect(page.getByRole("heading", { name: "bootstrap-lab" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Generate replacement code" })).toBeVisible();

  await page.getByRole("button", { name: "Generate replacement code" }).click();
  const replacementDialog = page.getByRole("dialog", { name: "Generate replacement code" });
  await replacementDialog.getByLabel("Current password").fill(credentials.superuser.password);
  await replacementDialog.getByLabel("Type “bootstrap-lab”").fill("bootstrap-lab");
  await replacementDialog.getByRole("button", { name: "Generate replacement code", exact: true }).click();
  await expect(replacementDialog.getByLabel("Secret setup code; select to copy manually")).toHaveValue("ABC-DEF-GHJ");
  await setFault({ path: `/api/v1/nodes/${page.url().split("/").at(-1)}/enrollment-bootstrap`, status: 503 });
  await replacementDialog.getByRole("button", { name: "Discard and revoke" }).click();
  await expect(replacementDialog).toBeVisible();
  await expect(replacementDialog.getByRole("alert")).toContainText("dialog remains open");
  await clearFaults();
  await replacementDialog.getByRole("button", { name: "Discard and revoke" }).click();
  await expect(replacementDialog).toBeHidden();
  await expect(page.getByRole("button", { name: "Generate setup code" })).toBeVisible();

  const snapshot = await fixtureSnapshot();
  expect(JSON.stringify(snapshot)).not.toContain("ABC-DEF-GHJ");
  expect(snapshot.requests.some((record) => record.method === "POST" && record.path === "/api/v1/nodes/actions/bootstrap")).toBe(true);
  expect(snapshot.requests.some((record) => record.method === "DELETE" && record.path.endsWith("/enrollment-bootstrap"))).toBe(true);
});

test("a lost one-time creation response finds the committed Node without duplicating it", async ({ page }) => {
  await loginAs(page, "superuser");
  await page.getByRole("link", { name: "Nodes", exact: true }).click();
  await page.getByRole("button", { name: "Add Node" }).click();
  const dialog = page.getByRole("dialog", { name: "Create Node" });
  await expect(dialog.getByRole("combobox", { name: "VNR" })).toHaveText(/berlin-edge/);
  await dialog.getByLabel("Name", { exact: true }).fill("lost-response-node");
  await dialog.getByLabel("Current password").fill(credentials.superuser.password);
  await dialog.getByLabel("Type “lost-response-node”").fill("lost-response-node");
  await setFault({ path: "/api/v1/nodes/actions/bootstrap", status: 503, afterRoute: true });
  await dialog.getByRole("button", { name: "Create Node and setup code" }).click();

  await expect(dialog.getByRole("alert")).toContainText("the one-time setup response did not reach this browser");
  await expect(dialog.getByText("No duplicate was created.", { exact: false })).toBeVisible();
  await expect(dialog.getByLabel("Secret setup code; select to copy manually")).toHaveCount(0);
  const snapshot = await fixtureSnapshot();
  expect(snapshot.counts.nodes).toBe(4);
  expect(snapshot.requests.filter((record) => record.method === "POST" && record.path === "/api/v1/nodes/actions/bootstrap")).toHaveLength(1);

  await dialog.getByRole("button", { name: "Open Node" }).click();
  await page.waitForURL("**/nodes/*");
  await expect(page.getByRole("heading", { name: "lost-response-node" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Generate replacement code" })).toBeVisible();
});

test("a pre-dispatch reauthentication failure does not claim that Node creation may have committed", async ({ page }) => {
  await loginAs(page, "superuser");
  await page.getByRole("link", { name: "Nodes", exact: true }).click();
  await page.getByRole("button", { name: "Add Node" }).click();
  const dialog = page.getByRole("dialog", { name: "Create Node" });
  await expect(dialog.getByRole("combobox", { name: "VNR" })).toHaveText(/berlin-edge/);
  await dialog.getByLabel("Name", { exact: true }).fill("reauth-failure-node");
  await dialog.getByLabel("Current password").fill("definitely-not-valid-2026");
  await dialog.getByLabel("Type “reauth-failure-node”").fill("reauth-failure-node");
  await dialog.getByRole("button", { name: "Create Node and setup code" }).click();

  await expect(dialog.getByRole("status").filter({ hasText: "The password was not accepted." })).toBeVisible();
  await expect(dialog.getByText("one-time setup response did not reach", { exact: false })).toHaveCount(0);
  const snapshot = await fixtureSnapshot();
  expect(snapshot.counts.nodes).toBe(3);
  expect(snapshot.requests.filter((record) =>
    record.method === "POST" && record.path === "/api/v1/nodes/actions/bootstrap"
  )).toHaveLength(0);
});

test("aborted bootstrap-config reads cannot overwrite newer dialog generations", async ({ page }) => {
  await loginAs(page, "superuser");
  await page.getByRole("link", { name: "Nodes", exact: true }).click();
  await setFault({
    path: "/api/v1/enrollment/bootstrap-config",
    status: 503,
    delayMilliseconds: 700,
    remaining: 1,
  });

  await page.getByRole("button", { name: "Add Node" }).click();
  let dialog = page.getByRole("dialog", { name: "Create Node" });
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await page.getByRole("button", { name: "Add Node" }).click();
  dialog = page.getByRole("dialog", { name: "Create Node" });
  await expect(dialog.getByRole("combobox", { name: "VNR" })).toHaveText(/berlin-edge/);
  await dialog.getByLabel("Name", { exact: true }).fill("config-generation-node");
  await dialog.getByLabel("Current password").fill(credentials.superuser.password);
  await dialog.getByLabel("Type “config-generation-node”").fill("config-generation-node");
  const submit = dialog.getByRole("button", { name: "Create Node and setup code" });
  await expect(submit).toBeEnabled();
  await page.waitForTimeout(900);
  await expect(submit).toBeEnabled();
  await expect(dialog.getByText("Setup invitation creation is disabled", { exact: false })).toHaveCount(0);

  await dialog.getByRole("button", { name: "Cancel" }).click();
  await page.getByRole("link", { name: "warehouse-sensor", exact: true }).click();
  await setFault({
    path: "/api/v1/enrollment/bootstrap-config",
    status: 503,
    delayMilliseconds: 700,
    remaining: 1,
  });
  await page.getByRole("button", { name: "Generate setup code" }).click();
  let setupDialog = page.getByRole("dialog", { name: "Generate setup code" });
  await setupDialog.getByRole("button", { name: "Cancel" }).click();
  await page.getByRole("button", { name: "Generate setup code" }).click();
  setupDialog = page.getByRole("dialog", { name: "Generate setup code" });
  await setupDialog.getByLabel("Current password").fill(credentials.superuser.password);
  await setupDialog.getByLabel("Type “warehouse-sensor”").fill("warehouse-sensor");
  const generate = setupDialog.getByRole("button", { name: "Generate setup code", exact: true });
  await expect(generate).toBeEnabled();
  await page.waitForTimeout(900);
  await expect(generate).toBeEnabled();
  await expect(setupDialog.getByText("Installer configuration could not be loaded", { exact: false })).toHaveCount(0);
});

test("one-time Node bootstrap mutations consume idempotency markers without redisclosing secrets", async ({ page }) => {
  await loginAs(page, "superuser");
  const csrfToken = await reauthenticateFixtureSession(page, "bootstrap-idempotency-reauth");
  const headers = (idempotencyKey: string, ifMatch?: string) => ({
    Origin: publicOrigin,
    "X-CSRF-Token": csrfToken,
    "Idempotency-Key": idempotencyKey,
    ...(ifMatch === undefined ? {} : { "If-Match": ifMatch }),
  });

  const createBody = {
    name: "idempotency-node",
    address: "10.42.0.3",
    vnrName: "berlin-edge",
    confirmation: "idempotency-node",
  };
  const createHeaders = headers("bootstrap-idempotency-create");
  const created = await page.request.post("/api/v1/nodes/actions/bootstrap", { data: createBody, headers: createHeaders });
  expect(created.status()).toBe(201);
  const createdDisclosure = await created.json() as { node: { id: string }; bootstrap: { secretCode: string } };
  expect(createdDisclosure.bootstrap.secretCode).toBe("ABC-DEF-GHJ");

  const createReplay = await page.request.post("/api/v1/nodes/actions/bootstrap", { data: createBody, headers: createHeaders });
  expect(createReplay.status()).toBe(409);
  expect((await createReplay.json()).error.code).toBe("conflict");
  expect(await createReplay.text().catch(() => "")).not.toContain("secretCode");
  const createChanged = await page.request.post("/api/v1/nodes/actions/bootstrap", {
    data: { ...createBody, address: "10.42.0.4" },
    headers: createHeaders,
  });
  expect(createChanged.status()).toBe(409);
  expect((await createChanged.json()).error.code).toBe("idempotency_conflict");

  const nodePath = `/api/v1/nodes/${createdDisclosure.node.id}`;
  const nodeRead = await page.request.get(nodePath);
  const replacementHeaders = headers("bootstrap-idempotency-replacement", requireResponseHeader(nodeRead, "ETag"));
  const confirmation = { confirmation: "idempotency-node" };
  const replacementPath = `${nodePath}/enrollment-bootstrap`;
  const replacement = await page.request.post(replacementPath, { data: confirmation, headers: replacementHeaders });
  expect(replacement.status()).toBe(200);
  const replacementReplay = await page.request.post(replacementPath, { data: confirmation, headers: replacementHeaders });
  expect(replacementReplay.status()).toBe(409);
  expect((await replacementReplay.json()).error.code).toBe("conflict");
  expect(await replacementReplay.text().catch(() => "")).not.toContain("secretCode");
  const replacementChanged = await page.request.post(replacementPath, {
    data: { confirmation: "different-node" },
    headers: replacementHeaders,
  });
  expect(replacementChanged.status()).toBe(409);
  expect((await replacementChanged.json()).error.code).toBe("idempotency_conflict");

  const enrolledPath = "/api/v1/nodes/01000000000000000000000000000001";
  const enrolledRead = await page.request.get(enrolledPath);
  const resetHeaders = headers("bootstrap-idempotency-reset", requireResponseHeader(enrolledRead, "ETag"));
  const resetPath = `${enrolledPath}/actions/reset-enrollment`;
  const reset = await page.request.post(resetPath, { data: { confirmation: "berlin-gateway" }, headers: resetHeaders });
  expect(reset.status()).toBe(200);
  const resetReplay = await page.request.post(resetPath, { data: { confirmation: "berlin-gateway" }, headers: resetHeaders });
  expect(resetReplay.status()).toBe(409);
  expect((await resetReplay.json()).error.code).toBe("conflict");
  expect(await resetReplay.text().catch(() => "")).not.toContain("secretCode");

  const changedEnrolledRead = await page.request.get(enrolledPath);
  const invalidSecondReset = await page.request.post(resetPath, {
    data: { confirmation: "berlin-gateway" },
    headers: headers("bootstrap-idempotency-reset-again", requireResponseHeader(changedEnrolledRead, "ETag")),
  });
  expect(invalidSecondReset.status()).toBe(409);
  expect((await invalidSecondReset.json()).error.code).toBe("conflict");
});

test("superuser resets an enrolled Node directly into a new setup invitation", async ({ page }) => {
  await loginAs(page, "superuser");
  await page.getByRole("link", { name: "Nodes", exact: true }).click();
  await page.getByRole("link", { name: "berlin-gateway", exact: true }).click();
  await page.getByRole("button", { name: "Reset enrollment and generate setup code" }).click();
  const dialog = page.getByRole("dialog", { name: "Reset enrollment and generate setup code" });
  await dialog.getByLabel("Current password").fill(credentials.superuser.password);
  await dialog.getByLabel("Type “berlin-gateway”").fill("berlin-gateway");
  await dialog.getByRole("button", { name: "Reset enrollment and generate setup code", exact: true }).click();
  await expect(dialog.getByLabel("Secret setup code; select to copy manually")).toHaveValue("ABC-DEF-GHJ");
  await dialog.getByLabel("I saved it securely.").check();
  await dialog.getByRole("button", { name: "Done" }).click();
  await expect(page.getByRole("button", { name: "Generate replacement code" })).toBeVisible();

  const reset = (await fixtureSnapshot()).requests.find((record) =>
    record.method === "POST" && record.path.endsWith("/actions/reset-enrollment")
  );
  expect(reset?.body).toEqual({ confirmation: "berlin-gateway" });
});

test("setup confirmation refuses a Node whose enrollment intent changed while the dialog was open", async ({ page }) => {
  await loginAs(page, "superuser");
  await page.getByRole("link", { name: "Nodes", exact: true }).click();
  await page.getByRole("link", { name: "berlin-gateway", exact: true }).click();
  await page.getByRole("button", { name: "Reset enrollment and generate setup code" }).click();
  const dialog = page.getByRole("dialog", { name: "Reset enrollment and generate setup code" });
  await expect(dialog.getByLabel("Current password")).toBeVisible();

  const csrfToken = await reauthenticateFixtureSession(page, "bootstrap-intent-reauth");
  const nodePath = "/api/v1/nodes/01000000000000000000000000000001";
  const nodeRead = await page.request.get(nodePath);
  const directReset = await page.request.post(`${nodePath}/actions/reset-enrollment`, {
    data: { confirmation: "berlin-gateway" },
    headers: {
      Origin: publicOrigin,
      "X-CSRF-Token": csrfToken,
      "Idempotency-Key": "bootstrap-intent-direct-reset",
      "If-Match": requireResponseHeader(nodeRead, "ETag"),
    },
  });
  expect(directReset.status()).toBe(200);

  await dialog.getByLabel("Current password").fill(credentials.superuser.password);
  await dialog.getByLabel("Type “berlin-gateway”").fill("berlin-gateway");
  await dialog.getByRole("button", { name: "Reset enrollment and generate setup code", exact: true }).click();
  await expect(dialog.getByRole("status").filter({
    hasText: "The Node changed while this confirmation was open",
  })).toBeVisible();
  await expect(dialog.getByLabel("Secret setup code; select to copy manually")).toHaveCount(0);
  expect((await fixtureSnapshot()).requests.filter((record) =>
    record.method === "POST" && record.path.endsWith("/actions/reset-enrollment")
  )).toHaveLength(1);
});

test("Node editing moves VNR membership onto the destination's lowest free address", async ({ page }) => {
  await loginAs(page, "operator");
  await page.getByRole("link", { name: "Nodes", exact: true }).click();
  await page.getByRole("link", { name: "berlin-gateway", exact: true }).click();
  await page.getByRole("button", { name: "Edit Node" }).click();
  const dialog = page.getByRole("dialog", { name: "Edit berlin-gateway" });

  await expect(dialog.getByRole("combobox", { name: "VNR" })).toHaveText(/berlin-edge/);
  await expect(dialog.getByRole("combobox", { name: "Node IPv4 address, octet 1 of 4" })).toBeDisabled();
  await expect(dialog.getByRole("combobox", { name: "Node IPv4 address, octet 2 of 4" })).toBeDisabled();
  await expect(dialog.getByRole("combobox", { name: "Node IPv4 address, octet 3 of 4" })).toBeDisabled();
  await expect(dialog.getByRole("combobox", { name: "Node IPv4 address, octet 4 of 4" })).toHaveText("2");

  await dialog.getByRole("combobox", { name: "VNR" }).click();
  await page.getByRole("option", { name: /^london-core/ }).click();
  await expect(dialog.getByRole("combobox", { name: "Node IPv4 address, octet 2 of 4" })).toHaveText("43");
  await expect(dialog.getByRole("combobox", { name: "Node IPv4 address, octet 4 of 4" })).toHaveText("3");
  await expect(dialog.getByRole("status").filter({
    hasText: "Moving this Node to london-core retires its current association. Address 10.43.0.3 is selected as the destination VNR’s lowest free host.",
  })).toBeVisible();

  await dialog.getByRole("button", { name: "Save changes" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByText("10.43.0.3", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "london-core", exact: true })).toBeVisible();

  const update = (await fixtureSnapshot()).requests.find((record) =>
    record.method === "PATCH" && record.path === "/api/v1/nodes/01000000000000000000000000000001"
  );
  expect(update?.body).toEqual({
    name: "berlin-gateway",
    address: "10.43.0.3",
    vnrName: "london-core",
  });
});

test("Node creation blocks safely when topology is unavailable or a VNR is exhausted", async ({ page }) => {
  await loginAs(page, "operator");
  const auth = await (await page.request.get("/api/v1/auth/me")).json() as { csrfToken: string };
  const mutationHeaders = (idempotencyKey: string) => ({
    Origin: publicOrigin,
    "X-CSRF-Token": auth.csrfToken,
    "Idempotency-Key": idempotencyKey,
  });
  expect((await page.request.post("/api/v1/vnrs", {
    data: { name: "exhausted-lab", cidr: "10.99.0.0/30" },
    headers: mutationHeaders("inventory-e2e-exhausted-vnr"),
  })).status()).toBe(201);
  expect((await page.request.post("/api/v1/nodes", {
    data: { name: "only-host", address: "10.99.0.2", vnrName: "exhausted-lab" },
    headers: mutationHeaders("inventory-e2e-exhausted-node"),
  })).status()).toBe(201);

  await page.getByRole("link", { name: "Nodes", exact: true }).click();
  await setFault({ path: "/api/v1/topology", status: 503, remaining: 1 });
  await page.getByRole("button", { name: "Add Node" }).click();
  let dialog = page.getByRole("dialog", { name: "Create Node" });
  await expect(dialog.getByText(
    "Address selection is unavailable until the topology can be loaded.",
    { exact: true },
  )).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Create Node", exact: true })).toBeDisabled();
  await dialog.getByRole("button", { name: "Cancel" }).click();

  await page.getByRole("button", { name: "Add Node" }).click();
  dialog = page.getByRole("dialog", { name: "Create Node" });
  await expect(dialog.getByRole("combobox", { name: "VNR" })).toHaveText(/berlin-edge/);
  await dialog.getByRole("combobox", { name: "VNR" }).click();
  await page.getByRole("option", { name: /^exhausted-lab/ }).click();
  await expect(dialog.getByText(
    "exhausted-lab has no free host address after reserving the network, Master, broadcast, and current Node allocations.",
    { exact: true },
  )).toBeVisible();
  for (let octet = 1; octet <= 4; octet += 1) {
    await expect(dialog.getByRole("combobox", { name: `Node IPv4 address, octet ${octet} of 4` })).toBeDisabled();
  }
  await expect(dialog.getByRole("button", { name: "Create Node", exact: true })).toBeDisabled();
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

test("fixture enforces canonical inventory ranges, address reservations, uniqueness, and dependencies", async ({ page }) => {
  await loginAs(page, "operator");
  const auth = await (await page.request.get("/api/v1/auth/me")).json() as { csrfToken: string };
  let mutationSequence = 0;
  const post = async (path: string, data: unknown): Promise<APIResponse> => {
    mutationSequence += 1;
    return page.request.post(path, {
      data,
      headers: {
        Origin: publicOrigin,
        "X-CSRF-Token": auth.csrfToken,
        "Idempotency-Key": `inventory-e2e-${mutationSequence.toString().padStart(4, "0")}`,
      },
    });
  };

  await expectViolation(await post("/api/v1/vnrs", { name: "bad-host-bits", cidr: "10.77.0.1/24" }), {
    status: 400,
    errorCode: "validation_failed",
    field: "cidr",
    violationCode: "noncanonical_ipv4_cidr",
  });
  await expectViolation(await post("/api/v1/vnrs", { name: "bad-prefix", cidr: "10.77.0.0/31" }), {
    status: 400,
    errorCode: "validation_failed",
    field: "cidr",
    violationCode: "prefix_out_of_range",
  });
  await expectViolation(await post("/api/v1/vnrs", { name: "reserved", cidr: "127.50.0.0/16" }), {
    status: 409,
    errorCode: "invariant_violation",
    field: "cidr",
    violationCode: "range_reserved",
  });
  await expectViolation(await post("/api/v1/vnrs", { name: "overlapping", cidr: "10.42.0.128/25" }), {
    status: 409,
    errorCode: "invariant_violation",
    field: "cidr",
    violationCode: "range_overlaps_vnr",
  });
  await expectViolation(await post("/api/v1/vnrs", { name: "route-overlap", cidr: "192.0.2.0/25" }), {
    status: 409,
    errorCode: "invariant_violation",
    field: "cidr",
    violationCode: "range_overlaps_route",
  });
  expect((await post("/api/v1/vnrs", { name: "berlin-edge", cidr: "10.90.0.0/24" })).status()).toBe(409);

  const berlinVnrRead = await page.request.get("/api/v1/vnrs/berlin-edge");
  await expectViolation(await page.request.patch("/api/v1/vnrs/berlin-edge", {
    data: { cidr: "10.42.0.0/29" },
    headers: {
      Origin: publicOrigin,
      "X-CSRF-Token": auth.csrfToken,
      "If-Match": requireResponseHeader(berlinVnrRead, "ETag"),
    },
  }), {
    status: 409,
    errorCode: "invariant_violation",
    field: "cidr",
    violationCode: "range_excludes_node",
  });

  await expectViolation(await post("/api/v1/nodes", {
    name: "invalid-address",
    address: "10.42.0.999",
    vnrName: "berlin-edge",
  }), {
    status: 400,
    errorCode: "validation_failed",
    field: "address",
    violationCode: "invalid_ipv4_address",
  });
  expect((await post("/api/v1/nodes", {
    name: "missing-membership",
    address: "10.99.0.2",
    vnrName: "absent-vnr",
  })).status()).toBe(400);

  await expectViolation(await post("/api/v1/nodes", {
    name: "outside-node",
    address: "10.99.0.2",
    vnrName: "berlin-edge",
  }), {
    status: 409,
    errorCode: "invariant_violation",
    field: "address",
    violationCode: "address_outside_vnr",
  });
  for (const [name, address, violationCode] of [
    ["network-node", "10.42.0.0", "address_reserved_network"],
    ["master-node", "10.42.0.1", "address_reserved_master"],
    ["broadcast-node", "10.42.0.255", "address_reserved_broadcast"],
  ] as const) {
    await expectViolation(await post("/api/v1/nodes", { name, address, vnrName: "berlin-edge" }), {
      status: 409,
      errorCode: "invariant_violation",
      field: "address",
      violationCode,
    });
  }
  await expectViolation(await post("/api/v1/nodes", {
    name: "duplicate-address",
    address: "10.42.0.2",
    vnrName: "berlin-edge",
  }), {
    status: 409,
    errorCode: "conflict",
    field: "address",
    violationCode: "address_in_use",
  });
  expect((await post("/api/v1/nodes", {
    name: "berlin-gateway",
    address: "10.42.0.9",
    vnrName: "berlin-edge",
  })).status()).toBe(409);

  const labVnr = await post("/api/v1/vnrs", { name: "dependency-lab", cidr: "10.80.0.0/24" });
  expect(labVnr.status()).toBe(201);
  const labNode = await post("/api/v1/nodes", {
    name: "dependency-node",
    address: "10.80.0.129",
    vnrName: "dependency-lab",
  });
  expect(labNode.status()).toBe(201);
  const labVnrRead = await page.request.get("/api/v1/vnrs/dependency-lab");
  await expectViolation(await page.request.patch("/api/v1/vnrs/dependency-lab", {
    data: { cidr: "10.80.0.128/25" },
    headers: {
      Origin: publicOrigin,
      "X-CSRF-Token": auth.csrfToken,
      "If-Match": requireResponseHeader(labVnrRead, "ETag"),
    },
  }), {
    status: 409,
    errorCode: "invariant_violation",
    field: "cidr",
    violationCode: "range_reserves_node_address",
  });

  const berlinNodeId = "01000000000000000000000000000001";
  await expectViolation(await post("/api/v1/routes", { nodeId: berlinNodeId, prefix: "198.51.100.1/24" }), {
    status: 400,
    errorCode: "validation_failed",
    field: "prefix",
    violationCode: "noncanonical_ipv4_cidr",
  });
  await expectViolation(await post("/api/v1/routes", { nodeId: berlinNodeId, prefix: "0.0.0.0/0" }), {
    status: 400,
    errorCode: "validation_failed",
    field: "prefix",
    violationCode: "prefix_out_of_range",
  });
  await expectViolation(await post("/api/v1/routes", { nodeId: berlinNodeId, prefix: "169.254.0.0/16" }), {
    status: 409,
    errorCode: "invariant_violation",
    field: "prefix",
    violationCode: "range_reserved",
  });
  await expectViolation(await post("/api/v1/routes", { nodeId: berlinNodeId, prefix: "10.42.0.0/25" }), {
    status: 409,
    errorCode: "invariant_violation",
    field: "prefix",
    violationCode: "range_overlaps_vnr",
  });
  await expectViolation(await post("/api/v1/routes", { nodeId: berlinNodeId, prefix: "192.0.2.128/25" }), {
    status: 409,
    errorCode: "invariant_violation",
    field: "prefix",
    violationCode: "range_overlaps_route",
  });
  expect((await post("/api/v1/routes", { nodeId: berlinNodeId, prefix: "192.0.2.0/24" })).status()).toBe(409);
});
