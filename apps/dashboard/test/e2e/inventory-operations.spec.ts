import { expect, test, type APIResponse, type Page } from "@playwright/test";
import { fixtureSnapshot, loginAs, resetFixture, setFault, useReducedMotion } from "./support";

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
