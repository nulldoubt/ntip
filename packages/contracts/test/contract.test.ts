import { describe, expect, test } from "bun:test";
import {
  expectedBootstrapOperations,
  expectedBootstrapPaths,
  expectedPaths,
  expectedOperations,
  loadBootstrapContract,
  loadContract,
  operationalSettingFields,
  renderGeneratedArtifacts,
  stableErrorCodes,
  stableInventoryViolationCodes,
  stableInventoryViolationFields,
  trafficStates,
  validateBootstrapContract,
  validateContract,
} from "../scripts/contract.ts";

describe("NTIP OpenAPI v1", () => {
  test("validates the complete canonical surface", async () => {
    const summary = await validateContract();
    expect(summary).toEqual({
      pathCount: 37,
      operationCount: 52,
      schemaCount: 85,
    });
  });

  test("keeps inventory-only creation separate from one-time bootstrap disclosure", async () => {
    const document = await loadContract();
    const paths = document.paths as Record<string, Record<string, Record<string, unknown>>>;

    expect(paths["/nodes"]!.post!.operationId).toBe("createNode");
    expect(paths["/nodes"]!.post!["x-ntip-one-time-response"]).toBeUndefined();
    expect(paths["/nodes/{id}/enrollment-credentials"]).toBeUndefined();

    for (const path of [
      "/nodes/actions/bootstrap",
      "/nodes/{id}/enrollment-bootstrap",
      "/nodes/{id}/actions/reset-enrollment",
    ]) {
      const operation = paths[path]!.post!;
      expect(operation["x-ntip-roles"]).toEqual(["superuser"]);
      expect(operation["x-ntip-dangerous"]).toBe(true);
      expect(operation["x-ntip-reauthentication"]).toBe("required");
      expect(operation["x-ntip-one-time-response"]).toBe(true);
      expect(operation["x-ntip-idempotency-replay"]).toBe("forbidden");
    }

    expect(paths["/nodes/actions/bootstrap"]!.post!["x-ntip-etag-precondition"]).toBe(false);
  });

  test("keeps every route method and operation identifier in the canonical set", async () => {
    const summary = await validateContract();
    expect(summary.operationCount).toBe(expectedOperations.length);
  });

  test("keeps every accepted route group in one stable path set", async () => {
    const document = await loadContract();
    const paths = document.paths as Record<string, unknown>;
    expect(Object.keys(paths).sort()).toEqual([...expectedPaths]);
  });

  test("keeps the machine-readable error vocabulary stable", async () => {
    const document = await loadContract();
    const components = document.components as Record<string, Record<string, unknown>>;
    const schemas = components.schemas as Record<string, Record<string, unknown>>;
    const errorCodes = schemas.ErrorCode?.enum as string[];
    expect([...errorCodes].sort()).toEqual([...stableErrorCodes]);
  });

  test("documents stable inventory violations while allowing additive future values", async () => {
    const document = await loadContract();
    const schemas = (document.components as Record<string, Record<string, unknown>>).schemas as Record<
      string,
      Record<string, unknown>
    >;
    const properties = schemas.FieldViolation!.properties as Record<string, Record<string, unknown>>;
    const fieldDescription = properties.field!.description as string;
    const codeDescription = properties.code!.description as string;

    expect(properties.code!.enum).toBeUndefined();
    for (const field of stableInventoryViolationFields) expect(fieldDescription).toContain(`\`${field}\``);
    for (const code of stableInventoryViolationCodes) expect(codeDescription).toContain(`\`${code}\``);
  });

  test("keeps inventory error status and top-level code semantics explicit", async () => {
    const document = await loadContract();
    const responses = (document.components as Record<string, Record<string, unknown>>).responses as Record<
      string,
      Record<string, unknown>
    >;

    expect(responses.BadRequest!.description).toContain("HTTP 400");
    expect(responses.BadRequest!.description).toContain("`validation_failed`");
    expect(responses.Conflict!.description).toContain("HTTP 409");
    expect(responses.Conflict!.description).toContain("`invariant_violation`");
    expect(responses.Conflict!.description).toContain("`conflict`");
  });

  test("keeps settings aligned with the runtime and SQLite snapshot", async () => {
    const document = await loadContract();
    const schemas = (document.components as Record<string, Record<string, unknown>>).schemas as Record<
      string,
      Record<string, unknown>
    >;
    expect(Object.keys(schemas.OperationalSettings!.properties as object).sort()).toEqual([
      ...operationalSettingFields,
    ]);
  });

  test("keeps the public traffic states aligned with runtime telemetry", async () => {
    const document = await loadContract();
    const schemas = (document.components as Record<string, Record<string, unknown>>).schemas as Record<
      string,
      Record<string, unknown>
    >;
    expect(schemas.TrafficState!.enum).toEqual([...trafficStates]);
  });

  test("publishes the audit collection ETag and canonical UTC timestamp shape", async () => {
    const document = await loadContract();
    const paths = document.paths as Record<string, Record<string, Record<string, unknown>>>;
    const auditResponses = paths["/audit"]!.get!.responses as Record<
      string,
      Record<string, unknown>
    >;
    const auditHeaders = auditResponses["200"]!.headers as Record<string, unknown>;
    expect(auditHeaders.ETag).toEqual({ $ref: "#/components/headers/ETag" });

    const schemas = (document.components as Record<string, Record<string, unknown>>).schemas as Record<
      string,
      Record<string, unknown>
    >;
    expect(schemas.Timestamp).toMatchObject({
      minLength: 20,
      maxLength: 20,
      pattern:
        "^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$",
    });
  });

  test("has no generated artifact drift", async () => {
    for (const artifact of await renderGeneratedArtifacts()) {
      expect(await Bun.file(artifact.url).text()).toBe(artifact.source);
    }
  });
});

describe("NTIP public Bootstrap v1 OpenAPI", () => {
  test("validates its complete cookie-independent surface", async () => {
    expect(await validateBootstrapContract()).toEqual({
      pathCount: 3,
      operationCount: 3,
      schemaCount: 15,
    });
  });

  test("keeps the exact public path and operation sets", async () => {
    const document = await loadBootstrapContract();
    const paths = document.paths as Record<string, Record<string, Record<string, unknown>>>;
    expect(Object.keys(paths).sort()).toEqual([...expectedBootstrapPaths]);

    const operations: string[] = [];
    for (const [path, item] of Object.entries(paths)) {
      for (const method of ["get", "post"] as const) {
        const operation = item[method];
        if (operation) operations.push(`${method.toUpperCase()} ${path} ${operation.operationId as string}`);
      }
    }
    expect(operations.sort()).toEqual([...expectedBootstrapOperations]);
  });

  test("bounds strict redemption and makes invitation failures indistinguishable", async () => {
    const document = await loadBootstrapContract();
    const paths = document.paths as Record<string, Record<string, Record<string, unknown>>>;
    const redeem = paths["/enrollment/v1/redeem"]!.post!;
    expect(redeem).toMatchObject({
      "x-ntip-cookie-independent": true,
      "x-ntip-cors": "disabled",
      "x-ntip-redirects": "forbidden",
      "x-ntip-reject-origin": true,
      "x-ntip-reject-transfer-encoding": true,
      "x-ntip-max-request-body-bytes": 128,
    });

    const schemas = (document.components as Record<string, Record<string, unknown>>).schemas as Record<
      string,
      Record<string, unknown>
    >;
    expect(schemas.BootstrapRedeemRequest).toMatchObject({
      additionalProperties: false,
      required: ["bootstrapId", "secretCode"],
    });
    const unavailable = schemas.BootstrapUnavailableError!.properties as Record<
      string,
      Record<string, unknown>
    >;
    expect(unavailable.code!.const).toBe("bootstrap_unavailable");
    expect(unavailable.message!.const).toBe("Bootstrap invitation is unavailable.");
  });

  test("documents generated shell and NGINX-owned immutable assets", async () => {
    const document = await loadBootstrapContract();
    const paths = document.paths as Record<string, Record<string, Record<string, unknown>>>;
    const installer = paths["/enrollment/{bootstrapId}"]!.get!;
    const installerResponses = installer.responses as Record<string, Record<string, unknown>>;
    expect(Object.keys(installerResponses["200"]!.content as object)).toEqual(["text/x-shellscript"]);
    expect(paths["/enrollment/assets/{versioned-file}"]!.get!["x-ntip-owner"]).toBe("nginx");
  });
});
