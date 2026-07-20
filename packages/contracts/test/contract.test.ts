import { describe, expect, test } from "bun:test";
import {
  expectedPaths,
  expectedOperations,
  loadContract,
  operationalSettingFields,
  renderGeneratedArtifacts,
  stableErrorCodes,
  trafficStates,
  validateContract,
} from "../scripts/contract.ts";

describe("NTIP OpenAPI v1", () => {
  test("validates the complete canonical surface", async () => {
    const summary = await validateContract();
    expect(summary).toEqual({
      pathCount: 35,
      operationCount: 49,
      schemaCount: 81,
    });
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
