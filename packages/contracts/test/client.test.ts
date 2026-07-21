import { describe, expect, test } from "bun:test";
import { createNtipApiClient, createNtipBootstrapClient } from "../src/index.ts";
import type { bootstrapComponents, components } from "../src/index.ts";

describe("generated openapi-fetch client", () => {
  test("uses typed paths and preserves same-origin credentials", async () => {
    let request: Request | undefined;
    let requestedCredentials: RequestCredentials | undefined;
    class CapturingRequest extends Request {
      constructor(input: RequestInfo | URL, init?: RequestInit) {
        requestedCredentials = init?.credentials;
        super(input, init);
      }
    }
    const client = createNtipApiClient({
      baseUrl: "https://console.example/api/v1",
      Request: CapturingRequest,
      fetch: async (input) => {
        request = input;
        return Response.json({ status: "live" });
      },
    });

    const result = await client.GET("/health/live");
    expect(result.data).toEqual({ status: "live" });
    expect(request?.url).toBe("https://console.example/api/v1/health/live");
    expect(requestedCredentials).toBe("same-origin");
  });

  test("exports named DTO types from the generated schema", () => {
    const request: components["schemas"]["ConnectivityCheckCreate"] = {
      nodeId: "018f8d95b0f74d669f16a606fa9c87e2",
      timeoutMilliseconds: 3000,
    };
    const role: components["schemas"]["Role"] = "operator";

    expect(request.timeoutMilliseconds).toBe(3000);
    expect(role).toBe("operator");
  });

  test("keeps the public bootstrap client cookie-free and rejects redirects", async () => {
    let request: Request | undefined;
    let requestedCredentials: RequestCredentials | undefined;
    let requestedRedirect: RequestRedirect | undefined;
    class CapturingRequest extends Request {
      constructor(input: RequestInfo | URL, init?: RequestInit) {
        requestedCredentials = init?.credentials;
        requestedRedirect = init?.redirect;
        super(input, init);
      }
    }
    const client = createNtipBootstrapClient({
      baseUrl: "https://console.example",
      Request: CapturingRequest,
      fetch: async (input) => {
        request = input;
        return Response.json({
          schemaVersion: 1,
          bootstrapId: "ABCDEFGH",
          nodeName: "edge-01",
          masterEndpoint: "43.157.23.67:49152",
          expiresAt: "2026-07-22T19:00:00Z",
          enrollmentCredential: `ntip-enroll-v1.${"A".repeat(107)}`,
          archives: [],
        });
      },
    });

    await client.POST("/enrollment/v1/redeem", {
      body: { bootstrapId: "ABCDEFGH", secretCode: "ABC-DEF-GHJ" },
    });
    expect(request?.url).toBe("https://console.example/enrollment/v1/redeem");
    expect(requestedCredentials).toBe("omit");
    expect(requestedRedirect).toBe("error");
  });

  test("exports public bootstrap DTO types without changing management aliases", () => {
    const request: bootstrapComponents["schemas"]["BootstrapRedeemRequest"] = {
      bootstrapId: "ABCDEFGH",
      secretCode: "ABC-DEF-GHJ",
    };
    const managementRole: components["schemas"]["Role"] = "superuser";

    expect(request.bootstrapId).toBe("ABCDEFGH");
    expect(managementRole).toBe("superuser");
  });

  test("serializes opaque cursors and canonical timestamps as URI query components", async () => {
    let request: Request | undefined;
    const client = createNtipApiClient({
      baseUrl: "https://console.example/api/v1",
      fetch: async (input) => {
        request = input;
        return Response.json({ items: [], nextCursor: null });
      },
    });

    await client.GET("/events", {
      params: {
        query: {
          cursor: "v1:e:1625159473:abababababababababababababababab",
          since: "2021-07-01T17:11:13Z",
        },
      },
    });

    expect(request?.url).toBe(
      "https://console.example/api/v1/events?cursor=v1%3Ae%3A1625159473%3Aabababababababababababababababab&since=2021-07-01T17%3A11%3A13Z",
    );
  });
});
