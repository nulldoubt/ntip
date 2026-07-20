import { describe, expect, test } from "bun:test";
import { createNtipApiClient } from "../src/index.ts";
import type { components } from "../src/index.ts";

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
