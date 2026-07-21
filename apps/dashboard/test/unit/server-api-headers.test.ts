import { describe, expect, test } from "bun:test";

import { internalApiHeaders } from "../../src/lib/server-api-headers";

describe("dashboard internal API headers", () => {
  test("closes each loopback connection so bounded API workers cannot be pinned idle", () => {
    const headers = internalApiHeaders("session-token");

    expect(headers.get("accept")).toBe("application/json");
    expect(headers.get("connection")).toBe("close");
    expect(headers.get("cookie")).toBe("__Host-ntip_session=session-token");
  });

  test("does not synthesize a session cookie for anonymous reads", () => {
    const headers = internalApiHeaders(undefined);

    expect(headers.get("cookie")).toBeNull();
  });

  test("rejects cookie delimiters before the privileged loopback hop", () => {
    for (const session of ["token;admin=true", "token\rspoofed", "token\nspoofed"]) {
      expect(internalApiHeaders(session).get("cookie")).toBeNull();
    }
  });
});
