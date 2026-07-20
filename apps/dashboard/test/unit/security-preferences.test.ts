import { describe, expect, test } from "bun:test";

import {
  CAPABILITIES,
  capabilitiesForRole,
  roleCan,
} from "../../src/lib/behavior/capabilities";
import { createMutationAttempt } from "../../src/lib/behavior/mutation";
import {
  parseThemePreference,
  persistThemePreference,
  readThemePreference,
  resolveThemePreference,
  type ThemePreferenceStorage,
} from "../../src/lib/behavior/theme";

class MemoryStorage implements ThemePreferenceStorage {
  readonly values = new Map<string, string>();

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }
}

describe("theme preference behavior", () => {
  test("parses only System, Light, and Dark persistence values", () => {
    expect(parseThemePreference("system")).toBe("system");
    expect(parseThemePreference("light")).toBe("light");
    expect(parseThemePreference("dark")).toBe("dark");
    expect(parseThemePreference("sepia")).toBe("system");
    expect(parseThemePreference(null)).toBe("system");
  });

  test("persists and resolves an explicit or system preference", () => {
    const storage = new MemoryStorage();
    expect(readThemePreference(storage)).toBe("system");
    expect(persistThemePreference(storage, "dark")).toBeTrue();
    expect(readThemePreference(storage)).toBe("dark");
    expect(resolveThemePreference("dark", false)).toBe("dark");
    expect(resolveThemePreference("system", true)).toBe("dark");
    expect(resolveThemePreference("system", false)).toBe("light");
  });

  test("falls back safely when storage is unavailable", () => {
    const unavailable: ThemePreferenceStorage = {
      getItem: () => { throw new Error("denied"); },
      setItem: () => { throw new Error("denied"); },
    };
    expect(readThemePreference(unavailable)).toBe("system");
    expect(persistThemePreference(unavailable, "light")).toBeFalse();
  });
});

describe("role capabilities", () => {
  test("all roles can use common reads and manage their own credentials", () => {
    for (const role of ["viewer", "operator", "superuser"] as const) {
      expect(roleCan(role, "inventory.read")).toBeTrue();
      expect(roleCan(role, "audit.read_redacted")).toBeTrue();
      expect(roleCan(role, "password.self.change")).toBeTrue();
      expect(roleCan(role, "sessions.self.manage")).toBeTrue();
    }
  });

  test("operators mutate inventory but cannot delete or administer security", () => {
    expect(roleCan("operator", "vnrs.create")).toBeTrue();
    expect(roleCan("operator", "nodes.update")).toBeTrue();
    expect(roleCan("operator", "routes.update")).toBeTrue();
    expect(roleCan("operator", "connectivity.create")).toBeTrue();
    expect(roleCan("operator", "nodes.delete")).toBeFalse();
    expect(roleCan("operator", "users.manage")).toBeFalse();
    expect(roleCan("operator", "settings.manage")).toBeFalse();
  });

  test("superusers inherit operator access and receive every dangerous capability", () => {
    expect(capabilitiesForRole("superuser")).toEqual(CAPABILITIES);
    expect(roleCan("superuser", "enrollment.manage")).toBeTrue();
    expect(roleCan("superuser", "sessions.all.manage")).toBeTrue();
    expect(roleCan("superuser", "audit.export")).toBeTrue();
    expect(roleCan("superuser", "audit.prune")).toBeTrue();
    expect(roleCan("superuser", "service.restart")).toBeTrue();
    expect(roleCan("superuser", "service.shutdown")).toBeTrue();
  });
});

describe("mutation attempts", () => {
  test("adds browser mutation protections and keeps one key for one attempt", async () => {
    let keyFactoryCalls = 0;
    const attempt = createMutationAttempt({
      url: "https://ntip.example/api/v1/nodes",
      method: "POST",
      csrfToken: "csrf-token",
      ifMatch: '"generation-41"',
      body: { name: "edge-berlin", address: "10.10.0.2", vnrName: "east" },
      headers: { "X-CSRF-Token": "untrusted", "Idempotency-Key": "untrusted" },
      idempotencyKeyFactory: () => {
        keyFactoryCalls += 1;
        return "0123456789abcdef0123456789abcdef";
      },
    });

    const first = attempt.buildRequest();
    const second = attempt.buildRequest();
    expect(keyFactoryCalls).toBe(1);
    expect(attempt.idempotencyKey).toBe("0123456789abcdef0123456789abcdef");
    expect(first.headers.get("X-CSRF-Token")).toBe("csrf-token");
    expect(first.headers.get("If-Match")).toBe('"generation-41"');
    expect(first.headers.get("Idempotency-Key")).toBe("0123456789abcdef0123456789abcdef");
    expect(second.headers.get("Idempotency-Key")).toBe(first.headers.get("Idempotency-Key"));
    expect(first.cache).toBe("no-store");
    expect(await first.json()).toEqual({ name: "edge-berlin", address: "10.10.0.2", vnrName: "east" });
    expect(attempt.automaticTransportRetryAllowed).toBeTrue();
  });

  test("never allows automatic retry for a one-time response", () => {
    const attempt = createMutationAttempt({
      url: "https://ntip.example/api/v1/nodes/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/enrollment-credentials",
      method: "POST",
      csrfToken: "csrf-token",
      responseKind: "one-time",
      idempotencyKeyFactory: () => "fedcba9876543210fedcba9876543210",
      body: { confirmation: "east-core", expiresInSeconds: 3600 },
    });

    expect(attempt.responseKind).toBe("one-time");
    expect(attempt.automaticTransportRetryAllowed).toBeFalse();
    expect(attempt.buildRequest().headers.get("Idempotency-Key")).toBe("fedcba9876543210fedcba9876543210");
    expect(() => attempt.buildRequest()).toThrow("cannot be retried");
  });

  test("requires a fresh ETag when the operation declares a precondition", () => {
    expect(() => createMutationAttempt({
      url: "https://ntip.example/api/v1/nodes/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      method: "PATCH",
      csrfToken: "csrf-token",
      requiresIfMatch: true,
      body: { name: "new-name" },
    })).toThrow("ifMatch is required");

    const attempt = createMutationAttempt({
      url: "https://ntip.example/api/v1/nodes/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      method: "DELETE",
      csrfToken: "csrf-token",
      ifMatch: '"node-etag"',
      requiresIfMatch: true,
    });
    expect(attempt.idempotencyKey).toBeNull();
    expect(attempt.automaticTransportRetryAllowed).toBeFalse();
    expect(attempt.buildRequest().headers.get("If-Match")).toBe('"node-etag"');
  });
});
