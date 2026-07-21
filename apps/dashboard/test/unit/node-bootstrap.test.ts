import { describe, expect, test } from "bun:test";
import { BrowserApiError } from "../../src/lib/browser-api-error";
import {
  bootstrapActionLabel,
  buildNodeInstallationCommand,
  parseEnrollmentBootstrapConfig,
  parseNodeBootstrapDisclosure,
  shouldRecoverLostBootstrapResponse,
} from "../../src/lib/node-bootstrap";

const config = {
  installerOrigin: "https://43.157.23.67",
  spkiPin: "sha256//KFgtXcDvCiDozs2cJZwVJ8wagYkpqbJXfT3ew5HlGDY=",
} as const;

const disclosure = {
  node: {
    id: "01000000000000000000000000000001",
    name: "edge",
    address: "10.10.1.2",
    vnrName: "primary",
    enrollmentState: "credential_issued",
    generation: 2,
    createdAt: "2026-07-22T00:00:00Z",
    updatedAt: "2026-07-22T00:00:01Z",
  },
  bootstrap: {
    bootstrapId: "ABCDEFGH",
    secretCode: "ABC-DEF-GHJ",
    expiresAt: "2026-07-22T19:00:00Z",
  },
} as const;

describe("Node bootstrap presentation", () => {
  test("builds a pinned, forced-HTTP/1.1 command without the short secret", () => {
    const command = buildNodeInstallationCommand(config, "ABCDEFGH");

    expect(command).toBe(
      "sudo bash -o pipefail -c 'curl -q --http1.1 --proto \"=https\" --fail --silent --show-error --insecure --pinnedpubkey \"sha256//KFgtXcDvCiDozs2cJZwVJ8wagYkpqbJXfT3ew5HlGDY=\" \"https://43.157.23.67/enrollment/ABCDEFGH\" | bash'",
    );
    expect(command).not.toContain("ABC-DEF-GHJ");
  });

  test("rejects values that could escape the pinned command", () => {
    expect(() => buildNodeInstallationCommand(config, "ABC'DEFG")).toThrow("bootstrap ID");
    expect(() => buildNodeInstallationCommand({ ...config, installerOrigin: "https://example.test/path" }, "ABCDEFGH")).toThrow("exact HTTPS origin");
    expect(() => buildNodeInstallationCommand({ ...config, spkiPin: "sha256//bad'pin" }, "ABCDEFGH")).toThrow("SPKI pin");
  });

  test("limits lost-response recovery to uncertain transport and upstream outcomes", () => {
    expect(shouldRecoverLostBootstrapResponse(new TypeError("fetch failed"), false)).toBeFalse();
    expect(shouldRecoverLostBootstrapResponse(new TypeError("fetch failed"), true)).toBeTrue();
    expect(shouldRecoverLostBootstrapResponse(new BrowserApiError(503, "service_unavailable", "down", null), true)).toBeTrue();
    expect(shouldRecoverLostBootstrapResponse(new BrowserApiError(409, "conflict", "duplicate", null), true)).toBeFalse();
  });

  test("strictly parses the bootstrap configuration", () => {
    expect(parseEnrollmentBootstrapConfig(config)).toEqual(config);
    expect(() => parseEnrollmentBootstrapConfig({ ...config, ignored: true })).toThrow("unexpected or missing fields");
    expect(() => parseEnrollmentBootstrapConfig({ installerOrigin: config.installerOrigin, spkiPin: 42 })).toThrow("must be a string");
  });

  test("strictly parses the complete one-time disclosure", () => {
    expect(parseNodeBootstrapDisclosure(disclosure)).toEqual(disclosure);
    expect(() => parseNodeBootstrapDisclosure({ ...disclosure, ignored: true })).toThrow("unexpected or missing fields");
    expect(() => parseNodeBootstrapDisclosure({
      ...disclosure,
      bootstrap: { ...disclosure.bootstrap, secretCode: "ABC-DEF-0HJ" },
    })).toThrow("secret code");
    expect(() => parseNodeBootstrapDisclosure({
      ...disclosure,
      node: { ...disclosure.node, address: "10.10.01.2" },
    })).toThrow("canonical decimal notation");
    expect(() => parseNodeBootstrapDisclosure({
      ...disclosure,
      bootstrap: { ...disclosure.bootstrap, expiresAt: "2026-02-30T19:00:00Z" },
    })).toThrow("canonical UTC timestamp");
  });

  test("describes the appropriate setup action for each enrollment state", () => {
    const base = {
      id: "01000000000000000000000000000001",
      name: "edge",
      address: "10.10.1.2",
      vnrName: "primary",
      generation: 1,
      createdAt: "2026-07-22T00:00:00Z",
      updatedAt: "2026-07-22T00:00:00Z",
    } as const;
    expect(bootstrapActionLabel({ ...base, enrollmentState: "unenrolled" })).toBe("Generate setup code");
    expect(bootstrapActionLabel({ ...base, enrollmentState: "credential_issued" })).toBe("Generate replacement code");
    expect(bootstrapActionLabel({ ...base, enrollmentState: "enrolled" })).toBe("Reset enrollment and generate setup code");
  });
});
