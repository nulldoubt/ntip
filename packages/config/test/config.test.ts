import { describe, expect, test } from "bun:test";
import {
  loadDashboardRuntimeConfig,
  parseDashboardBootstrap,
  parseLoopbackHttpOrigin,
  parsePublicHttpsOrigin,
} from "../src/index";

describe("dashboard runtime configuration", () => {
  test("accepts only exact loopback HTTP API origins", () => {
    expect(parseLoopbackHttpOrigin("http://127.0.0.1:8787")).toBe("http://127.0.0.1:8787");
    expect(parseLoopbackHttpOrigin("http://[::1]:8787")).toBe("http://[::1]:8787");
    for (const invalid of [
      "https://127.0.0.1:8787",
      "http://0.0.0.0:8787",
      "http://localhost:8787",
      "http://127.0.0.1:8787/api",
      "http://user@127.0.0.1:8787",
    ]) {
      expect(() => parseLoopbackHttpOrigin(invalid)).toThrow();
    }
  });

  test("accepts only an exact public HTTPS origin", () => {
    expect(parsePublicHttpsOrigin("https://ntip.example.test")).toBe(
      "https://ntip.example.test",
    );
    expect(parsePublicHttpsOrigin(undefined)).toBeNull();
    expect(() => parsePublicHttpsOrigin("http://ntip.example.test")).toThrow();
    expect(() => parsePublicHttpsOrigin("https://ntip.example.test/admin")).toThrow();
  });

  test("defaults to private loopback service endpoints", () => {
    expect(loadDashboardRuntimeConfig({ HOSTNAME: "container-id" })).toEqual({
      apiInternalOrigin: "http://127.0.0.1:8787",
      publicOrigin: null,
      listenHost: "127.0.0.1",
      listenPort: 3000,
    });
    expect(() => loadDashboardRuntimeConfig({
      NTIP_DASHBOARD_LISTEN_HOST: "0.0.0.0",
    })).toThrow("loopback");
  });

  test("accepts only the complete strict dashboard bootstrap object", () => {
    expect(parseDashboardBootstrap({
      schema_version: 2,
      bind_address: "0.0.0.0",
      port: 443,
      api_origin: "http://127.0.0.1:8787",
      bootstrap_assets_root: "/usr/share/ntip/bootstrap-assets",
    })).toEqual({
      schemaVersion: 2,
      bindAddress: "0.0.0.0",
      port: 443,
      apiOrigin: "http://127.0.0.1:8787",
      bootstrapAssetsRoot: "/usr/share/ntip/bootstrap-assets",
    });
    expect(() => parseDashboardBootstrap({
      schema_version: 2,
      bind_address: "127.0.0.1",
      port: 443,
      api_origin: "http://127.0.0.1:8787",
      bootstrap_assets_root: "/usr/share/ntip/bootstrap-assets",
    })).toThrow("0.0.0.0");
    expect(() => parseDashboardBootstrap({
      schema_version: 2,
      bind_address: "0.0.0.0",
      port: 443,
      api_origin: "http://127.0.0.1:8787",
      bootstrap_assets_root: "/usr/share/ntip/bootstrap-assets",
      public_origin: "https://ntip.example.invalid",
    })).toThrow("missing or unknown");
    expect(() => parseDashboardBootstrap({
      schema_version: 2,
      bind_address: "0.0.0.0",
      port: 443,
      api_origin: "http://127.0.0.1:8787",
      bootstrap_assets_root: "/tmp/ntip-assets",
    })).toThrow("bootstrap_assets_root");
  });
});
