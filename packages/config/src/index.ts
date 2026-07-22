export type DashboardRuntimeConfig = Readonly<{
  apiInternalOrigin: string;
  publicOrigin: string | null;
  listenHost: "127.0.0.1" | "::1";
  listenPort: number;
}>;

export type DashboardBootstrapConfig = Readonly<{
  schemaVersion: 2;
  bindAddress: "0.0.0.0";
  port: number;
  apiOrigin: string;
  bootstrapAssetsRoot: "/usr/share/ntip/bootstrap-assets";
}>;

const loopbackHosts = new Set(["127.0.0.1", "[::1]"]);

export function parseLoopbackHttpOrigin(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("NTIP_API_INTERNAL_ORIGIN must be an absolute URL");
  }
  if (
    parsed.protocol !== "http:" ||
    !loopbackHosts.has(parsed.hostname) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new Error("NTIP_API_INTERNAL_ORIGIN must be an HTTP loopback origin");
  }
  return parsed.origin;
}

export function parsePublicHttpsOrigin(value: string | undefined): string | null {
  if (value === undefined || value === "") return null;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("NTIP_PUBLIC_ORIGIN must be an absolute URL");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new Error("NTIP_PUBLIC_ORIGIN must be an exact HTTPS origin");
  }
  return parsed.origin;
}

export function loadDashboardRuntimeConfig(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): DashboardRuntimeConfig {
  const rawPort = environment.PORT ?? "3000";
  if (!/^[1-9][0-9]{0,4}$/.test(rawPort)) {
    throw new Error("PORT must be an integer from 1 through 65535");
  }
  const listenPort = Number(rawPort);
  if (listenPort > 65_535) throw new Error("PORT must be an integer from 1 through 65535");
  // `HOSTNAME` is populated with a machine/container name by many Linux
  // environments. Keep NTIP's bind policy on a namespaced variable; the
  // launcher separately sets Next's framework-level `HOSTNAME`.
  const rawHost = environment.NTIP_DASHBOARD_LISTEN_HOST ?? "127.0.0.1";
  if (rawHost !== "127.0.0.1" && rawHost !== "::1") {
    throw new Error("NTIP_DASHBOARD_LISTEN_HOST must be a loopback address");
  }
  return {
    apiInternalOrigin: parseLoopbackHttpOrigin(
      environment.NTIP_API_INTERNAL_ORIGIN ?? "http://127.0.0.1:8787",
    ),
    publicOrigin: parsePublicHttpsOrigin(environment.NTIP_PUBLIC_ORIGIN),
    listenHost: rawHost,
    listenPort,
  };
}

export function parseDashboardBootstrap(value: unknown): DashboardBootstrapConfig {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("dashboard configuration must be a JSON object");
  }
  const object = value as Record<string, unknown>;
  const expected = [
    "api_origin",
    "bind_address",
    "bootstrap_assets_root",
    "port",
    "schema_version",
  ] as const;
  const actual = Object.keys(object).sort();
  if (actual.length !== expected.length || expected.some((key, index) => actual[index] !== key)) {
    throw new Error("dashboard configuration contains missing or unknown fields");
  }
  if (object.schema_version !== 2) {
    throw new Error("dashboard schema_version must be 2");
  }
  if (object.bind_address !== "0.0.0.0") {
    throw new Error("dashboard bind_address must be 0.0.0.0");
  }
  if (!Number.isInteger(object.port) || (object.port as number) < 1 || (object.port as number) > 65_535) {
    throw new Error("dashboard port must be an integer from 1 through 65535");
  }
  if (typeof object.api_origin !== "string") {
    throw new Error("dashboard api_origin must be a string");
  }
  if (object.bootstrap_assets_root !== "/usr/share/ntip/bootstrap-assets") {
    throw new Error(
      "dashboard bootstrap_assets_root must be /usr/share/ntip/bootstrap-assets",
    );
  }
  return {
    schemaVersion: 2,
    bindAddress: "0.0.0.0",
    port: object.port as number,
    apiOrigin: parseLoopbackHttpOrigin(object.api_origin),
    bootstrapAssetsRoot: "/usr/share/ntip/bootstrap-assets",
  };
}
