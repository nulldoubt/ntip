import type { components } from "@ntip/contracts";
import { BrowserApiError } from "@/lib/browser-api-error";
import { parseIpv4 } from "@/lib/network/ipv4";

export type EnrollmentBootstrapConfig = components["schemas"]["EnrollmentBootstrapConfig"];
export type EnrollmentBootstrapDisclosure = components["schemas"]["EnrollmentBootstrapDisclosure"];
export type Node = components["schemas"]["Node"];
export type NodeBootstrapDisclosure = components["schemas"]["NodeBootstrapDisclosure"];

const bootstrapIdPattern = /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$/;
const bootstrapSecretPattern = /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{3}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{3}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{3}$/;
const idPattern = /^[0-9a-f]{32}$/;
const inventoryNamePattern = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$/;
const spkiPinPattern = /^sha256\/{2}[A-Za-z0-9+/]{43}=$/;
const timestampPattern = /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;

function exactObject(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const actualKeys = Object.keys(value);
  if (actualKeys.length !== keys.length || actualKeys.some((key) => !keys.includes(key))) {
    throw new TypeError(`${label} contains unexpected or missing fields`);
  }
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
  return value;
}

function canonicalTimestamp(value: unknown, label: string): string {
  const text = requiredString(value, label);
  const milliseconds = Date.parse(text);
  if (
    !timestampPattern.test(text) ||
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== `${text.slice(0, -1)}.000Z`
  ) {
    throw new TypeError(`${label} must be a canonical UTC timestamp`);
  }
  return text;
}

function parseNode(value: unknown): Node {
  const object = exactObject(value, [
    "address",
    "createdAt",
    "enrollmentState",
    "generation",
    "id",
    "name",
    "updatedAt",
    "vnrName",
  ], "Bootstrap Node");
  const id = requiredString(object.id, "Node ID");
  const name = requiredString(object.name, "Node name");
  const vnrName = requiredString(object.vnrName, "VNR name");
  const address = requiredString(object.address, "Node address");
  const enrollmentState = object.enrollmentState;
  const generation = object.generation;

  if (!idPattern.test(id)) throw new TypeError("Node ID is invalid");
  if (!inventoryNamePattern.test(name)) throw new TypeError("Node name is invalid");
  if (!inventoryNamePattern.test(vnrName)) throw new TypeError("VNR name is invalid");
  parseIpv4(address);
  if (!["unenrolled", "credential_issued", "enrolled"].includes(String(enrollmentState))) {
    throw new TypeError("Node enrollment state is invalid");
  }
  if (typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 0) {
    throw new TypeError("Node generation is invalid");
  }

  return {
    address,
    createdAt: canonicalTimestamp(object.createdAt, "Node creation time"),
    enrollmentState: enrollmentState as Node["enrollmentState"],
    generation,
    id,
    name,
    updatedAt: canonicalTimestamp(object.updatedAt, "Node update time"),
    vnrName,
  };
}

export function buildNodeInstallationCommand(
  config: EnrollmentBootstrapConfig,
  bootstrapId: string,
): string {
  if (!bootstrapIdPattern.test(bootstrapId)) throw new TypeError("The bootstrap ID is invalid");
  if (!spkiPinPattern.test(config.spkiPin)) throw new TypeError("The bootstrap SPKI pin is invalid");

  const origin = new URL(config.installerOrigin);
  if (
    origin.protocol !== "https:" ||
    origin.username.length !== 0 ||
    origin.password.length !== 0 ||
    origin.pathname !== "/" ||
    origin.search.length !== 0 ||
    origin.hash.length !== 0 ||
    origin.origin !== config.installerOrigin
  ) {
    throw new TypeError("The installer origin must be an exact HTTPS origin");
  }

  const scriptUrl = `${origin.origin}/enrollment/${bootstrapId}`;
  return `sudo bash -o pipefail -c 'curl -q --http1.1 --proto "=https" --fail --silent --show-error --insecure --pinnedpubkey "${config.spkiPin}" "${scriptUrl}" | bash'`;
}

export function parseEnrollmentBootstrapConfig(value: unknown): EnrollmentBootstrapConfig {
  const object = exactObject(value, ["installerOrigin", "spkiPin"], "Enrollment bootstrap configuration");
  const config: EnrollmentBootstrapConfig = {
    installerOrigin: requiredString(object.installerOrigin, "Installer origin"),
    spkiPin: requiredString(object.spkiPin, "Installer SPKI pin"),
  };
  buildNodeInstallationCommand(config, "ABCDEFGH");
  return config;
}

export function parseNodeBootstrapDisclosure(value: unknown): NodeBootstrapDisclosure {
  const object = exactObject(value, ["bootstrap", "node"], "Node bootstrap disclosure");
  const bootstrap = exactObject(
    object.bootstrap,
    ["bootstrapId", "expiresAt", "secretCode"],
    "Enrollment bootstrap disclosure",
  );
  const bootstrapId = requiredString(bootstrap.bootstrapId, "Bootstrap ID");
  const secretCode = requiredString(bootstrap.secretCode, "Bootstrap secret code");
  if (!bootstrapIdPattern.test(bootstrapId)) throw new TypeError("The bootstrap ID is invalid");
  if (!bootstrapSecretPattern.test(secretCode)) throw new TypeError("The bootstrap secret code is invalid");

  return {
    bootstrap: {
      bootstrapId,
      expiresAt: canonicalTimestamp(bootstrap.expiresAt, "Bootstrap expiry"),
      secretCode,
    },
    node: parseNode(object.node),
  };
}

export function shouldRecoverLostBootstrapResponse(reason: unknown, provisioningDispatched: boolean): boolean {
  if (!provisioningDispatched) return false;
  if (reason instanceof TypeError) return true;
  return reason instanceof BrowserApiError && [
    "invalid_upstream_response",
    "service_unavailable",
    "internal_error",
  ].includes(reason.code);
}

export function bootstrapActionLabel(node: Node): string {
  switch (node.enrollmentState) {
    case "unenrolled":
      return "Generate setup code";
    case "credential_issued":
      return "Generate replacement code";
    case "enrolled":
      return "Reset enrollment and generate setup code";
  }
}
