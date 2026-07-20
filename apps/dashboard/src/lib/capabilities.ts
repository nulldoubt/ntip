import type { components } from "@ntip/contracts";

export type Role = components["schemas"]["Role"];

export type Capability =
  | "inventory:read"
  | "runtime:read"
  | "operations:read"
  | "settings:read"
  | "audit:read"
  | "inventory:write"
  | "connectivity:run"
  | "inventory:delete"
  | "enrollment:manage"
  | "users:manage"
  | "sessions:manage-all"
  | "settings:write"
  | "audit:manage"
  | "service:control"
  | "sessions:manage-self";

const viewerCapabilities: readonly Capability[] = [
  "inventory:read",
  "runtime:read",
  "operations:read",
  "settings:read",
  "audit:read",
  "sessions:manage-self",
];

const operatorCapabilities: readonly Capability[] = [
  ...viewerCapabilities,
  "inventory:write",
  "connectivity:run",
];

const superuserCapabilities: readonly Capability[] = [
  ...operatorCapabilities,
  "inventory:delete",
  "enrollment:manage",
  "users:manage",
  "sessions:manage-all",
  "settings:write",
  "audit:manage",
  "service:control",
];

export function capabilitiesForRole(role: Role): ReadonlySet<Capability> {
  switch (role) {
    case "viewer":
      return new Set(viewerCapabilities);
    case "operator":
      return new Set(operatorCapabilities);
    case "superuser":
      return new Set(superuserCapabilities);
  }
}

export function can(role: Role, capability: Capability): boolean {
  return capabilitiesForRole(role).has(capability);
}
