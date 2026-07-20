import type { components } from "@ntip/contracts";

export type Role = components["schemas"]["Role"];

export const CAPABILITIES = [
  "inventory.read",
  "runtime.read",
  "connectivity.read",
  "settings.read",
  "events.read",
  "audit.read_redacted",
  "password.self.change",
  "sessions.self.manage",
  "vnrs.create",
  "vnrs.update",
  "nodes.create",
  "nodes.update",
  "routes.create",
  "routes.update",
  "connectivity.create",
  "vnrs.delete",
  "nodes.delete",
  "routes.delete",
  "enrollment.manage",
  "users.manage",
  "sessions.all.manage",
  "settings.manage",
  "audit.export",
  "audit.prune",
  "service.restart",
  "service.shutdown",
] as const;

export type Capability = (typeof CAPABILITIES)[number];

const viewerCapabilities = [
  "inventory.read",
  "runtime.read",
  "connectivity.read",
  "settings.read",
  "events.read",
  "audit.read_redacted",
  "password.self.change",
  "sessions.self.manage",
] as const satisfies readonly Capability[];

const operatorCapabilities = [
  ...viewerCapabilities,
  "vnrs.create",
  "vnrs.update",
  "nodes.create",
  "nodes.update",
  "routes.create",
  "routes.update",
  "connectivity.create",
] as const satisfies readonly Capability[];

const superuserCapabilities = [
  ...operatorCapabilities,
  "vnrs.delete",
  "nodes.delete",
  "routes.delete",
  "enrollment.manage",
  "users.manage",
  "sessions.all.manage",
  "settings.manage",
  "audit.export",
  "audit.prune",
  "service.restart",
  "service.shutdown",
] as const satisfies readonly Capability[];

export const ROLE_CAPABILITIES: Readonly<Record<Role, ReadonlySet<Capability>>> = Object.freeze({
  viewer: new Set(viewerCapabilities),
  operator: new Set(operatorCapabilities),
  superuser: new Set(superuserCapabilities),
});

export function roleCan(role: Role, capability: Capability): boolean {
  return ROLE_CAPABILITIES[role].has(capability);
}

export function capabilitiesForRole(role: Role): readonly Capability[] {
  return CAPABILITIES.filter((capability) => roleCan(role, capability));
}
