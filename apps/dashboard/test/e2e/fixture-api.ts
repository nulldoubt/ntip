import type { components } from "@ntip/contracts";
import {
  containsIpv4,
  formatIpv4,
  networkAddress,
  parseIpv4,
  parseIpv4Cidr,
  type Ipv4Cidr,
} from "../../src/lib/network/ipv4";

type AcceptedOperation = components["schemas"]["AcceptedOperation"];
type AuditEntry = components["schemas"]["AuditEntry"];
type AuditPage = components["schemas"]["AuditPage"];
type AuthContext = components["schemas"]["AuthContext"];
type ConnectivityCheck = components["schemas"]["ConnectivityCheck"];
type ConnectivityCheckPage = components["schemas"]["ConnectivityCheckPage"];
type ErrorCode = components["schemas"]["ErrorCode"];
type FieldViolation = components["schemas"]["FieldViolation"];
type Event = components["schemas"]["Event"];
type Node = components["schemas"]["Node"];
type NodeDetail = components["schemas"]["NodeDetail"];
type NodeRuntime = components["schemas"]["NodeRuntime"];
type OperationalSettings = components["schemas"]["OperationalSettings"];
type Overview = components["schemas"]["Overview"];
type Role = components["schemas"]["Role"];
type Route = components["schemas"]["Route"];
type Session = components["schemas"]["Session"];
type SettingsRevision = components["schemas"]["SettingsRevision"];
type SettingsState = components["schemas"]["SettingsState"];
type Topology = components["schemas"]["Topology"];
type User = components["schemas"]["User"];
type Vnr = components["schemas"]["Vnr"];

const NOW = "2026-07-20T10:00:00Z";
const LATER = "2026-07-20T22:00:00Z";
const IDLE = "2026-07-20T10:30:00Z";

const reservedRanges = [
  "0.0.0.0/8",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "224.0.0.0/4",
  "240.0.0.0/4",
].map(parseIpv4Cidr);

const privateRanges = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
].map(parseIpv4Cidr);

const inventoryNamePattern = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$/;

const ids = {
  audit: "a1000000000000000000000000000001",
  check: "c1000000000000000000000000000001",
  event: "e1000000000000000000000000000001",
  nodeBerlin: "01000000000000000000000000000001",
  nodeLondon: "01000000000000000000000000000002",
  nodeOffline: "01000000000000000000000000000003",
  routeBerlin: "02000000000000000000000000000001",
  revisionActive: "51000000000000000000000000000001",
  revisionPrior: "51000000000000000000000000000002",
  sessionOther: "61000000000000000000000000000001",
  userOperator: "71000000000000000000000000000001",
  userSuperuser: "71000000000000000000000000000002",
  userTemporary: "71000000000000000000000000000003",
  userViewer: "71000000000000000000000000000004",
} as const;

const defaultSettings: OperationalSettings = {
  connectivityRetentionDays: 30,
  defaultEnrollmentLifetimeSeconds: 3600,
  heartbeatIntervalSeconds: 15,
  innerMtu: 1280,
  maximumNodes: 250,
  offlineAfterSeconds: 90,
  runtimeEventRetentionDays: 90,
  suspectAfterSeconds: 45,
  trafficColdAfterSeconds: 120,
  trafficHotBitsPerSecond: 50_000_000,
  trafficHotPacketsPerSecond: 50_000,
  trafficHysteresisSeconds: 30,
  trafficSaturatedQueuePercent: 90,
};

const seedVnrs: readonly Vnr[] = [
  { name: "berlin-edge", cidr: "10.42.0.0/24", masterAddress: "10.42.0.1", publicRangeWarning: false, generation: 3, createdAt: NOW, updatedAt: NOW },
  { name: "london-core", cidr: "10.43.0.0/24", masterAddress: "10.43.0.1", publicRangeWarning: false, generation: 2, createdAt: NOW, updatedAt: NOW },
];

const seedNodes: readonly Node[] = [
  { id: ids.nodeBerlin, name: "berlin-gateway", address: "10.42.0.2", vnrName: "berlin-edge", enrollmentState: "enrolled", generation: 7, createdAt: NOW, updatedAt: NOW },
  { id: ids.nodeLondon, name: "london-relay", address: "10.43.0.2", vnrName: "london-core", enrollmentState: "enrolled", generation: 4, createdAt: NOW, updatedAt: NOW },
  { id: ids.nodeOffline, name: "warehouse-sensor", address: "10.42.0.8", vnrName: "berlin-edge", enrollmentState: "unenrolled", generation: 1, createdAt: NOW, updatedAt: NOW },
];

const seedRoutes: readonly Route[] = [
  { id: ids.routeBerlin, prefix: "192.0.2.0/24", nodeId: ids.nodeBerlin, nodeName: "berlin-gateway", generation: 2, createdAt: NOW, updatedAt: NOW },
];

const seedRuntime: readonly NodeRuntime[] = [
  { nodeId: ids.nodeBerlin, liveness: "online", sessionState: "established", trafficState: "warm", observedEndpoint: "198.51.100.14:51900", authenticatedRxAt: NOW, authenticatedTxAt: NOW, observedAt: NOW },
  { nodeId: ids.nodeLondon, liveness: "suspect", sessionState: "connecting", trafficState: "hot", observedEndpoint: "203.0.113.8:51900", authenticatedRxAt: NOW, authenticatedTxAt: NOW, observedAt: NOW },
  { nodeId: ids.nodeOffline, liveness: "offline", sessionState: "disconnected", trafficState: "unknown", observedEndpoint: null, authenticatedRxAt: null, authenticatedTxAt: null, observedAt: NOW },
];

const seedUsers: readonly User[] = [
  { id: ids.userSuperuser, username: "superuser", role: "superuser", status: "active", mustChangePassword: false, generation: 5, createdAt: NOW, updatedAt: NOW },
  { id: ids.userOperator, username: "operator", role: "operator", status: "active", mustChangePassword: false, generation: 3, createdAt: NOW, updatedAt: NOW },
  { id: ids.userViewer, username: "viewer", role: "viewer", status: "active", mustChangePassword: false, generation: 2, createdAt: NOW, updatedAt: NOW },
  { id: ids.userTemporary, username: "temporary", role: "viewer", status: "active", mustChangePassword: true, generation: 1, createdAt: NOW, updatedAt: NOW },
];

const activeRevision: SettingsRevision = {
  id: ids.revisionActive,
  sequence: 2,
  settings: defaultSettings,
  status: "active",
  failureCode: null,
  createdAt: NOW,
  appliedAt: NOW,
  createdByUserId: ids.userSuperuser,
};

const priorRevision: SettingsRevision = {
  ...activeRevision,
  id: ids.revisionPrior,
  sequence: 1,
  settings: { ...defaultSettings, innerMtu: 1240 },
};

interface FixtureSession {
  token: string;
  csrfToken: string;
  session: Session;
  reauthenticatedUntil: number;
}

interface FaultRule {
  path: string;
  status?: number;
  delayMilliseconds: number;
  remaining: number;
}

export interface RequestRecord {
  sequence: number;
  method: string;
  path: string;
  headers: Readonly<Record<string, string>>;
  body: unknown;
}

interface FixtureState {
  generation: number;
  users: User[];
  passwords: Map<string, string>;
  sessions: Map<string, FixtureSession>;
  vnrs: Vnr[];
  nodes: Node[];
  routes: Route[];
  runtime: NodeRuntime[];
  events: Event[];
  checks: ConnectivityCheck[];
  audit: AuditEntry[];
  settings: SettingsState;
  revisions: SettingsRevision[];
  faults: FaultRule[];
  requests: RequestRecord[];
  activeRequests: number;
  maximumConcurrentRequests: number;
  sequence: number;
}

export interface FixtureSnapshot {
  readonly activeRequests: number;
  readonly maximumConcurrentRequests: number;
  readonly requests: readonly RequestRecord[];
  readonly counts: Readonly<{ users: number; vnrs: number; nodes: number; routes: number; checks: number }>;
}

export interface FixtureControlOptions {
  readonly publicOrigin: string;
}

function freshState(): FixtureState {
  const event: Event = {
    id: ids.event,
    kind: "node.liveness.changed",
    occurredAt: NOW,
    resourceType: "node",
    resourceId: ids.nodeLondon,
    severity: "warning",
    summary: "london-relay moved from online to suspect",
  };
  const audit: AuditEntry = {
    id: ids.audit,
    action: "auth.login",
    actorType: "web_user",
    actorUserId: ids.userSuperuser,
    actorUsername: "superuser",
    outcome: "succeeded",
    occurredAt: NOW,
    resourceType: "session",
    resourceId: null,
    proxyPeer: "127.0.0.1",
    requestId: "81000000000000000000000000000001",
    userAgent: "fixture",
  };
  const check: ConnectivityCheck = {
    id: ids.check,
    nodeId: ids.nodeBerlin,
    nodeAddress: "10.42.0.2",
    status: "succeeded",
    timeoutMilliseconds: 3000,
    roundTripMilliseconds: 18,
    failureCode: null,
    createdAt: NOW,
    startedAt: NOW,
    completedAt: NOW,
  };
  return {
    generation: 10,
    users: [...structuredClone(seedUsers)],
    passwords: new Map([
      [ids.userViewer, "viewer-password-2026"],
      [ids.userOperator, "operator-password-2026"],
      [ids.userSuperuser, "superuser-password-2026"],
      [ids.userTemporary, "temporary-password-2026"],
    ]),
    sessions: new Map(),
    vnrs: [...structuredClone(seedVnrs)],
    nodes: [...structuredClone(seedNodes)],
    routes: [...structuredClone(seedRoutes)],
    runtime: [...structuredClone(seedRuntime)],
    events: [event],
    checks: [check],
    audit: [audit],
    settings: { desired: structuredClone(activeRevision), effective: structuredClone(activeRevision), pendingRestart: false },
    revisions: [structuredClone(activeRevision), structuredClone(priorRevision)],
    faults: [],
    requests: [],
    activeRequests: 0,
    maximumConcurrentRequests: 0,
    sequence: 1,
  };
}

function requestId(sequence: number): string {
  return sequence.toString(16).padStart(32, "0").slice(-32);
}

function entityTag(kind: string, identity: string, generation: number): string {
  return `"${kind}:${identity}:${generation}"`;
}

function standardHeaders(sequence: number, extra?: HeadersInit): Headers {
  const headers = new Headers(extra);
  headers.set("Cache-Control", "no-store");
  headers.set("X-Request-ID", requestId(sequence));
  return headers;
}

function json(sequence: number, value: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = standardHeaders(sequence, extra);
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(value), { status, headers });
}

function empty(sequence: number, status = 204, extra?: HeadersInit): Response {
  return new Response(null, { status, headers: standardHeaders(sequence, extra) });
}

function apiError(
  sequence: number,
  status: number,
  code: ErrorCode,
  message: string,
  violations: readonly FieldViolation[] = [],
): Response {
  return json(sequence, {
    error: {
      code,
      message,
      requestId: requestId(sequence),
      ...(violations.length === 0 ? {} : { violations }),
    },
  }, status);
}

function roleRank(role: Role): number {
  return role === "superuser" ? 3 : role === "operator" ? 2 : 1;
}

function cookieToken(request: Request): string | null {
  const cookie = request.headers.get("cookie") ?? "";
  const match = /(?:^|;\s*)__Host-ntip_session=([^;]+)/.exec(cookie);
  return match?.[1] ?? null;
}

function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, child]) => {
    const normalized = key.toLowerCase();
    if (normalized.includes("password") || normalized.includes("credential") || normalized.includes("csrf") || normalized.includes("token")) {
      return [key, "<redacted>"];
    }
    return [key, redact(child)];
  }));
}

async function sanitizedBody(request: Request): Promise<unknown> {
  if (["GET", "HEAD"].includes(request.method)) return null;
  const text = await request.clone().text();
  if (text === "") return null;
  try {
    return redact(JSON.parse(text) as unknown);
  } catch {
    return "<non-json body>";
  }
}

function loggedHeaders(request: Request): Readonly<Record<string, string>> {
  const selected: Record<string, string> = {};
  for (const name of ["origin", "user-agent", "if-match", "connection"]) {
    const value = request.headers.get(name);
    if (value !== null) selected[name] = value;
  }
  for (const name of ["cookie", "x-csrf-token", "idempotency-key"]) {
    if (request.headers.has(name)) selected[name] = "<redacted>";
  }
  return selected;
}

function exactFields(value: unknown, allowed: readonly string[]): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.keys(value).every((key) => allowed.includes(key));
}

function rangesOverlap(left: Ipv4Cidr, right: Ipv4Cidr): boolean {
  return left.network <= right.broadcast && right.network <= left.broadcast;
}

function rangeContainsRange(container: Ipv4Cidr, candidate: Ipv4Cidr): boolean {
  return candidate.network >= container.network && candidate.broadcast <= container.broadcast;
}

function isReservedRange(cidr: Ipv4Cidr): boolean {
  return reservedRanges.some((reserved) => rangesOverlap(cidr, reserved));
}

function isPublicRange(cidr: Ipv4Cidr): boolean {
  return !privateRanges.some((privateRange) => rangeContainsRange(privateRange, cidr));
}

function cidrFailureCode(value: string): FieldViolation["code"] {
  const slash = value.indexOf("/");
  if (slash <= 0 || slash !== value.lastIndexOf("/") || slash === value.length - 1) {
    return "invalid_ipv4_cidr";
  }

  const addressText = value.slice(0, slash);
  const prefixText = value.slice(slash + 1);
  if (/^(?:[0-9]+\.){3}[0-9]+$/.test(addressText)) {
    const hasLeadingZero = addressText.split(".").some((octet) => octet.length > 1 && octet.startsWith("0"));
    if (hasLeadingZero) return "noncanonical_ipv4_cidr";
  }

  let address: bigint;
  try {
    address = parseIpv4(addressText);
  } catch {
    return "invalid_ipv4_cidr";
  }

  if (/^[0-9]+$/.test(prefixText) && prefixText.length > 1 && prefixText.startsWith("0")) {
    return "noncanonical_ipv4_cidr";
  }
  if (!/^(?:0|[1-9][0-9]{0,2})$/.test(prefixText)) return "prefix_out_of_range";
  const prefixLength = Number(prefixText);
  if (prefixLength > 32) return "prefix_out_of_range";
  if (networkAddress(address, prefixLength) !== address) return "noncanonical_ipv4_cidr";
  return "invalid_ipv4_cidr";
}

function cidrFailureMessage(code: FieldViolation["code"]): string {
  if (code === "noncanonical_ipv4_cidr") return "The IPv4 range must use canonical network notation.";
  if (code === "prefix_out_of_range") return "The IPv4 prefix length is outside the permitted range.";
  return "The value must be a valid IPv4 CIDR.";
}

function violation(field: string, code: string, message: string): FieldViolation {
  return { field, code, message };
}

export class FixtureApi {
  readonly #publicOrigin: string;
  #state = freshState();

  constructor(options: FixtureControlOptions) {
    this.#publicOrigin = options.publicOrigin;
  }

  reset(): void {
    this.#state = freshState();
  }

  resetMetrics(): void {
    this.#state.requests = [];
    this.#state.activeRequests = 0;
    this.#state.maximumConcurrentRequests = 0;
  }

  addFault(rule: Readonly<{ path: string; status?: number; delayMilliseconds?: number; remaining?: number }>): void {
    this.#state.faults.push({
      path: rule.path,
      ...(rule.status === undefined ? {} : { status: rule.status }),
      delayMilliseconds: rule.delayMilliseconds ?? 0,
      remaining: rule.remaining ?? 1,
    });
  }

  clearFaults(): void {
    this.#state.faults = [];
  }

  snapshot(): FixtureSnapshot {
    return structuredClone({
      activeRequests: this.#state.activeRequests,
      maximumConcurrentRequests: this.#state.maximumConcurrentRequests,
      requests: this.#state.requests,
      counts: {
        users: this.#state.users.length,
        vnrs: this.#state.vnrs.length,
        nodes: this.#state.nodes.length,
        routes: this.#state.routes.length,
        checks: this.#state.checks.length,
      },
    });
  }

  async handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const sequence = this.#state.sequence++;
    this.#state.activeRequests += 1;
    this.#state.maximumConcurrentRequests = Math.max(this.#state.maximumConcurrentRequests, this.#state.activeRequests);
    try {
      this.#state.requests.push({
        sequence,
        method: request.method,
        path: `${url.pathname}${url.search}`,
        headers: loggedHeaders(request),
        body: await sanitizedBody(request),
      });

      const fault = this.#state.faults.find((candidate) => candidate.path === url.pathname && candidate.remaining > 0);
      if (fault !== undefined) {
        fault.remaining -= 1;
        if (fault.delayMilliseconds > 0) await Bun.sleep(fault.delayMilliseconds);
        if (fault.status !== undefined) {
          return apiError(sequence, fault.status, fault.status === 503 ? "service_unavailable" : "internal_error", "Injected fixture fault");
        }
      }

      return await this.#route(request, url, sequence);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Fixture failure";
      return apiError(sequence, 500, "internal_error", message);
    } finally {
      this.#state.activeRequests -= 1;
    }
  }

  async #route(request: Request, url: URL, sequence: number): Promise<Response> {
    if (request.method === "GET" && url.pathname === "/api/v1/health/live") return json(sequence, { status: "live" }, 200, { ETag: '"live"' });
    if (request.method === "GET" && url.pathname === "/api/v1/health/ready") return json(sequence, { status: "ready", ntsrv: "ready", databaseSchemaVersion: 1 });

    if (request.method === "POST" && url.pathname === "/api/v1/auth/login") {
      const validation = this.#validateOriginAndIdempotency(request, sequence, false);
      if (validation !== null) return validation;
      const body: unknown = await request.json().catch(() => null);
      if (!exactFields(body, ["username", "password"]) || typeof body.username !== "string" || typeof body.password !== "string") {
        return apiError(sequence, 400, "validation_failed", "A username and password are required");
      }
      const username = body.username;
      const password = body.password;
      const user = this.#state.users.find((candidate) => candidate.username === username.toLowerCase());
      if (user === undefined || user.status !== "active" || this.#state.passwords.get(user.id) !== password) {
        return apiError(sequence, 401, "invalid_credentials", "Invalid credentials");
      }
      const session = this.#createSession(user, request.headers.get("user-agent"));
      return json(sequence, this.#authContext(user, session), 200, {
        "Set-Cookie": `__Host-ntip_session=${session.token}; Secure; HttpOnly; SameSite=Strict; Path=/`,
      });
    }

    const authenticated = this.#authenticate(request, sequence);
    if (authenticated instanceof Response) return authenticated;
    const { user, session } = authenticated;

    if (request.method === "GET" && url.pathname === "/api/v1/auth/me") return json(sequence, this.#authContext(user, session));

    if (request.method === "POST" && url.pathname === "/api/v1/auth/reauth") {
      const validation = this.#validateMutation(request, sequence, session, false);
      if (validation !== null) return validation;
      const body: unknown = await request.json().catch(() => null);
      if (!exactFields(body, ["password"]) || typeof body.password !== "string" || this.#state.passwords.get(user.id) !== body.password) {
        return apiError(sequence, 401, "invalid_credentials", "Invalid credentials");
      }
      session.reauthenticatedUntil = Date.now() + 5 * 60_000;
      return json(sequence, { validUntil: "2026-07-20T10:05:00Z" });
    }

    if (request.method === "POST" && url.pathname === "/api/v1/auth/change-password") {
      const validation = this.#validateMutation(request, sequence, session, false);
      if (validation !== null) return validation;
      const body: unknown = await request.json().catch(() => null);
      if (!exactFields(body, ["currentPassword", "newPassword"]) || typeof body.currentPassword !== "string" || typeof body.newPassword !== "string") {
        return apiError(sequence, 400, "validation_failed", "Both passwords are required");
      }
      if (this.#state.passwords.get(user.id) !== body.currentPassword || Array.from(body.newPassword).length < 14) {
        return apiError(sequence, 400, "validation_failed", "Password change was rejected");
      }
      this.#state.passwords.set(user.id, body.newPassword);
      this.#replaceUser({ ...user, mustChangePassword: false, generation: user.generation + 1, updatedAt: NOW });
      for (const [token, candidate] of this.#state.sessions) if (token !== session.token && candidate.session.userId === user.id) this.#state.sessions.delete(token);
      return empty(sequence);
    }

    if (request.method === "POST" && url.pathname === "/api/v1/auth/logout") {
      const validation = this.#validateMutation(request, sequence, session, false);
      if (validation !== null) return validation;
      this.#state.sessions.delete(session.token);
      return empty(sequence, 204, { "Set-Cookie": "__Host-ntip_session=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" });
    }

    if (request.method === "GET" && url.pathname === "/api/v1/overview") return json(sequence, this.#overview());
    if (request.method === "GET" && url.pathname === "/api/v1/topology") return json(sequence, this.#topology());
    if (request.method === "GET" && url.pathname === "/api/v1/runtime/nodes") return json(sequence, { items: this.#state.runtime, nextCursor: null, observedAt: NOW });
    if (request.method === "GET" && url.pathname === "/api/v1/events") return json(sequence, { items: this.#state.events, nextCursor: null });
    if (request.method === "GET" && url.pathname === "/api/v1/audit") return json(sequence, this.#auditPage(user.role), 200, { ETag: entityTag("audit", "head", this.#state.generation) });

    if (url.pathname === "/api/v1/vnrs") return this.#vnrs(request, sequence, user, session);
    const vnrMatch = /^\/api\/v1\/vnrs\/([^/]+)$/.exec(url.pathname);
    if (vnrMatch?.[1] !== undefined) return this.#vnr(request, sequence, user, session, decodeURIComponent(vnrMatch[1]));

    if (url.pathname === "/api/v1/nodes") return this.#nodes(request, sequence, user, session);
    const nodeMatch = /^\/api\/v1\/nodes\/([0-9a-f]{32})$/.exec(url.pathname);
    if (nodeMatch?.[1] !== undefined) return this.#node(request, sequence, user, session, nodeMatch[1]);
    const enrollmentMatch = /^\/api\/v1\/nodes\/([0-9a-f]{32})\/enrollment-credentials$/.exec(url.pathname);
    if (enrollmentMatch?.[1] !== undefined) return this.#enrollmentCredential(request, sequence, user, session, enrollmentMatch[1]);
    const resetEnrollmentMatch = /^\/api\/v1\/nodes\/([0-9a-f]{32})\/actions\/reset-enrollment$/.exec(url.pathname);
    if (resetEnrollmentMatch?.[1] !== undefined) return this.#resetEnrollment(request, sequence, user, session, resetEnrollmentMatch[1]);

    if (url.pathname === "/api/v1/routes") return this.#routes(request, sequence, user, session);
    const routeMatch = /^\/api\/v1\/routes\/([0-9a-f]{32})$/.exec(url.pathname);
    if (routeMatch?.[1] !== undefined) return this.#routeResource(request, sequence, user, session, routeMatch[1]);

    if (url.pathname === "/api/v1/connectivity-checks") return this.#connectivityChecks(request, sequence, user, session);
    const checkMatch = /^\/api\/v1\/connectivity-checks\/([0-9a-f]{32})$/.exec(url.pathname);
    if (request.method === "GET" && checkMatch?.[1] !== undefined) {
      const check = this.#state.checks.find((candidate) => candidate.id === checkMatch[1]);
      return check === undefined ? apiError(sequence, 404, "not_found", "Connectivity check not found") : json(sequence, check);
    }

    if (request.method === "POST" && url.pathname === "/api/v1/audit/export") return this.#exportAudit(request, sequence, user, session);
    if (request.method === "POST" && url.pathname === "/api/v1/audit/prune") return this.#pruneAudit(request, sequence, user, session);
    if (url.pathname === "/api/v1/users" || url.pathname.startsWith("/api/v1/users/")) return this.#users(request, url, sequence, user, session);
    if (url.pathname === "/api/v1/sessions" || url.pathname.startsWith("/api/v1/sessions/")) return this.#sessions(request, url, sequence, user, session);
    if (url.pathname === "/api/v1/settings" || url.pathname.startsWith("/api/v1/settings/revisions")) return this.#settings(request, url, sequence, user, session);
    if (request.method === "POST" && ["/api/v1/operations/restart", "/api/v1/operations/shutdown"].includes(url.pathname)) {
      return this.#serviceOperation(request, url, sequence, user, session);
    }

    return json(sequence, { error: { code: "not_implemented", message: "The fixture has no matching canonical route", requestId: requestId(sequence) } }, 501);
  }

  #authenticate(request: Request, sequence: number): { user: User; session: FixtureSession } | Response {
    const token = cookieToken(request);
    const session = token === null ? undefined : this.#state.sessions.get(token);
    const user = session === undefined ? undefined : this.#state.users.find((candidate) => candidate.id === session.session.userId);
    if (session === undefined || user === undefined || user.status !== "active") return apiError(sequence, 401, "authentication_required", "Authentication required");
    return { user, session };
  }

  #validateOriginAndIdempotency(request: Request, sequence: number, requireIfMatch: boolean): Response | null {
    if (request.headers.get("origin") !== this.#publicOrigin) return apiError(sequence, 403, "origin_forbidden", "Exact public Origin required");
    if (request.method === "POST" && !(request.headers.get("idempotency-key")?.trim())) return apiError(sequence, 400, "idempotency_required", "Idempotency-Key required");
    if (requireIfMatch && !(request.headers.get("if-match")?.trim())) return apiError(sequence, 428, "precondition_required", "If-Match required");
    return null;
  }

  #validateMutation(request: Request, sequence: number, session: FixtureSession, requireIfMatch: boolean): Response | null {
    const base = this.#validateOriginAndIdempotency(request, sequence, requireIfMatch);
    if (base !== null) return base;
    if (request.headers.get("x-csrf-token") !== session.csrfToken) return apiError(sequence, 403, "csrf_failed", "Session CSRF token required");
    return null;
  }

  #requireRole(user: User, minimum: Role, sequence: number): Response | null {
    return roleRank(user.role) < roleRank(minimum) ? apiError(sequence, 403, "forbidden", "Role does not permit this operation") : null;
  }

  #requireReauthentication(session: FixtureSession, sequence: number): Response | null {
    return session.reauthenticatedUntil < Date.now() ? apiError(sequence, 403, "reauthentication_required", "Recent password reauthentication required") : null;
  }

  #createSession(user: User, userAgent: string | null): FixtureSession {
    const token = crypto.randomUUID().replaceAll("-", "") + crypto.randomUUID().replaceAll("-", "");
    const id = crypto.randomUUID().replaceAll("-", "").slice(0, 32);
    const session: FixtureSession = {
      token,
      csrfToken: `csrf-${crypto.randomUUID().replaceAll("-", "")}`,
      reauthenticatedUntil: 0,
      session: {
        id,
        userId: user.id,
        username: user.username,
        generation: 1,
        current: true,
        etag: entityTag("session", id, 1),
        createdAt: NOW,
        lastSeenAt: NOW,
        idleExpiresAt: IDLE,
        absoluteExpiresAt: LATER,
        userAgent,
        proxyPeer: "127.0.0.1",
      },
    };
    this.#state.sessions.set(token, session);
    return session;
  }

  #authContext(user: User, session: FixtureSession): AuthContext {
    const latestUser = this.#state.users.find((candidate) => candidate.id === user.id) ?? user;
    return { csrfToken: session.csrfToken, session: session.session, user: latestUser };
  }

  #replaceUser(user: User): void {
    this.#state.users = this.#state.users.map((candidate) => candidate.id === user.id ? user : candidate);
  }

  #overview(): Overview {
    const online = this.#state.runtime.filter((item) => item.liveness === "online").length;
    const suspect = this.#state.runtime.filter((item) => item.liveness === "suspect").length;
    const offline = this.#state.runtime.filter((item) => item.liveness === "offline").length;
    return {
      inventory: { vnrs: this.#state.vnrs.length, nodes: this.#state.nodes.length, routes: this.#state.routes.length },
      runtime: { online, suspect, offline, unknown: this.#state.runtime.length - online - suspect - offline },
      generation: this.#state.generation,
      observedAt: NOW,
      pendingRestart: this.#state.settings.pendingRestart,
      desiredSettingsRevisionId: this.#state.settings.desired.id,
      effectiveSettingsRevisionId: this.#state.settings.effective.id,
      serviceControlEtag: entityTag("service", "control", this.#state.generation),
    };
  }

  #topology(): Topology {
    return { vnrs: this.#state.vnrs, nodes: this.#state.nodes, routes: this.#state.routes, runtime: this.#state.runtime, generation: this.#state.generation, observedAt: NOW };
  }

  #auditPage(role: Role): AuditPage {
    return { items: this.#state.audit.map((entry) => role === "viewer" ? { ...entry, proxyPeer: null, userAgent: null } : entry), nextCursor: null };
  }

  #parseInventoryCidr(
    sequence: number,
    value: string,
    field: "cidr" | "prefix",
    purpose: "vnr" | "route",
  ): Ipv4Cidr | Response {
    let cidr: Ipv4Cidr;
    try {
      cidr = parseIpv4Cidr(value);
    } catch {
      const code = cidrFailureCode(value);
      const message = cidrFailureMessage(code);
      return apiError(sequence, 400, "validation_failed", "Request validation failed", [
        violation(field, code, message),
      ]);
    }

    const prefixIsValid = purpose === "vnr"
      ? cidr.prefixLength >= 1 && cidr.prefixLength <= 30
      : cidr.prefixLength >= 1 && cidr.prefixLength <= 32;
    if (!prefixIsValid) {
      const message = "The IPv4 prefix length is outside the permitted range.";
      return apiError(sequence, 400, "validation_failed", "Request validation failed", [
        violation(field, "prefix_out_of_range", message),
      ]);
    }
    if (isReservedRange(cidr)) {
      const message = "The range overlaps reserved IPv4 address space.";
      return apiError(sequence, 409, "invariant_violation", "Domain invariant would be violated", [
        violation(field, "range_reserved", message),
      ]);
    }
    return cidr;
  }

  #validateVnrRange(
    sequence: number,
    cidr: Ipv4Cidr,
    currentName?: string,
  ): Response | null {
    const overlappingVnr = this.#state.vnrs.find((candidate) =>
      candidate.name !== currentName && rangesOverlap(parseIpv4Cidr(candidate.cidr), cidr)
    );
    if (overlappingVnr !== undefined) {
      const message = `The range overlaps VNR "${overlappingVnr.name}".`;
      return apiError(sequence, 409, "invariant_violation", "Domain invariant would be violated", [
        violation("cidr", "range_overlaps_vnr", message),
      ]);
    }

    const overlappingRoute = this.#state.routes.find((route) => rangesOverlap(parseIpv4Cidr(route.prefix), cidr));
    if (overlappingRoute !== undefined) {
      const message = `The range overlaps a route owned by Node "${overlappingRoute.nodeName}".`;
      return apiError(sequence, 409, "invariant_violation", "Domain invariant would be violated", [
        violation("cidr", "range_overlaps_route", message),
      ]);
    }

    if (currentName === undefined) return null;
    const masterAddress = cidr.network + 1n;
    for (const node of this.#state.nodes) {
      if (node.vnrName !== currentName) continue;
      const address = parseIpv4(node.address);
      if (!containsIpv4(cidr, address)) {
        const message = `The range excludes Node "${node.name}".`;
        return apiError(sequence, 409, "invariant_violation", "Domain invariant would be violated", [
          violation("cidr", "range_excludes_node", message),
        ]);
      }
      if (address === cidr.network || address === masterAddress || address === cidr.broadcast) {
        const message = `The range would reserve Node "${node.name}"'s address.`;
        return apiError(sequence, 409, "invariant_violation", "Domain invariant would be violated", [
          violation("cidr", "range_reserves_node_address", message),
        ]);
      }
    }
    return null;
  }

  #validateNodeState(
    sequence: number,
    input: Readonly<{ name: string; address: string; vnrName: string }>,
    currentId?: string,
  ): Readonly<{ address: bigint; vnr: Vnr }> | Response {
    if (!inventoryNamePattern.test(input.name)) {
      return apiError(sequence, 400, "validation_failed", "Node name is invalid");
    }
    const vnr = this.#state.vnrs.find((candidate) => candidate.name === input.vnrName);
    if (vnr === undefined) return apiError(sequence, 400, "validation_failed", "Selected VNR does not exist");
    const duplicateName = this.#state.nodes.find((candidate) =>
      candidate.id !== currentId && candidate.name === input.name
    );
    if (duplicateName !== undefined) return apiError(sequence, 409, "conflict", "Node name is already in use");

    let address: bigint;
    try {
      address = parseIpv4(input.address);
    } catch {
      const message = "Address must be canonical dotted-decimal IPv4.";
      return apiError(sequence, 400, "validation_failed", "Request validation failed", [
        violation("address", "invalid_ipv4_address", message),
      ]);
    }

    const range = parseIpv4Cidr(vnr.cidr);
    if (!containsIpv4(range, address)) {
      const message = "Address must be a usable host inside the selected VNR.";
      return apiError(sequence, 409, "invariant_violation", "Domain invariant would be violated", [
        violation("address", "address_outside_vnr", message),
      ]);
    }
    const masterAddress = parseIpv4(vnr.masterAddress);
    if (address === range.network || address === masterAddress || address === range.broadcast) {
      const code = address === range.network
        ? "address_reserved_network"
        : address === masterAddress
          ? "address_reserved_master"
          : "address_reserved_broadcast";
      const message = address === range.network
        ? "The VNR network address cannot be assigned to a Node."
        : address === masterAddress
          ? "The VNR Master address cannot be assigned to a Node."
          : "The VNR broadcast address cannot be assigned to a Node.";
      return apiError(sequence, 409, "invariant_violation", "Domain invariant would be violated", [
        violation("address", code, message),
      ]);
    }
    const duplicateAddress = this.#state.nodes.find((candidate) =>
      candidate.id !== currentId && candidate.address === input.address
    );
    if (duplicateAddress !== undefined) {
      const message = `Address is already assigned to Node "${duplicateAddress.name}".`;
      return apiError(sequence, 409, "conflict", "Resource conflicts with current state", [
        violation("address", "address_in_use", message),
      ]);
    }
    return { address, vnr };
  }

  #validateRouteState(
    sequence: number,
    input: Readonly<{ nodeId: string; prefix: string }>,
    currentId?: string,
  ): Readonly<{ node: Node; prefix: Ipv4Cidr }> | Response {
    const node = this.#state.nodes.find((candidate) => candidate.id === input.nodeId);
    if (node === undefined) return apiError(sequence, 400, "validation_failed", "Route owner does not exist");
    const parsed = this.#parseInventoryCidr(sequence, input.prefix, "prefix", "route");
    if (parsed instanceof Response) return parsed;

    const overlappingVnr = this.#state.vnrs.find((vnr) => rangesOverlap(parseIpv4Cidr(vnr.cidr), parsed));
    if (overlappingVnr !== undefined) {
      const message = `The range overlaps VNR "${overlappingVnr.name}".`;
      return apiError(sequence, 409, "invariant_violation", "Domain invariant would be violated", [
        violation("prefix", "range_overlaps_vnr", message),
      ]);
    }
    const sameRoute = this.#state.routes.find((route) => route.id !== currentId && route.prefix === input.prefix);
    if (sameRoute !== undefined) return apiError(sequence, 409, "conflict", "Route already exists");
    const overlappingRoute = this.#state.routes.find((route) =>
      route.id !== currentId && rangesOverlap(parseIpv4Cidr(route.prefix), parsed)
    );
    if (overlappingRoute !== undefined) {
      const message = `The range overlaps a route owned by Node "${overlappingRoute.nodeName}".`;
      return apiError(sequence, 409, "invariant_violation", "Domain invariant would be violated", [
        violation("prefix", "range_overlaps_route", message),
      ]);
    }
    return { node, prefix: parsed };
  }

  async #vnrs(request: Request, sequence: number, user: User, session: FixtureSession): Promise<Response> {
    if (request.method === "GET") return json(sequence, { items: this.#state.vnrs, nextCursor: null });
    const roleError = this.#requireRole(user, "operator", sequence);
    if (roleError !== null) return roleError;
    if (request.method !== "POST") return apiError(sequence, 400, "invalid_request", "Unsupported VNR collection method");
    const validation = this.#validateMutation(request, sequence, session, false);
    if (validation !== null) return validation;
    const body: unknown = await request.json().catch(() => null);
    if (!exactFields(body, ["name", "cidr"]) || typeof body.name !== "string" || typeof body.cidr !== "string") return apiError(sequence, 400, "validation_failed", "Name and CIDR are required");
    if (!inventoryNamePattern.test(body.name)) return apiError(sequence, 400, "validation_failed", "VNR name is invalid");
    if (this.#state.vnrs.some((item) => item.name === body.name)) return apiError(sequence, 409, "conflict", "VNR already exists");
    const parsed = this.#parseInventoryCidr(sequence, body.cidr, "cidr", "vnr");
    if (parsed instanceof Response) return parsed;
    const rangeError = this.#validateVnrRange(sequence, parsed);
    if (rangeError !== null) return rangeError;
    const vnr: Vnr = {
      name: body.name,
      cidr: body.cidr,
      masterAddress: formatIpv4(parsed.network + 1n),
      publicRangeWarning: isPublicRange(parsed),
      generation: 1,
      createdAt: NOW,
      updatedAt: NOW,
    };
    this.#state.vnrs.push(vnr);
    this.#state.generation += 1;
    return json(sequence, vnr, 201, { ETag: entityTag("vnr", vnr.name, vnr.generation), Location: `/api/v1/vnrs/${encodeURIComponent(vnr.name)}` });
  }

  async #vnr(request: Request, sequence: number, user: User, session: FixtureSession, name: string): Promise<Response> {
    const index = this.#state.vnrs.findIndex((item) => item.name === name);
    const current = this.#state.vnrs[index];
    if (current === undefined) return apiError(sequence, 404, "not_found", "VNR not found");
    const etag = entityTag("vnr", current.name, current.generation);
    if (request.method === "GET") return json(sequence, current, 200, { ETag: etag });
    const minimum: Role = request.method === "DELETE" ? "superuser" : "operator";
    const roleError = this.#requireRole(user, minimum, sequence);
    if (roleError !== null) return roleError;
    const validation = this.#validateMutation(request, sequence, session, true);
    if (validation !== null) return validation;
    if (request.headers.get("if-match") !== etag) return apiError(sequence, 412, "precondition_failed", "The VNR changed");
    if (request.method === "PATCH") {
      const body: unknown = await request.json().catch(() => null);
      if (!exactFields(body, ["cidr"]) || typeof body.cidr !== "string") return apiError(sequence, 400, "validation_failed", "CIDR is required");
      const parsed = this.#parseInventoryCidr(sequence, body.cidr, "cidr", "vnr");
      if (parsed instanceof Response) return parsed;
      const rangeError = this.#validateVnrRange(sequence, parsed, current.name);
      if (rangeError !== null) return rangeError;
      const updated: Vnr = {
        ...current,
        cidr: body.cidr,
        masterAddress: formatIpv4(parsed.network + 1n),
        publicRangeWarning: isPublicRange(parsed),
        generation: current.generation + 1,
        updatedAt: NOW,
      };
      this.#state.vnrs[index] = updated;
      this.#state.generation += 1;
      return json(sequence, updated, 200, { ETag: entityTag("vnr", updated.name, updated.generation) });
    }
    if (request.method === "DELETE") {
      const reauth = this.#requireReauthentication(session, sequence);
      if (reauth !== null) return reauth;
      if (this.#state.nodes.some((node) => node.vnrName === current.name)) {
        return apiError(sequence, 409, "invariant_violation", "VNR must have no Nodes before deletion");
      }
      this.#state.vnrs.splice(index, 1);
      this.#state.generation += 1;
      return empty(sequence);
    }
    return apiError(sequence, 400, "invalid_request", "Unsupported VNR method");
  }

  async #nodes(request: Request, sequence: number, user: User, session: FixtureSession): Promise<Response> {
    if (request.method === "GET") return json(sequence, { items: this.#state.nodes, nextCursor: null });
    const roleError = this.#requireRole(user, "operator", sequence);
    if (roleError !== null) return roleError;
    if (request.method !== "POST") return apiError(sequence, 400, "invalid_request", "Unsupported Node collection method");
    const validation = this.#validateMutation(request, sequence, session, false);
    if (validation !== null) return validation;
    const body: unknown = await request.json().catch(() => null);
    if (!exactFields(body, ["name", "address", "vnrName"]) || typeof body.name !== "string" || typeof body.address !== "string" || typeof body.vnrName !== "string") return apiError(sequence, 400, "validation_failed", "Node fields are required");
    const state = this.#validateNodeState(sequence, {
      name: body.name,
      address: body.address,
      vnrName: body.vnrName,
    });
    if (state instanceof Response) return state;
    const id = (this.#state.nodes.length + 100).toString(16).padStart(32, "0");
    const node: Node = { id, name: body.name, address: body.address, vnrName: body.vnrName, enrollmentState: "unenrolled", generation: 1, createdAt: NOW, updatedAt: NOW };
    this.#state.nodes.push(node);
    this.#state.runtime.push({ nodeId: id, liveness: "unknown", sessionState: "disconnected", trafficState: "unknown", observedEndpoint: null, authenticatedRxAt: null, authenticatedTxAt: null, observedAt: NOW });
    this.#state.generation += 1;
    return json(sequence, node, 201, { ETag: entityTag("node", id, 1), Location: `/api/v1/nodes/${id}` });
  }

  async #node(request: Request, sequence: number, user: User, session: FixtureSession, id: string): Promise<Response> {
    const index = this.#state.nodes.findIndex((item) => item.id === id);
    const current = this.#state.nodes[index];
    if (current === undefined) return apiError(sequence, 404, "not_found", "Node not found");
    const etag = entityTag("node", id, current.generation);
    const detail: NodeDetail = { node: current, routes: this.#state.routes.filter((route) => route.nodeId === id), runtime: this.#state.runtime.find((runtime) => runtime.nodeId === id) ?? null };
    if (request.method === "GET") return json(sequence, detail, 200, { ETag: etag });
    const minimum: Role = request.method === "DELETE" ? "superuser" : "operator";
    const roleError = this.#requireRole(user, minimum, sequence);
    if (roleError !== null) return roleError;
    const validation = this.#validateMutation(request, sequence, session, true);
    if (validation !== null) return validation;
    if (request.headers.get("if-match") !== etag) return apiError(sequence, 412, "precondition_failed", "The Node changed");
    if (request.method === "PATCH") {
      const body: unknown = await request.json().catch(() => null);
      if (!exactFields(body, ["name", "address", "vnrName"]) || Object.keys(body).length === 0) {
        return apiError(sequence, 400, "validation_failed", "At least one Node field is required");
      }
      if (
        (body.name !== undefined && typeof body.name !== "string") ||
        (body.address !== undefined && typeof body.address !== "string") ||
        (body.vnrName !== undefined && typeof body.vnrName !== "string")
      ) {
        return apiError(sequence, 400, "validation_failed", "Node fields are invalid");
      }
      const requested = {
        name: typeof body.name === "string" ? body.name : current.name,
        address: typeof body.address === "string" ? body.address : current.address,
        vnrName: typeof body.vnrName === "string" ? body.vnrName : current.vnrName,
      };
      const state = this.#validateNodeState(sequence, requested, current.id);
      if (state instanceof Response) return state;
      const updated: Node = { ...current, ...requested, generation: current.generation + 1, updatedAt: NOW };
      this.#state.nodes[index] = updated;
      if (updated.name !== current.name) {
        this.#state.routes = this.#state.routes.map((route) =>
          route.nodeId === current.id ? { ...route, nodeName: updated.name, updatedAt: NOW } : route
        );
      }
      this.#state.generation += 1;
      return json(sequence, updated, 200, { ETag: entityTag("node", id, updated.generation) });
    }
    if (request.method === "DELETE") {
      const reauth = this.#requireReauthentication(session, sequence);
      if (reauth !== null) return reauth;
      if (this.#state.routes.some((route) => route.nodeId === current.id)) {
        return apiError(sequence, 409, "invariant_violation", "Node must own no routes before deletion");
      }
      this.#state.nodes.splice(index, 1);
      this.#state.runtime = this.#state.runtime.filter((item) => item.nodeId !== id);
      this.#state.generation += 1;
      return empty(sequence);
    }
    return apiError(sequence, 400, "invalid_request", "Unsupported Node method");
  }

  async #enrollmentCredential(request: Request, sequence: number, user: User, session: FixtureSession, id: string): Promise<Response> {
    if (request.method !== "POST") return apiError(sequence, 400, "invalid_request", "Unsupported enrollment method");
    const roleError = this.#requireRole(user, "superuser", sequence);
    if (roleError !== null) return roleError;
    const validation = this.#validateMutation(request, sequence, session, true);
    if (validation !== null) return validation;
    const reauth = this.#requireReauthentication(session, sequence);
    if (reauth !== null) return reauth;
    const node = this.#state.nodes.find((item) => item.id === id);
    if (node === undefined) return apiError(sequence, 404, "not_found", "Node not found");
    if (request.headers.get("if-match") !== entityTag("node", id, node.generation)) return apiError(sequence, 412, "precondition_failed", "The Node changed");
    const credential = `ntip-enroll-v1:${crypto.randomUUID()}:${crypto.randomUUID()}`;
    return new Response(credential, {
      status: 200,
      headers: standardHeaders(sequence, {
        "Content-Type": "application/vnd.ntip.enrollment-credential",
        "Content-Disposition": `attachment; filename="${node.name}.ntip-enrollment"`,
      }),
    });
  }

  async #resetEnrollment(request: Request, sequence: number, user: User, session: FixtureSession, id: string): Promise<Response> {
    if (request.method !== "POST") return apiError(sequence, 400, "invalid_request", "Unsupported enrollment method");
    const roleError = this.#requireRole(user, "superuser", sequence);
    if (roleError !== null) return roleError;
    const validation = this.#validateMutation(request, sequence, session, true);
    if (validation !== null) return validation;
    const reauth = this.#requireReauthentication(session, sequence);
    if (reauth !== null) return reauth;
    const index = this.#state.nodes.findIndex((item) => item.id === id);
    const node = this.#state.nodes[index];
    if (node === undefined) return apiError(sequence, 404, "not_found", "Node not found");
    const updated: Node = { ...node, enrollmentState: "unenrolled", generation: node.generation + 1, updatedAt: NOW };
    this.#state.nodes[index] = updated;
    return json(sequence, updated, 200, { ETag: entityTag("node", id, updated.generation) });
  }

  async #routes(request: Request, sequence: number, user: User, session: FixtureSession): Promise<Response> {
    if (request.method === "GET") return json(sequence, { items: this.#state.routes, nextCursor: null });
    const roleError = this.#requireRole(user, "operator", sequence);
    if (roleError !== null) return roleError;
    if (request.method !== "POST") return apiError(sequence, 400, "invalid_request", "Unsupported Route collection method");
    const validation = this.#validateMutation(request, sequence, session, false);
    if (validation !== null) return validation;
    const body: unknown = await request.json().catch(() => null);
    if (!exactFields(body, ["nodeId", "prefix"]) || typeof body.nodeId !== "string" || typeof body.prefix !== "string") {
      return apiError(sequence, 400, "validation_failed", "Route owner and prefix are required");
    }
    const state = this.#validateRouteState(sequence, { nodeId: body.nodeId, prefix: body.prefix });
    if (state instanceof Response) return state;
    const id = (this.#state.routes.length + 200).toString(16).padStart(32, "0");
    const route: Route = { id, nodeId: state.node.id, nodeName: state.node.name, prefix: body.prefix, generation: 1, createdAt: NOW, updatedAt: NOW };
    this.#state.routes.push(route);
    this.#state.generation += 1;
    return json(sequence, route, 201, { ETag: entityTag("route", id, 1), Location: `/api/v1/routes/${id}` });
  }

  async #routeResource(request: Request, sequence: number, user: User, session: FixtureSession, id: string): Promise<Response> {
    const index = this.#state.routes.findIndex((item) => item.id === id);
    const current = this.#state.routes[index];
    if (current === undefined) return apiError(sequence, 404, "not_found", "Route not found");
    const etag = entityTag("route", id, current.generation);
    if (request.method === "GET") return json(sequence, current, 200, { ETag: etag });
    const minimum: Role = request.method === "DELETE" ? "superuser" : "operator";
    const roleError = this.#requireRole(user, minimum, sequence);
    if (roleError !== null) return roleError;
    const validation = this.#validateMutation(request, sequence, session, true);
    if (validation !== null) return validation;
    if (request.headers.get("if-match") !== etag) return apiError(sequence, 412, "precondition_failed", "The Route changed");
    if (request.method === "PATCH") {
      const body: unknown = await request.json().catch(() => null);
      if (!exactFields(body, ["nodeId", "prefix"]) || Object.keys(body).length === 0) {
        return apiError(sequence, 400, "validation_failed", "At least one Route field is required");
      }
      if (
        (body.nodeId !== undefined && typeof body.nodeId !== "string") ||
        (body.prefix !== undefined && typeof body.prefix !== "string")
      ) {
        return apiError(sequence, 400, "validation_failed", "Route fields are invalid");
      }
      const requested = {
        nodeId: typeof body.nodeId === "string" ? body.nodeId : current.nodeId,
        prefix: typeof body.prefix === "string" ? body.prefix : current.prefix,
      };
      const state = this.#validateRouteState(sequence, requested, current.id);
      if (state instanceof Response) return state;
      const updated: Route = {
        ...current,
        ...requested,
        nodeName: state.node.name,
        generation: current.generation + 1,
        updatedAt: NOW,
      };
      this.#state.routes[index] = updated;
      this.#state.generation += 1;
      return json(sequence, updated, 200, { ETag: entityTag("route", id, updated.generation) });
    }
    if (request.method === "DELETE") {
      const reauth = this.#requireReauthentication(session, sequence);
      if (reauth !== null) return reauth;
      this.#state.routes.splice(index, 1);
      this.#state.generation += 1;
      return empty(sequence);
    }
    return apiError(sequence, 400, "invalid_request", "Unsupported Route method");
  }

  async #connectivityChecks(request: Request, sequence: number, user: User, session: FixtureSession): Promise<Response> {
    if (request.method === "GET") {
      const nodeId = new URL(request.url).searchParams.get("nodeId");
      const items = nodeId === null ? this.#state.checks : this.#state.checks.filter((item) => item.nodeId === nodeId);
      const page: ConnectivityCheckPage = { items, nextCursor: null };
      return json(sequence, page);
    }
    const roleError = this.#requireRole(user, "operator", sequence);
    if (roleError !== null) return roleError;
    const validation = this.#validateMutation(request, sequence, session, false);
    if (validation !== null) return validation;
    const body = await request.json() as { nodeId: string; timeoutMilliseconds: number };
    const node = this.#state.nodes.find((item) => item.id === body.nodeId);
    if (node === undefined) return apiError(sequence, 400, "validation_failed", "Node does not exist");
    const id = (this.#state.checks.length + 300).toString(16).padStart(32, "0");
    const check: ConnectivityCheck = { id, nodeId: node.id, nodeAddress: node.address, status: "queued", timeoutMilliseconds: body.timeoutMilliseconds, roundTripMilliseconds: null, failureCode: null, createdAt: NOW, startedAt: null, completedAt: null };
    this.#state.checks.unshift(check);
    return json(sequence, check, 202, { Location: `/api/v1/connectivity-checks/${id}` });
  }

  async #exportAudit(request: Request, sequence: number, user: User, session: FixtureSession): Promise<Response> {
    const roleError = this.#requireRole(user, "superuser", sequence);
    if (roleError !== null) return roleError;
    const validation = this.#validateMutation(request, sequence, session, true);
    if (validation !== null) return validation;
    const reauth = this.#requireReauthentication(session, sequence);
    if (reauth !== null) return reauth;
    const exportId = crypto.randomUUID().replaceAll("-", "").slice(0, 32);
    const ndjson = this.#state.audit.map((entry) => JSON.stringify(entry)).join("\n") + "\n";
    return new Response(ndjson, { status: 200, headers: standardHeaders(sequence, { "Content-Type": "application/x-ndjson", "Content-Disposition": `attachment; filename="ntip-audit-${ids.audit}.ndjson"`, "X-NTIP-Audit-Export-ID": exportId }) });
  }

  async #pruneAudit(request: Request, sequence: number, user: User, session: FixtureSession): Promise<Response> {
    const roleError = this.#requireRole(user, "superuser", sequence);
    if (roleError !== null) return roleError;
    const validation = this.#validateMutation(request, sequence, session, true);
    if (validation !== null) return validation;
    const reauth = this.#requireReauthentication(session, sequence);
    if (reauth !== null) return reauth;
    const body = await request.json() as { exportId: string; throughAuditId: string };
    const pruned = this.#state.audit.length;
    this.#state.audit = [];
    return json(sequence, { exportId: body.exportId, throughAuditId: body.throughAuditId, prunedEntries: pruned, prunedAt: NOW });
  }

  async #users(request: Request, url: URL, sequence: number, user: User, session: FixtureSession): Promise<Response> {
    const roleError = this.#requireRole(user, "superuser", sequence);
    if (roleError !== null) return roleError;
    if (url.pathname === "/api/v1/users") {
      if (request.method === "GET") return json(sequence, { items: this.#state.users, nextCursor: null });
      const validation = this.#validateMutation(request, sequence, session, false);
      if (validation !== null) return validation;
      const body = await request.json() as { username: string; role: Role };
      const id = (this.#state.users.length + 700).toString(16).padStart(32, "0");
      const created: User = { id, username: body.username.toLowerCase(), role: body.role, status: "active", mustChangePassword: true, generation: 1, createdAt: NOW, updatedAt: NOW };
      const temporaryPassword = `ntip-temp-${crypto.randomUUID()}-A9`;
      this.#state.users.push(created);
      this.#state.passwords.set(id, temporaryPassword);
      return json(sequence, { user: created, temporaryPassword }, 201, { ETag: entityTag("user", id, 1), Location: `/api/v1/users/${id}` });
    }
    const passwordResetMatch = /^\/api\/v1\/users\/([0-9a-f]{32})\/password-reset$/.exec(url.pathname);
    const id = passwordResetMatch?.[1] ?? /^\/api\/v1\/users\/([0-9a-f]{32})$/.exec(url.pathname)?.[1];
    const index = id === undefined ? -1 : this.#state.users.findIndex((candidate) => candidate.id === id);
    const current = this.#state.users[index];
    if (current === undefined) return apiError(sequence, 404, "not_found", "User not found");
    const etag = entityTag("user", current.id, current.generation);
    if (request.method === "GET") return json(sequence, current, 200, { ETag: etag });
    const validation = this.#validateMutation(request, sequence, session, true);
    if (validation !== null) return validation;
    const reauth = this.#requireReauthentication(session, sequence);
    if (reauth !== null) return reauth;
    if (request.headers.get("if-match") !== etag) return apiError(sequence, 412, "precondition_failed", "The User changed");
    if (passwordResetMatch !== null && request.method === "POST") {
      const temporaryPassword = `ntip-temp-${crypto.randomUUID()}-B7`;
      const updated = { ...current, mustChangePassword: true, generation: current.generation + 1, updatedAt: NOW };
      this.#state.users[index] = updated;
      this.#state.passwords.set(current.id, temporaryPassword);
      return json(sequence, { user: updated, temporaryPassword }, 200, { ETag: entityTag("user", current.id, updated.generation) });
    }
    if (request.method === "PATCH") {
      const body = await request.json() as { enabled?: boolean; role?: Role };
      const updated: User = { ...current, ...(body.role === undefined ? {} : { role: body.role }), ...(body.enabled === undefined ? {} : { status: body.enabled ? "active" : "disabled" }), generation: current.generation + 1, updatedAt: NOW };
      this.#state.users[index] = updated;
      return json(sequence, updated, 200, { ETag: entityTag("user", current.id, updated.generation) });
    }
    if (request.method === "DELETE") {
      this.#state.users[index] = { ...current, status: "tombstoned", generation: current.generation + 1, updatedAt: NOW };
      return empty(sequence);
    }
    return apiError(sequence, 400, "invalid_request", "Unsupported User method");
  }

  async #sessions(request: Request, url: URL, sequence: number, user: User, session: FixtureSession): Promise<Response> {
    if (url.pathname === "/api/v1/sessions" && request.method === "GET") {
      const all = url.searchParams.get("scope") === "all";
      if (all && user.role !== "superuser") return apiError(sequence, 403, "forbidden", "Only superusers can list every session");
      const live = [...this.#state.sessions.values()].map((item) => item.session);
      const other: Session = { id: ids.sessionOther, userId: ids.userOperator, username: "operator", generation: 1, current: false, etag: entityTag("session", ids.sessionOther, 1), createdAt: NOW, lastSeenAt: NOW, idleExpiresAt: IDLE, absoluteExpiresAt: LATER, userAgent: "Firefox fixture", proxyPeer: "127.0.0.1" };
      const items = all ? [...live, other] : live.filter((item) => item.userId === user.id);
      return json(sequence, { items, nextCursor: null });
    }
    const match = /^\/api\/v1\/sessions\/([0-9a-f]{32})$/.exec(url.pathname);
    if (request.method !== "DELETE" || match?.[1] === undefined) return apiError(sequence, 400, "invalid_request", "Unsupported Session method");
    const validation = this.#validateMutation(request, sequence, session, true);
    if (validation !== null) return validation;
    const target = [...this.#state.sessions.values()].find((item) => item.session.id === match[1]);
    if (target === undefined && match[1] !== ids.sessionOther) return apiError(sequence, 404, "not_found", "Session not found");
    if (target !== undefined && target.session.userId !== user.id && user.role !== "superuser") return apiError(sequence, 403, "forbidden", "Cannot revoke another user's session");
    if (target !== undefined) this.#state.sessions.delete(target.token);
    return empty(sequence);
  }

  async #settings(request: Request, url: URL, sequence: number, user: User, session: FixtureSession): Promise<Response> {
    if (url.pathname === "/api/v1/settings" && request.method === "GET") return json(sequence, this.#state.settings, 200, { ETag: entityTag("settings", "desired", this.#state.settings.desired.sequence) });
    if (url.pathname === "/api/v1/settings/revisions" && request.method === "GET") return json(sequence, { items: this.#state.revisions, nextCursor: null });
    const roleError = this.#requireRole(user, "superuser", sequence);
    if (roleError !== null) return roleError;
    const validation = this.#validateMutation(request, sequence, session, true);
    if (validation !== null) return validation;
    const reauth = this.#requireReauthentication(session, sequence);
    if (reauth !== null) return reauth;
    const currentEtag = entityTag("settings", "desired", this.#state.settings.desired.sequence);
    if (request.headers.get("if-match") !== currentEtag) return apiError(sequence, 412, "precondition_failed", "Settings changed");
    let nextSettings: OperationalSettings;
    if (url.pathname === "/api/v1/settings" && request.method === "PATCH") {
      const body = await request.json() as Partial<OperationalSettings>;
      nextSettings = { ...this.#state.settings.desired.settings, ...body };
    } else {
      const rollbackMatch = /^\/api\/v1\/settings\/revisions\/([0-9a-f]{32})\/rollback$/.exec(url.pathname);
      const target = rollbackMatch === null ? undefined : this.#state.revisions.find((item) => item.id === rollbackMatch[1]);
      if (request.method !== "POST" || target === undefined) return apiError(sequence, 404, "not_found", "Settings revision not found");
      nextSettings = target.settings;
    }
    const nextSequence = this.#state.settings.desired.sequence + 1;
    const revision: SettingsRevision = { ...activeRevision, id: (0x5100 + nextSequence).toString(16).padStart(32, "0"), sequence: nextSequence, settings: nextSettings, status: nextSettings.maximumNodes !== this.#state.settings.effective.settings.maximumNodes ? "pending_restart" : "active" };
    this.#state.revisions.unshift(revision);
    this.#state.settings = { desired: revision, effective: revision.status === "active" ? revision : this.#state.settings.effective, pendingRestart: revision.status === "pending_restart" };
    return json(sequence, revision, 202, { ETag: entityTag("settings", "desired", nextSequence), Location: `/api/v1/settings/revisions/${revision.id}` });
  }

  async #serviceOperation(request: Request, url: URL, sequence: number, user: User, session: FixtureSession): Promise<Response> {
    const roleError = this.#requireRole(user, "superuser", sequence);
    if (roleError !== null) return roleError;
    const validation = this.#validateMutation(request, sequence, session, true);
    if (validation !== null) return validation;
    const reauth = this.#requireReauthentication(session, sequence);
    if (reauth !== null) return reauth;
    if (request.headers.get("if-match") !== this.#overview().serviceControlEtag) return apiError(sequence, 412, "precondition_failed", "Service state changed");
    const kind = url.pathname.endsWith("restart") ? "restart" : "shutdown";
    const operation: AcceptedOperation = { id: crypto.randomUUID().replaceAll("-", "").slice(0, 32), kind, acceptedAt: NOW };
    if (kind === "restart") {
      // Model the managed process cycling twice before readiness returns so the
      // dashboard's stale/recovery state is exercised against real polling.
      this.#state.faults.push({ path: "/api/v1/health/ready", status: 503, delayMilliseconds: 0, remaining: 2 });
    }
    return json(sequence, operation, 202);
  }
}
