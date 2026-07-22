import { lstat, realpath } from "node:fs/promises";
import { dirname, join } from "node:path";

const MAXIMUM_REQUEST_BODY_BYTES = 64 * 1024;
const MAXIMUM_REDEMPTION_BODY_BYTES = 128;
const API_TIMEOUT_MILLISECONDS = 65_000;
const PUBLIC_BOOTSTRAP_TIMEOUT_MILLISECONDS = 30_000;
const PAGE_TIMEOUT_MILLISECONDS = 65_000;
const REDEMPTION_BUCKET_CAPACITY = 6;
const REDEMPTION_REFILL_PER_MILLISECOND = 10 / 60_000;
const MAXIMUM_REDEMPTION_PEERS = 1_024;

const bootstrapIdPattern = /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$/;
const bootstrapAssetPattern = /^(ntip-node-v[A-Za-z0-9][A-Za-z0-9.+-]{0,63}-(?:x86_64|aarch64)-linux-musl(?:\.tar\.gz(?:\.sha256)?|\.spdx\.json))$/;
const hopByHopHeaders = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
] as const;
const anonymousHeaders = [
  "authorization",
  "cookie",
  "forwarded",
  "origin",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
] as const;

type UpstreamFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export type HttpGatewayOptions = Readonly<{
  apiOrigin: string;
  assetsRoot: string;
  nextOrigin: string;
  fetchUpstream?: UpstreamFetch;
  now?: () => number;
}>;

export type HttpGatewayServerOptions = HttpGatewayOptions & Readonly<{
  hostname: string;
  port: number;
}>;

type RedemptionPeer = {
  lastSeen: number;
  tokens: number;
};

function requestId(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

function bootstrapError(
  status: number,
  code: "bootstrap_unavailable" | "invalid_request" | "rate_limited" | "service_unavailable",
  message: string,
  options: Readonly<{ allow?: "GET" | "POST"; retryAfter?: string }> = {},
): Response {
  const id = requestId();
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "X-Request-ID": id,
  });
  if (options.allow !== undefined) headers.set("Allow", options.allow);
  if (options.retryAfter !== undefined) headers.set("Retry-After", options.retryAfter);
  return Response.json(
    { error: { code, message }, requestId: id },
    { status, headers },
  );
}

function assetNotFound(): Response {
  return new Response(null, {
    status: 404,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function bodyTooLarge(): Response {
  return bootstrapError(413, "invalid_request", "Request body is too large.");
}

function contentLength(request: Request): number | null {
  const raw = request.headers.get("content-length");
  if (raw === null || !/^(?:0|[1-9][0-9]*)$/.test(raw)) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}

function removeHopByHop(headers: Headers): void {
  const connection = headers.get("connection");
  if (connection !== null) {
    for (const token of connection.split(",")) {
      const name = token.trim().toLowerCase();
      if (/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) headers.delete(name);
    }
  }
  for (const name of hopByHopHeaders) headers.delete(name);
}

function incomingBodyAllowed(request: Request, maximumBytes: number): boolean {
  const declared = contentLength(request);
  return declared === null || declared <= maximumBytes;
}

async function requestBody(request: Request, maximumBytes: number): Promise<ArrayBuffer | undefined> {
  if (request.method === "GET" || request.method === "HEAD" || request.body === null) return undefined;
  const body = await request.arrayBuffer();
  if (body.byteLength > maximumBytes) throw new RangeError("request body is too large");
  return body;
}

function responseFromUpstream(upstream: Response, forceNoStore: boolean): Response {
  const headers = new Headers(upstream.headers);
  removeHopByHop(headers);
  // The loopback fetch is explicitly identity encoded. Dropping framing here
  // also avoids retaining a stale Content-Length if Bun decoded defensively.
  headers.delete("content-encoding");
  headers.delete("content-length");
  if (forceNoStore) {
    headers.set("Cache-Control", "no-store");
    headers.set("X-Content-Type-Options", "nosniff");
    headers.delete("Set-Cookie");
  }
  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  });
}

async function forward(
  request: Request,
  targetOrigin: string,
  options: Readonly<{
    anonymous?: boolean;
    forceNoStore?: boolean;
    maximumBodyBytes?: number;
    requireExactContentLength?: boolean;
    rejectRedirect?: boolean;
    timeoutMilliseconds: number;
    upstreamConnectionClose?: boolean;
  }>,
  fetchUpstream: UpstreamFetch,
): Promise<Response> {
  const incoming = new URL(request.url);
  const target = new URL(`${incoming.pathname}${incoming.search}`, targetOrigin);
  const maximumBodyBytes = options.maximumBodyBytes ?? MAXIMUM_REQUEST_BODY_BYTES;
  if (!incomingBodyAllowed(request, maximumBodyBytes)) return bodyTooLarge();

  let body: ArrayBuffer | undefined;
  try {
    body = await requestBody(request, maximumBodyBytes);
  } catch (error) {
    if (error instanceof RangeError) return bodyTooLarge();
    throw error;
  }
  if (
    options.requireExactContentLength === true &&
    contentLength(request) !== (body?.byteLength ?? 0)
  ) return bootstrapError(400, "invalid_request", "Bootstrap request is invalid.");

  const headers = new Headers(request.headers);
  removeHopByHop(headers);
  headers.set("accept-encoding", "identity");
  headers.set("host", incoming.host);
  if (options.upstreamConnectionClose === true) headers.set("connection", "close");
  if (options.anonymous === true) {
    for (const name of anonymousHeaders) headers.delete(name);
  }
  if (body === undefined) headers.delete("content-length");
  else headers.set("content-length", String(body.byteLength));

  try {
    const upstream = await fetchUpstream(target, {
      method: request.method,
      headers,
      ...(body === undefined ? {} : { body }),
      redirect: "manual",
      signal: AbortSignal.any([
        request.signal,
        AbortSignal.timeout(options.timeoutMilliseconds),
      ]),
    });
    if (options.rejectRedirect === true && upstream.status >= 300 && upstream.status < 400) {
      return bootstrapError(503, "service_unavailable", "Bootstrap service is unavailable.", { retryAfter: "1" });
    }
    return responseFromUpstream(upstream, options.forceNoStore === true);
  } catch {
    if (options.forceNoStore === true) {
      return bootstrapError(503, "service_unavailable", "Bootstrap service is unavailable.", { retryAfter: "1" });
    }
    return new Response("upstream unavailable", {
      status: 502,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "text/plain; charset=utf-8",
      },
    });
  }
}

class RedemptionRateLimiter {
  readonly #now: () => number;
  readonly #peers = new Map<string, RedemptionPeer>();

  constructor(now: () => number) {
    this.#now = now;
  }

  admit(peerAddress: string): boolean {
    const now = this.#now();
    let peer = this.#peers.get(peerAddress);
    if (peer === undefined) {
      if (this.#peers.size >= MAXIMUM_REDEMPTION_PEERS) {
        let oldestAddress: string | null = null;
        let oldestSeen = Number.POSITIVE_INFINITY;
        for (const [address, candidate] of this.#peers) {
          if (candidate.lastSeen < oldestSeen) {
            oldestAddress = address;
            oldestSeen = candidate.lastSeen;
          }
        }
        if (oldestAddress !== null) this.#peers.delete(oldestAddress);
      }
      peer = { lastSeen: now, tokens: REDEMPTION_BUCKET_CAPACITY };
      this.#peers.set(peerAddress, peer);
    } else {
      const elapsed = Math.max(0, now - peer.lastSeen);
      peer.tokens = Math.min(
        REDEMPTION_BUCKET_CAPACITY,
        peer.tokens + elapsed * REDEMPTION_REFILL_PER_MILLISECOND,
      );
      peer.lastSeen = now;
    }
    if (peer.tokens < 1) return false;
    peer.tokens -= 1;
    return true;
  }
}

async function serveAsset(request: Request, assetsRoot: string, basename: string): Promise<Response> {
  if (request.method !== "GET") {
    return bootstrapError(405, "invalid_request", "Bootstrap request method is not allowed.", { allow: "GET" });
  }
  if (request.headers.has("transfer-encoding") || request.headers.has("content-length")) {
    return bootstrapError(400, "invalid_request", "Bootstrap request is invalid.");
  }

  try {
    const canonicalRoot = await realpath(assetsRoot);
    const candidate = join(canonicalRoot, basename);
    const metadata = await lstat(candidate);
    const canonicalCandidate = await realpath(candidate);
    if (
      metadata.isSymbolicLink() ||
      !metadata.isFile() ||
      dirname(canonicalCandidate) !== canonicalRoot
    ) return assetNotFound();
    return new Response(Bun.file(canonicalCandidate), {
      status: 200,
      headers: {
        "Cache-Control": "public, max-age=31536000, immutable",
        "Content-Type": "application/octet-stream",
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch {
    return assetNotFound();
  }
}

export function createHttpGatewayHandler(options: HttpGatewayOptions) {
  const fetchUpstream = options.fetchUpstream ?? fetch;
  const rateLimiter = new RedemptionRateLimiter(options.now ?? performance.now.bind(performance));

  return async (request: Request, peerAddress = "unknown"): Promise<Response> => {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith("/api/v1/")) {
      return forward(request, options.apiOrigin, {
        timeoutMilliseconds: API_TIMEOUT_MILLISECONDS,
        upstreamConnectionClose: true,
      }, fetchUpstream);
    }

    if (path === "/enrollment/v1/redeem") {
      if (request.method !== "POST") {
        return bootstrapError(405, "invalid_request", "Bootstrap request method is not allowed.", { allow: "POST" });
      }
      const declared = contentLength(request);
      if (
        request.headers.has("transfer-encoding") ||
        declared === null ||
        declared === 0
      ) return bootstrapError(400, "invalid_request", "Bootstrap request is invalid.");
      if (declared > MAXIMUM_REDEMPTION_BODY_BYTES) return bodyTooLarge();
      if (request.headers.get("content-type")?.toLowerCase() !== "application/json") {
        return bootstrapError(415, "invalid_request", "Bootstrap request must use application/json.");
      }
      if (request.headers.has("origin")) {
        return bootstrapError(400, "invalid_request", "Bootstrap request is invalid.");
      }
      if (!rateLimiter.admit(peerAddress)) {
        return bootstrapError(429, "rate_limited", "Bootstrap redemption is temporarily rate limited.", { retryAfter: "60" });
      }
      return forward(request, options.apiOrigin, {
        anonymous: true,
        forceNoStore: true,
        maximumBodyBytes: MAXIMUM_REDEMPTION_BODY_BYTES,
        rejectRedirect: true,
        requireExactContentLength: true,
        timeoutMilliseconds: PUBLIC_BOOTSTRAP_TIMEOUT_MILLISECONDS,
        upstreamConnectionClose: true,
      }, fetchUpstream);
    }

    const enrollmentPrefix = "/enrollment/";
    if (path.startsWith(`${enrollmentPrefix}assets/`)) {
      if (url.search !== "") return assetNotFound();
      const basename = path.slice(`${enrollmentPrefix}assets/`.length);
      const match = bootstrapAssetPattern.exec(basename);
      if (match?.[1] === undefined) return assetNotFound();
      return serveAsset(request, options.assetsRoot, match[1]);
    }

    if (path.startsWith(enrollmentPrefix)) {
      const identifier = path.slice(enrollmentPrefix.length);
      if (url.search !== "" || !bootstrapIdPattern.test(identifier)) {
        return bootstrapError(404, "bootstrap_unavailable", "Bootstrap invitation is unavailable.");
      }
      if (request.method !== "GET") {
        return bootstrapError(405, "invalid_request", "Bootstrap request method is not allowed.", { allow: "GET" });
      }
      if (request.headers.has("transfer-encoding") || request.headers.has("content-length")) {
        return bootstrapError(400, "invalid_request", "Bootstrap request is invalid.");
      }
      return forward(request, options.apiOrigin, {
        anonymous: true,
        forceNoStore: true,
        rejectRedirect: true,
        timeoutMilliseconds: PUBLIC_BOOTSTRAP_TIMEOUT_MILLISECONDS,
        upstreamConnectionClose: true,
      }, fetchUpstream);
    }

    return forward(request, options.nextOrigin, {
      timeoutMilliseconds: PAGE_TIMEOUT_MILLISECONDS,
    }, fetchUpstream);
  };
}

export function startHttpGateway(options: HttpGatewayServerOptions): ReturnType<typeof Bun.serve> {
  const handle = createHttpGatewayHandler(options);
  return Bun.serve({
    hostname: options.hostname,
    port: options.port,
    idleTimeout: 70,
    maxRequestBodySize: MAXIMUM_REQUEST_BODY_BYTES,
    fetch(request, server) {
      return handle(request, server.requestIP(request)?.address ?? "unknown");
    },
    error() {
      return new Response("gateway request failed", {
        status: 500,
        headers: {
          "Cache-Control": "no-store",
          "Content-Type": "text/plain; charset=utf-8",
        },
      });
    },
  });
}
