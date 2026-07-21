import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { FixtureApi } from "../test/e2e/fixture-api";

const PINNED_BUN_VERSION = "1.3.14";

export interface DashboardHarnessOptions {
  readonly apiPort?: number;
  readonly controlPort?: number;
  readonly httpsPort?: number;
  readonly nextPort?: number;
  readonly quiet?: boolean;
}

export interface DashboardHarness {
  readonly controlOrigin: string;
  readonly publicOrigin: string;
  close(): Promise<number>;
}

function checkedPort(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1024 || value > 65_535) throw new RangeError(`${name} must be an unprivileged TCP port`);
  return value;
}

async function createCertificate(): Promise<Readonly<{ directory: string; certificatePath: string; keyPath: string }>> {
  const directory = await mkdtemp(join(tmpdir(), "ntip-dashboard-e2e-"));
  const certificatePath = join(directory, "certificate.pem");
  const keyPath = join(directory, "private-key.pem");
  const configurationPath = join(directory, "openssl.cnf");
  await Bun.write(configurationPath, [
    "[req]",
    "distinguished_name = subject",
    "x509_extensions = extensions",
    "prompt = no",
    "[subject]",
    "CN = 127.0.0.1",
    "[extensions]",
    "subjectAltName = @alternative_names",
    "keyUsage = critical, digitalSignature, keyEncipherment",
    "extendedKeyUsage = serverAuth",
    "[alternative_names]",
    "IP.1 = 127.0.0.1",
    "DNS.1 = localhost",
    "",
  ].join("\n"));
  const generated = Bun.spawnSync([
    "openssl",
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-sha256",
    "-days",
    "1",
    "-nodes",
    "-config",
    configurationPath,
    "-keyout",
    keyPath,
    "-out",
    certificatePath,
  ], { stdout: "ignore", stderr: "pipe" });
  if (!generated.success) {
    const detail = new TextDecoder().decode(generated.stderr).trim();
    await rm(directory, { recursive: true, force: true });
    throw new Error(`temporary TLS certificate generation failed: ${detail}`);
  }
  return { directory, certificatePath, keyPath };
}

async function waitFor(url: string, timeoutMilliseconds: number): Promise<void> {
  const deadline = Date.now() + timeoutMilliseconds;
  let lastError: unknown = null;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(1_000) });
      if (response.status < 500) return;
      lastError = new Error(`readiness returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await Bun.sleep(100);
  }
  const detail = lastError instanceof Error ? lastError.message : "unknown readiness failure";
  throw new Error(`timed out waiting for ${url}: ${detail}`);
}

async function forward(request: Request, targetOrigin: string): Promise<Response> {
  const incoming = new URL(request.url);
  const target = new URL(`${incoming.pathname}${incoming.search}`, targetOrigin);
  const headers = new Headers(request.headers);
  headers.set("host", target.host);
  headers.set("x-forwarded-host", incoming.host);
  headers.set("x-forwarded-proto", incoming.protocol.slice(0, -1));
  headers.set("accept-encoding", "identity");
  headers.delete("content-length");
  for (const name of ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"]) {
    headers.delete(name);
  }
  const body = request.method === "GET" || request.method === "HEAD" ? undefined : await request.arrayBuffer();
  try {
    const upstream = await fetch(target, {
      method: request.method,
      headers,
      ...(body === undefined ? {} : { body }),
      redirect: "manual",
    });
    const responseHeaders = new Headers(upstream.headers);
    // Bun transparently decodes upstream compression. Recomputing framing here
    // prevents a browser from waiting for the encoded Content-Length.
    responseHeaders.delete("content-encoding");
    responseHeaders.delete("content-length");
    responseHeaders.delete("transfer-encoding");
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    });
  } catch {
    return new Response("upstream unavailable", {
      status: 502,
      headers: { "Cache-Control": "no-store", "Content-Type": "text/plain; charset=utf-8" },
    });
  }
}

export async function startDashboardHarness(options: DashboardHarnessOptions = {}): Promise<DashboardHarness> {
  if (Bun.version !== PINNED_BUN_VERSION) throw new Error(`dashboard verification requires Bun ${PINNED_BUN_VERSION}; received ${Bun.version}`);

  const apiPort = checkedPort(options.apiPort ?? Number(process.env.NTIP_E2E_API_PORT ?? "8789"), "apiPort");
  const controlPort = checkedPort(options.controlPort ?? Number(process.env.NTIP_E2E_CONTROL_PORT ?? "8790"), "controlPort");
  const httpsPort = checkedPort(options.httpsPort ?? Number(process.env.NTIP_E2E_HTTPS_PORT ?? "3443"), "httpsPort");
  const nextPort = checkedPort(options.nextPort ?? Number(process.env.NTIP_E2E_NEXT_PORT ?? "3100"), "nextPort");
  if (new Set([apiPort, controlPort, httpsPort, nextPort]).size !== 4) throw new Error("dashboard harness ports must be distinct");

  const applicationRoot = resolve(import.meta.dirname, "..");
  const buildIdPath = join(applicationRoot, ".next", "BUILD_ID");
  const buildId = (await readFile(buildIdPath, "utf8").catch(() => "")).trim();
  if (buildId.length === 0) throw new Error("production build is missing; run bun --bun next build first");
  const standaloneRoot = join(applicationRoot, ".next", "standalone");
  const standaloneDashboardRoot = join(standaloneRoot, "apps", "dashboard");
  const standaloneServer = join(standaloneDashboardRoot, "server.js");
  await access(standaloneServer);
  const standaloneLauncher = join(applicationRoot, "scripts", "start-standalone.ts");
  await access(standaloneLauncher);

  const publicOrigin = `https://127.0.0.1:${httpsPort}`;
  const apiOrigin = `http://127.0.0.1:${apiPort}`;
  const controlOrigin = `http://127.0.0.1:${controlPort}`;
  const nextOrigin = `http://127.0.0.1:${nextPort}`;
  const fixture = new FixtureApi({ publicOrigin });
  const certificate = await createCertificate();

  const apiServer = Bun.serve({
    hostname: "127.0.0.1",
    port: apiPort,
    fetch: (request) => fixture.handle(request),
  });

  const controlServer = Bun.serve({
    hostname: "127.0.0.1",
    port: controlPort,
    async fetch(request) {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/ready") return Response.json({ status: "ready", buildId }, { headers: { "Cache-Control": "no-store" } });
      if (request.method === "POST" && url.pathname === "/reset") {
        fixture.reset();
        return new Response(null, { status: 204 });
      }
      if (request.method === "POST" && url.pathname === "/metrics/reset") {
        fixture.resetMetrics();
        return new Response(null, { status: 204 });
      }
      if (request.method === "DELETE" && url.pathname === "/faults") {
        fixture.clearFaults();
        return new Response(null, { status: 204 });
      }
      if (request.method === "POST" && url.pathname === "/fault") {
        const body: unknown = await request.json().catch(() => null);
        if (body === null || typeof body !== "object" || !("path" in body) || typeof body.path !== "string" || !body.path.startsWith("/api/v1/")) {
          return Response.json({ error: "path must name an /api/v1 fixture route" }, { status: 400 });
        }
        const status = "status" in body && typeof body.status === "number" ? body.status : undefined;
        const afterRoute = "afterRoute" in body && typeof body.afterRoute === "boolean" ? body.afterRoute : undefined;
        const delayMilliseconds = "delayMilliseconds" in body && typeof body.delayMilliseconds === "number" ? body.delayMilliseconds : undefined;
        const remaining = "remaining" in body && typeof body.remaining === "number" ? body.remaining : undefined;
        fixture.addFault({ path: body.path, ...(status === undefined ? {} : { status }), ...(afterRoute === undefined ? {} : { afterRoute }), ...(delayMilliseconds === undefined ? {} : { delayMilliseconds }), ...(remaining === undefined ? {} : { remaining }) });
        return new Response(null, { status: 204 });
      }
      if (request.method === "GET" && url.pathname === "/snapshot") return Response.json(fixture.snapshot(), { headers: { "Cache-Control": "no-store" } });
      return Response.json({ error: "unknown control route" }, { status: 404 });
    },
  });

  // Exercise the same checked standalone launcher as `dashboard:start`; that
  // launcher materializes static assets, validates loopback configuration, and
  // imports Next's generated server under the pinned Bun runtime.
  const nextProcess = Bun.spawn([process.execPath, standaloneLauncher], {
    cwd: applicationRoot,
    env: {
      ...process.env,
      HOSTNAME: "127.0.0.1",
      NEXT_TELEMETRY_DISABLED: "1",
      NTIP_API_INTERNAL_ORIGIN: apiOrigin,
      NTIP_DASHBOARD_LISTEN_HOST: "127.0.0.1",
      NTIP_PUBLIC_ORIGIN: publicOrigin,
      PORT: String(nextPort),
      TZ: "UTC",
    },
    stdin: "ignore",
    stdout: options.quiet === true ? "ignore" : "inherit",
    stderr: options.quiet === true ? "ignore" : "inherit",
  });

  let proxyServer: ReturnType<typeof Bun.serve> | null = null;
  let closed = false;
  let exitCode = -1;

  async function close(): Promise<number> {
    if (closed) return exitCode;
    closed = true;
    proxyServer?.stop(true);
    controlServer.stop(true);
    apiServer.stop(true);
    nextProcess.kill("SIGTERM");
    const timed = await new Promise<Readonly<{ code: number; timedOut: boolean }>>((resolvePromise) => {
      const timeout = setTimeout(() => resolvePromise({ code: -1, timedOut: true }), 10_000);
      void nextProcess.exited.then((code) => {
        clearTimeout(timeout);
        resolvePromise({ code, timedOut: false });
      });
    });
    if (timed.timedOut) {
      nextProcess.kill("SIGKILL");
      exitCode = await nextProcess.exited;
    } else {
      exitCode = timed.code;
    }
    await rm(certificate.directory, { recursive: true, force: true });
    return exitCode;
  }

  try {
    await waitFor(`${nextOrigin}/login`, 30_000);
    proxyServer = Bun.serve({
      hostname: "127.0.0.1",
      port: httpsPort,
      tls: {
        cert: Bun.file(certificate.certificatePath),
        key: Bun.file(certificate.keyPath),
      },
      fetch(request) {
        const path = new URL(request.url).pathname;
        return forward(request, path.startsWith("/api/v1/") ? apiOrigin : nextOrigin);
      },
    });
  } catch (error) {
    await close();
    throw error;
  }

  if (options.quiet !== true) process.stdout.write(`NTIP dashboard harness ready at ${publicOrigin}\n`);
  return { controlOrigin, publicOrigin, close };
}
