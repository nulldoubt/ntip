import { access } from "node:fs/promises";
import { request as nodeHttpsRequest } from "node:https";
import { resolve } from "node:path";
import { startDashboardHarness } from "./harness-runtime";

const PINNED_BUN_VERSION = "1.3.14";

interface SmokeResponse {
  readonly body: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly status: number;
}

function request(url: string, options: Readonly<{ method?: string; headers?: Record<string, string>; body?: string }> = {}): Promise<SmokeResponse> {
  return new Promise((resolvePromise, reject) => {
    const body = options.body;
    const headers = { ...options.headers, ...(body === undefined ? {} : { "Content-Length": String(Buffer.byteLength(body)) }) };
    const outgoing = nodeHttpsRequest(url, {
      method: options.method ?? "GET",
      headers,
      rejectUnauthorized: false,
    }, (incoming) => {
      const chunks: Buffer[] = [];
      incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
      incoming.once("error", reject);
      incoming.once("end", () => resolvePromise({
        body: Buffer.concat(chunks).toString("utf8"),
        headers: incoming.headers,
        status: incoming.statusCode ?? 0,
      }));
    });
    outgoing.once("error", reject);
    if (body !== undefined) outgoing.write(body);
    outgoing.end();
  });
}

if (Bun.version !== PINNED_BUN_VERSION) throw new Error(`expected Bun ${PINNED_BUN_VERSION}, received ${Bun.version}`);
await access(resolve(import.meta.dirname, "../.next/BUILD_ID"));

const harness = await startDashboardHarness({ apiPort: 8889, controlPort: 8890, httpsPort: 3543, nextPort: 3200, quiet: true });
try {
  const anonymous = await request(`${harness.publicOrigin}/overview`);
  if (![307, 308].includes(anonymous.status) || anonymous.headers.location !== "/login") {
    throw new Error(`anonymous protected route did not redirect to /login (${anonymous.status}, ${String(anonymous.headers.location)})`);
  }

  const loginBody = JSON.stringify({ username: "viewer", password: "viewer-password-2026" });
  const login = await request(`${harness.publicOrigin}/api/v1/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": "smoke-login-0001",
      Origin: harness.publicOrigin,
    },
    body: loginBody,
  });
  if (login.status !== 200) throw new Error(`fixture login failed (${login.status})`);
  const setCookie = Array.isArray(login.headers["set-cookie"]) ? login.headers["set-cookie"][0] : login.headers["set-cookie"];
  const cookie = setCookie?.split(";", 1)[0];
  if (cookie === undefined) throw new Error("fixture login did not return the Secure session cookie");

  const authenticated = await request(`${harness.publicOrigin}/overview`, { headers: { Cookie: cookie } });
  if (authenticated.status !== 200 || !authenticated.body.includes("berlin-gateway") || !authenticated.body.includes("Runtime state")) {
    throw new Error(`authenticated production RSC render failed (${authenticated.status})`);
  }
} finally {
  const exitCode = await harness.close();
  if (exitCode !== 0 && exitCode !== 143) throw new Error(`Next production server did not terminate cleanly (${exitCode})`);
}

process.stdout.write(`production smoke passed with Bun ${Bun.version}\n`);
