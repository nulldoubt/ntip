import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createHttpGatewayHandler } from "../../scripts/http-gateway";

const temporaryDirectories: string[] = [];

async function temporaryAssets(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "ntip-gateway-test-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => (
    rm(directory, { recursive: true, force: true })
  )));
});

describe("dashboard HTTP gateway", () => {
  test("routes browser API requests to the loopback API without weakening auth headers", async () => {
    const observed: Array<{ body: string; headers: Headers; method: string; url: string }> = [];
    const handle = createHttpGatewayHandler({
      apiOrigin: "http://127.0.0.1:8787",
      assetsRoot: await temporaryAssets(),
      nextOrigin: "http://127.0.0.1:3000",
      async fetchUpstream(input, init) {
        observed.push({
          body: typeof init?.body === "string" ? init.body : new TextDecoder().decode(init?.body as ArrayBuffer),
          headers: new Headers(init?.headers),
          method: init?.method ?? "GET",
          url: input.toString(),
        });
        return Response.json({ ok: true }, {
          headers: { "Set-Cookie": "__Host-ntip_session=opaque; Secure; HttpOnly" },
        });
      },
    });
    const body = JSON.stringify({ username: "admin", password: "not-a-real-password" });
    const response = await handle(new Request("http://demo.ntip.test/api/v1/auth/login", {
      method: "POST",
      headers: {
        "Content-Length": String(Buffer.byteLength(body)),
        "Content-Type": "application/json",
        Cookie: "existing=value",
        Origin: "https://demo.ntip.test",
      },
      body,
    }), "127.0.0.1");

    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toContain("__Host-ntip_session=opaque");
    expect(observed).toHaveLength(1);
    expect(observed[0]?.url).toBe("http://127.0.0.1:8787/api/v1/auth/login");
    expect(observed[0]?.method).toBe("POST");
    expect(observed[0]?.body).toBe(body);
    expect(observed[0]?.headers.get("host")).toBe("demo.ntip.test");
    expect(observed[0]?.headers.get("cookie")).toBe("existing=value");
    expect(observed[0]?.headers.get("origin")).toBe("https://demo.ntip.test");
    expect(observed[0]?.headers.get("connection")).toBe("close");
    expect(observed[0]?.headers.get("accept-encoding")).toBe("identity");
  });

  test("routes pages to the isolated Next listener", async () => {
    let target = "";
    const handle = createHttpGatewayHandler({
      apiOrigin: "http://127.0.0.1:8787",
      assetsRoot: await temporaryAssets(),
      nextOrigin: "http://127.0.0.1:32123",
      async fetchUpstream(input) {
        target = input.toString();
        return new Response("login page", { status: 200 });
      },
    });

    const response = await handle(new Request("http://demo.ntip.test/login?next=%2Foverview"));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("login page");
    expect(target).toBe("http://127.0.0.1:32123/login?next=%2Foverview");
  });

  test("keeps installer requests anonymous and never forwards redirects", async () => {
    let observedHeaders = new Headers();
    const handle = createHttpGatewayHandler({
      apiOrigin: "http://127.0.0.1:8787",
      assetsRoot: await temporaryAssets(),
      nextOrigin: "http://127.0.0.1:3000",
      async fetchUpstream(_input, init) {
        observedHeaders = new Headers(init?.headers);
        return new Response(null, { status: 302, headers: { Location: "https://attacker.invalid" } });
      },
    });
    const response = await handle(new Request("http://demo.ntip.test/enrollment/ABCDEFGH", {
      headers: {
        Authorization: "Bearer forbidden",
        Cookie: "session=forbidden",
        Forwarded: "for=198.51.100.2",
        Origin: "https://elsewhere.invalid",
        "X-Forwarded-For": "198.51.100.2",
      },
    }));

    expect(response.status).toBe(503);
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.get("cache-control")).toBe("no-store");
    for (const header of ["authorization", "cookie", "forwarded", "origin", "x-forwarded-for"]) {
      expect(observedHeaders.get(header)).toBeNull();
    }
  });

  test("enforces the strict redemption envelope and bounded peer rate", async () => {
    let upstreamCalls = 0;
    const handle = createHttpGatewayHandler({
      apiOrigin: "http://127.0.0.1:8787",
      assetsRoot: await temporaryAssets(),
      nextOrigin: "http://127.0.0.1:3000",
      fetchUpstream: async () => {
        upstreamCalls += 1;
        return Response.json({ schemaVersion: 1 });
      },
      now: () => 1_000,
    });
    const body = JSON.stringify({ bootstrapId: "ABCDEFGH", secretCode: "ABC-DEF-GHJ" });
    const valid = () => new Request("http://demo.ntip.test/enrollment/v1/redeem", {
      method: "POST",
      headers: {
        "Content-Length": String(Buffer.byteLength(body)),
        "Content-Type": "application/json",
      },
      body,
    });

    expect((await handle(new Request("http://demo.ntip.test/enrollment/v1/redeem"))).status).toBe(405);
    expect((await handle(new Request("http://demo.ntip.test/enrollment/v1/redeem", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    }))).status).toBe(400);
    expect((await handle(new Request("http://demo.ntip.test/enrollment/v1/redeem", {
      method: "POST",
      headers: {
        "Content-Length": String(Buffer.byteLength(body)),
        "Content-Type": "text/plain",
      },
      body,
    }))).status).toBe(415);
    expect((await handle(new Request("http://demo.ntip.test/enrollment/v1/redeem", {
      method: "POST",
      headers: {
        "Content-Length": String(Buffer.byteLength(body)),
        "Content-Type": "application/json",
        Origin: "https://demo.ntip.test",
      },
      body,
    }))).status).toBe(400);
    expect((await handle(new Request("http://demo.ntip.test/enrollment/v1/redeem", {
      method: "POST",
      headers: {
        "Content-Length": "1",
        "Content-Type": "application/json",
      },
      body,
    }))).status).toBe(400);

    for (let attempt = 0; attempt < 6; attempt += 1) {
      expect((await handle(valid(), "127.0.0.1")).status).toBe(200);
    }
    const limited = await handle(valid(), "127.0.0.1");
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("60");
    expect(upstreamCalls).toBe(6);
  });

  test("serves only regular versioned Node archive basenames with immutable caching", async () => {
    const root = await temporaryAssets();
    const basename = "ntip-node-v0.2.0-x86_64-linux-musl.tar.gz";
    await Bun.write(join(root, basename), "archive-bytes");
    await Bun.write(join(root, "outside"), "outside");
    await symlink(join(root, "outside"), join(root, "ntip-node-v0.2.1-x86_64-linux-musl.tar.gz"));
    await mkdir(join(root, "ntip-node-v0.2.2-x86_64-linux-musl.tar.gz"));
    const handle = createHttpGatewayHandler({
      apiOrigin: "http://127.0.0.1:8787",
      assetsRoot: root,
      nextOrigin: "http://127.0.0.1:3000",
      fetchUpstream: async () => new Response("must not run", { status: 500 }),
    });

    const response = await handle(new Request(`http://demo.ntip.test/enrollment/assets/${basename}`));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("archive-bytes");
    expect(response.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    expect(response.headers.get("content-type")).toBe("application/octet-stream");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");

    for (const path of [
      "/enrollment/assets/%2e%2e%2fetc%2fpasswd",
      "/enrollment/assets/not-a-release.tar.gz",
      "/enrollment/assets/ntip-node-v0.2.1-x86_64-linux-musl.tar.gz",
      "/enrollment/assets/ntip-node-v0.2.2-x86_64-linux-musl.tar.gz",
      `/enrollment/assets/${basename}?download=true`,
    ]) {
      const missing = await handle(new Request(`http://demo.ntip.test${path}`));
      expect(missing.status).toBe(404);
      expect(missing.headers.get("cache-control")).toBe("no-store");
    }

    const disallowed = await handle(new Request(`http://demo.ntip.test/enrollment/assets/${basename}`, {
      method: "POST",
    }));
    expect(disallowed.status).toBe(405);
    expect(disallowed.headers.get("allow")).toBe("GET");
  });

  test("rejects declared management bodies above 64 KiB before proxying", async () => {
    let called = false;
    const handle = createHttpGatewayHandler({
      apiOrigin: "http://127.0.0.1:8787",
      assetsRoot: await temporaryAssets(),
      nextOrigin: "http://127.0.0.1:3000",
      fetchUpstream: async () => {
        called = true;
        return new Response(null, { status: 204 });
      },
    });
    const response = await handle(new Request("http://demo.ntip.test/api/v1/settings", {
      method: "PATCH",
      headers: { "Content-Length": String(65 * 1024) },
      body: "{}",
    }));
    expect(response.status).toBe(413);
    expect(called).toBeFalse();
  });
});
