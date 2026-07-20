import type { NextConfig } from "next";
import path from "node:path";
import { readFileSync } from "node:fs";

const dashboardPackage = JSON.parse(
  readFileSync(new URL("./package.json", import.meta.url), "utf8"),
) as { version?: unknown };
if (typeof dashboardPackage.version !== "string" || dashboardPackage.version === "") {
  throw new Error("dashboard package version is absent");
}

const nextConfig: NextConfig = {
  generateBuildId: async () => process.env.NTIP_DASHBOARD_BUILD_ID ?? `ntip-${dashboardPackage.version}`,
  images: { unoptimized: true },
  poweredByHeader: false,
  reactStrictMode: true,
  output: "standalone",
  outputFileTracingRoot: path.join(import.meta.dirname, "../.."),
  outputFileTracingExcludes: {
    "/*": ["**/node_modules/sharp/**/*", "**/node_modules/@img/**/*"],
  },
  transpilePackages: ["@ntip/config", "@ntip/contracts", "@ntip/ui"],
  experimental: {
    // Next otherwise serializes a host-derived worker count into the
    // standalone configuration. A fixed build worker count keeps release
    // output independent of builder CPU topology.
    cpus: 1,
    optimizePackageImports: ["lucide-react"],
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          { key: "X-Frame-Options", value: "DENY" },
        ],
      },
    ];
  },
  // Deliberately no /api/v1 rewrite: the operator TLS proxy owns that route.
  // A misrouted API request must fail instead of silently using a build-time
  // loopback destination that can disagree with the runtime bootstrap file.
};

export default nextConfig;
