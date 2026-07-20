import { loadDashboardRuntimeConfig } from "@ntip/config";
import { access, cp, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const applicationRoot = resolve(import.meta.dirname, "..");
const standaloneRoot = join(applicationRoot, ".next", "standalone");
const standaloneDashboardRoot = join(standaloneRoot, "apps", "dashboard");
const serverPath = join(standaloneDashboardRoot, "server.js");
await access(serverPath);

// Match Next's documented standalone deployment layout. The generated trace
// intentionally omits static assets because deployments may serve them from a
// separate origin; NTIP's loopback page service serves them itself.
const staticTarget = join(standaloneDashboardRoot, ".next", "static");
await mkdir(staticTarget, { recursive: true });
await cp(join(applicationRoot, ".next", "static"), staticTarget, {
  recursive: true,
  force: true,
});

const configuration = loadDashboardRuntimeConfig();
process.env.HOSTNAME = configuration.listenHost;
process.env.NTIP_DASHBOARD_LISTEN_HOST = configuration.listenHost;
process.env.PORT = String(configuration.listenPort);
process.env.NEXT_TELEMETRY_DISABLED = "1";
process.chdir(standaloneRoot);
await import(pathToFileURL(serverPath).href);
