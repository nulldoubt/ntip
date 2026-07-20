import { access } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { parseDashboardBootstrap } from "@ntip/config";

const MAXIMUM_CONFIG_BYTES = 64 * 1024;

function rejectDuplicateTopLevelKeys(source: string): void {
  const seen = new Set<string>();
  let index = 0;
  const skipWhitespace = (): void => {
    while (index < source.length && /\s/.test(source[index] ?? "")) index += 1;
  };
  skipWhitespace();
  if (source[index] !== "{") return;
  index += 1;
  while (index < source.length) {
    skipWhitespace();
    if (source[index] === "}") return;
    if (source[index] !== "\"") return;
    const start = index;
    index += 1;
    let escaped = false;
    while (index < source.length) {
      const character = source[index];
      index += 1;
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === "\"") {
        break;
      }
    }
    const key = JSON.parse(source.slice(start, index)) as unknown;
    if (typeof key !== "string") return;
    if (seen.has(key)) throw new Error(`dashboard configuration repeats field: ${key}`);
    seen.add(key);
    skipWhitespace();
    if (source[index] !== ":") return;
    index += 1;

    let depth = 0;
    let inString = false;
    escaped = false;
    while (index < source.length) {
      const character = source[index];
      if (inString) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === "\"") inString = false;
      } else if (character === "\"") inString = true;
      else if (character === "[" || character === "{") depth += 1;
      else if (character === "]" || character === "}") {
        if (character === "}" && depth === 0) return;
        depth -= 1;
      } else if (character === "," && depth === 0) {
        index += 1;
        break;
      }
      index += 1;
    }
  }
}

function configurationPath(arguments_: readonly string[]): string {
  if (arguments_.length !== 2 || arguments_[0] !== "--config" || arguments_[1] === undefined || arguments_[1] === "") {
    throw new Error("usage: launcher.ts --config PATH");
  }
  return arguments_[1];
}

async function main(): Promise<void> {
  const path = configurationPath(Bun.argv.slice(2));
  const file = Bun.file(path);
  if (!(await file.exists()) || file.size === 0 || file.size > MAXIMUM_CONFIG_BYTES) {
    throw new Error("dashboard configuration is missing, empty, or too large");
  }

  let decoded: unknown;
  try {
    const source = await file.text();
    rejectDuplicateTopLevelKeys(source);
    decoded = JSON.parse(source) as unknown;
  } catch {
    throw new Error("dashboard configuration must be valid JSON");
  }
  const configuration = parseDashboardBootstrap(decoded);
  const applicationRoot = process.cwd();
  const serverPath = join(applicationRoot, "apps", "dashboard", "server.js");
  await access(serverPath);

  process.env.HOSTNAME = configuration.bindAddress;
  process.env.NTIP_DASHBOARD_LISTEN_HOST = configuration.bindAddress;
  process.env.PORT = String(configuration.port);
  process.env.NTIP_API_INTERNAL_ORIGIN = configuration.apiOrigin;
  process.env.NEXT_TELEMETRY_DISABLED = "1";

  await import(pathToFileURL(serverPath).href);
}

await main();
