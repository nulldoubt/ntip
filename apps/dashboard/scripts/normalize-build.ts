import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

type JsonObject = Record<string, unknown>;

const canonicalApplicationRoot = "/usr/lib/ntip-dashboard/app";
const canonicalDashboardRoot = `${canonicalApplicationRoot}/apps/dashboard`;

function object(value: unknown, label: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as JsonObject;
}

async function readObject(path: string): Promise<JsonObject> {
  return object(JSON.parse(await readFile(path, "utf8")) as unknown, path);
}

function digest(label: string, buildId: string): Buffer {
  return createHash("sha256")
    .update("ntip-dashboard-next-build-v1\0", "utf8")
    .update(label, "utf8")
    .update("\0", "utf8")
    .update(buildId, "utf8")
    .digest();
}

function normalizeNextConfig(value: unknown, label: string): JsonObject {
  const configuration = object(value, label);
  if (typeof configuration.outputFileTracingRoot !== "string") {
    throw new Error(`${label}.outputFileTracingRoot must be a string`);
  }
  const experimental = object(configuration.experimental, `${label}.experimental`);
  if (experimental.cpus !== 1) {
    throw new Error(`${label}.experimental.cpus must remain fixed at one`);
  }
  if (experimental.multiZoneDraftMode !== false) {
    throw new Error(`${label}.experimental.multiZoneDraftMode must remain disabled`);
  }
  const turbopack = object(configuration.turbopack, `${label}.turbopack`);
  if (typeof turbopack.root !== "string") {
    throw new Error(`${label}.turbopack.root must be a string`);
  }

  configuration.outputFileTracingRoot = canonicalApplicationRoot;
  turbopack.root = canonicalApplicationRoot;
  return configuration;
}

async function normalizePrerenderManifest(path: string, buildId: string): Promise<void> {
  const manifest = await readObject(path);
  const preview = object(manifest.preview, `${path}.preview`);
  for (const field of ["previewModeId", "previewModeSigningKey", "previewModeEncryptionKey"] as const) {
    if (typeof preview[field] !== "string") throw new Error(`${path}.preview.${field} must be a string`);
  }

  manifest.preview = {
    previewModeId: digest("preview-id", buildId).toString("hex").slice(0, 32),
    previewModeSigningKey: digest("preview-signing", buildId).toString("hex"),
    previewModeEncryptionKey: digest("preview-encryption", buildId).toString("hex"),
  };
  await writeFile(path, JSON.stringify(manifest, null, 2));
}

async function normalizeServerReferenceManifest(
  jsonPath: string,
  javascriptPath: string,
  buildId: string,
): Promise<void> {
  const manifest = await readObject(jsonPath);
  const node = object(manifest.node, `${jsonPath}.node`);
  const edge = object(manifest.edge, `${jsonPath}.edge`);
  if (Object.keys(node).length !== 0 || Object.keys(edge).length !== 0) {
    throw new Error("NTIP does not permit Next Server Actions; deterministic normalization stopped");
  }
  if (typeof manifest.encryptionKey !== "string") {
    throw new Error(`${jsonPath}.encryptionKey must be a string`);
  }

  manifest.encryptionKey = digest("unused-server-actions", buildId).toString("base64");
  const serialized = JSON.stringify(manifest, null, 2);
  await writeFile(jsonPath, serialized);
  await writeFile(javascriptPath, `self.__RSC_SERVER_MANIFEST=${JSON.stringify(serialized)}`);
}

async function normalizeRequiredServerFiles(
  jsonPath: string,
  javascriptPath?: string,
): Promise<void> {
  const manifest = await readObject(jsonPath);
  manifest.config = normalizeNextConfig(manifest.config, `${jsonPath}.config`);
  if (typeof manifest.appDir !== "string") {
    throw new Error(`${jsonPath}.appDir must be a string`);
  }
  manifest.appDir = canonicalDashboardRoot;
  const serialized = JSON.stringify(manifest, null, 2);
  await writeFile(jsonPath, serialized);
  if (javascriptPath !== undefined) {
    await writeFile(javascriptPath, `self.__SERVER_FILES_MANIFEST=${serialized}`);
  }
}

async function normalizeStandaloneServer(path: string): Promise<void> {
  const source = await readFile(path, "utf8");
  const marker = "const nextConfig = ";
  const start = source.indexOf(marker);
  if (start < 0 || source.indexOf(marker, start + marker.length) >= 0) {
    throw new Error(`${path} must contain exactly one standalone Next configuration`);
  }
  const end = source.indexOf("\n", start);
  if (end < 0) throw new Error(`${path} has an unterminated standalone Next configuration`);
  const configuration = normalizeNextConfig(
    JSON.parse(source.slice(start + marker.length, end)) as unknown,
    `${path}.nextConfig`,
  );
  await writeFile(
    path,
    `${source.slice(0, start)}${marker}${JSON.stringify(configuration)}${source.slice(end)}`,
  );
}

const applicationRoot = resolve(import.meta.dirname, "..");
const outputRoot = join(applicationRoot, ".next");
const buildId = (await readFile(join(outputRoot, "BUILD_ID"), "utf8")).trim();
if (!/^[A-Za-z0-9._-]{1,128}$/.test(buildId)) throw new Error("Next BUILD_ID is not canonical");

const outputCopies = [
  outputRoot,
  join(outputRoot, "standalone", "apps", "dashboard", ".next"),
];
for (const copy of outputCopies) {
  await normalizePrerenderManifest(join(copy, "prerender-manifest.json"), buildId);
  await normalizeServerReferenceManifest(
    join(copy, "server", "server-reference-manifest.json"),
    join(copy, "server", "server-reference-manifest.js"),
    buildId,
  );
}

await normalizeRequiredServerFiles(
  join(outputRoot, "required-server-files.json"),
  join(outputRoot, "required-server-files.js"),
);
await normalizeRequiredServerFiles(
  join(outputRoot, "standalone", "apps", "dashboard", ".next", "required-server-files.json"),
);
await normalizeStandaloneServer(
  join(outputRoot, "standalone", "apps", "dashboard", "server.js"),
);

process.stdout.write(`normalized unsupported Next compatibility fields for reproducible build ${buildId}\n`);
