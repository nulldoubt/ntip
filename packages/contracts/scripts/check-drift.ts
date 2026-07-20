import { renderGeneratedArtifacts, validateContract } from "./contract.ts";

await validateContract();

const drifted: string[] = [];
for (const artifact of await renderGeneratedArtifacts()) {
  const current = await Bun.file(artifact.url).text().catch(() => "");
  if (current !== artifact.source) drifted.push(artifact.url.pathname);
}

if (drifted.length > 0) {
  console.error("Generated contract artifacts are stale:");
  for (const path of drifted) console.error(`  ${path}`);
  console.error("Run `bun run contracts:generate` and commit the result.");
  process.exit(1);
}

console.log("Generated NTIP contract artifacts match openapi/ntip-v1.yaml.");
