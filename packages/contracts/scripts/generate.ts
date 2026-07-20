import { renderGeneratedArtifacts, validateContract } from "./contract.ts";

const summary = await validateContract();
for (const artifact of await renderGeneratedArtifacts()) {
  await Bun.write(artifact.url, artifact.source);
}

console.log(
  `Generated NTIP API types and client from ${summary.pathCount} paths, ` +
    `${summary.operationCount} operations, and ${summary.schemaCount} schemas.`,
);
