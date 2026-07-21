import {
  renderGeneratedArtifacts,
  validateBootstrapContract,
  validateContract,
} from "./contract.ts";

const [summary, bootstrapSummary] = await Promise.all([
  validateContract(),
  validateBootstrapContract(),
]);
for (const artifact of await renderGeneratedArtifacts()) {
  await Bun.write(artifact.url, artifact.source);
}

console.log(
  `Generated NTIP management and bootstrap contracts from ` +
    `${summary.pathCount + bootstrapSummary.pathCount} paths, ` +
    `${summary.operationCount + bootstrapSummary.operationCount} operations, and ` +
    `${summary.schemaCount + bootstrapSummary.schemaCount} schemas.`,
);
