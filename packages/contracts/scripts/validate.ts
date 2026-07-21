import { validateBootstrapContract, validateContract } from "./contract.ts";

const [summary, bootstrapSummary] = await Promise.all([
  validateContract(),
  validateBootstrapContract(),
]);
console.log(
  `Validated NTIP management OpenAPI v1.1: ${summary.pathCount} paths, ` +
    `${summary.operationCount} operations, ${summary.schemaCount} schemas; ` +
    `Bootstrap v1: ${bootstrapSummary.pathCount} paths, ` +
    `${bootstrapSummary.operationCount} operations, ${bootstrapSummary.schemaCount} schemas.`,
);
