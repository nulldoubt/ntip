import { validateContract } from "./contract.ts";

const summary = await validateContract();
console.log(
  `Validated NTIP OpenAPI v1: ${summary.pathCount} paths, ` +
    `${summary.operationCount} operations, ${summary.schemaCount} schemas.`,
);
