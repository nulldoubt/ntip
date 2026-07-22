import { compileErrors, validate as validateOpenApi } from "@readme/openapi-parser";
import { fileURLToPath } from "node:url";
import openapiTS, { COMMENT_HEADER, astToString } from "openapi-typescript";
import { parse } from "yaml";

export const packageRoot = new URL("../", import.meta.url);
export const openApiUrl = new URL("openapi/ntip-v1.yaml", packageRoot);
export const bootstrapOpenApiUrl = new URL("openapi/ntip-bootstrap-v1.yaml", packageRoot);
export const generatedSchemaUrl = new URL("src/generated/schema.ts", packageRoot);
export const generatedClientUrl = new URL("src/generated/client.ts", packageRoot);
export const generatedOpenApiJsonUrl = new URL("src/generated/openapi.json", packageRoot);
export const generatedBootstrapSchemaUrl = new URL("src/generated/bootstrap-schema.ts", packageRoot);
export const generatedBootstrapClientUrl = new URL("src/generated/bootstrap-client.ts", packageRoot);
export const generatedBootstrapOpenApiJsonUrl = new URL(
  "src/generated/bootstrap-openapi.json",
  packageRoot,
);

export const expectedPaths = [
  "/audit",
  "/audit/export",
  "/audit/prune",
  "/auth/change-password",
  "/auth/login",
  "/auth/logout",
  "/auth/me",
  "/auth/reauth",
  "/connectivity-checks",
  "/connectivity-checks/{id}",
  "/enrollment/bootstrap-config",
  "/events",
  "/health/live",
  "/health/ready",
  "/nodes",
  "/nodes/actions/bootstrap",
  "/nodes/{id}",
  "/nodes/{id}/actions/reset-enrollment",
  "/nodes/{id}/enrollment-bootstrap",
  "/openapi.json",
  "/operations/restart",
  "/operations/shutdown",
  "/overview",
  "/routes",
  "/routes/{id}",
  "/runtime/nodes",
  "/sessions",
  "/sessions/{id}",
  "/settings",
  "/settings/revisions",
  "/settings/revisions/{id}/rollback",
  "/topology",
  "/users",
  "/users/{id}",
  "/users/{id}/password-reset",
  "/vnrs",
  "/vnrs/{name}",
] as const;

export const expectedOperations = [
  "DELETE /nodes/{id} deleteNode",
  "DELETE /nodes/{id}/enrollment-bootstrap revokeNodeEnrollmentBootstrap",
  "DELETE /routes/{id} deleteRoute",
  "DELETE /sessions/{id} revokeSession",
  "DELETE /users/{id} tombstoneUser",
  "DELETE /vnrs/{name} deleteVnr",
  "GET /audit listAuditEntries",
  "GET /auth/me getAuthContext",
  "GET /connectivity-checks listConnectivityChecks",
  "GET /connectivity-checks/{id} getConnectivityCheck",
  "GET /enrollment/bootstrap-config getEnrollmentBootstrapConfig",
  "GET /events listEvents",
  "GET /health/live getLiveness",
  "GET /health/ready getReadiness",
  "GET /nodes listNodes",
  "GET /nodes/{id} getNode",
  "GET /openapi.json getOpenApiDocument",
  "GET /overview getOverview",
  "GET /routes listRoutes",
  "GET /routes/{id} getRoute",
  "GET /runtime/nodes listNodeRuntime",
  "GET /sessions listSessions",
  "GET /settings getSettings",
  "GET /settings/revisions listSettingsRevisions",
  "GET /topology getTopology",
  "GET /users listUsers",
  "GET /users/{id} getUser",
  "GET /vnrs listVnrs",
  "GET /vnrs/{name} getVnr",
  "PATCH /nodes/{id} updateNode",
  "PATCH /routes/{id} updateRoute",
  "PATCH /settings updateSettings",
  "PATCH /users/{id} updateUser",
  "PATCH /vnrs/{name} updateVnr",
  "POST /audit/export exportAuditEntries",
  "POST /audit/prune pruneAuditEntries",
  "POST /auth/change-password changeOwnPassword",
  "POST /auth/login login",
  "POST /auth/logout logout",
  "POST /auth/reauth reauthenticate",
  "POST /connectivity-checks createConnectivityCheck",
  "POST /nodes createNode",
  "POST /nodes/actions/bootstrap createNodeBootstrap",
  "POST /nodes/{id}/actions/reset-enrollment resetNodeEnrollment",
  "POST /nodes/{id}/enrollment-bootstrap createNodeEnrollmentBootstrap",
  "POST /operations/restart restartService",
  "POST /operations/shutdown shutdownService",
  "POST /routes createRoute",
  "POST /settings/revisions/{id}/rollback rollbackSettings",
  "POST /users createUser",
  "POST /users/{id}/password-reset resetUserPassword",
  "POST /vnrs createVnr",
] as const;

export const expectedBootstrapPaths = [
  "/enrollment/assets/{versioned-file}",
  "/enrollment/v1/redeem",
  "/enrollment/{bootstrapId}",
] as const;

export const expectedBootstrapOperations = [
  "GET /enrollment/assets/{versioned-file} getBootstrapAsset",
  "GET /enrollment/{bootstrapId} getBootstrapInstaller",
  "POST /enrollment/v1/redeem redeemBootstrapInvitation",
] as const;

export const stableErrorCodes = [
  "authentication_required",
  "conflict",
  "csrf_failed",
  "forbidden",
  "idempotency_conflict",
  "idempotency_required",
  "internal_error",
  "invalid_credentials",
  "invalid_request",
  "invariant_violation",
  "not_found",
  "operation_unavailable",
  "origin_forbidden",
  "password_change_required",
  "precondition_failed",
  "precondition_required",
  "rate_limited",
  "reauthentication_required",
  "service_unavailable",
  "validation_failed",
] as const;

export const stableInventoryViolationCodes = [
  "invalid_ipv4_address",
  "address_outside_vnr",
  "address_reserved_network",
  "address_reserved_master",
  "address_reserved_broadcast",
  "address_in_use",
  "invalid_ipv4_cidr",
  "noncanonical_ipv4_cidr",
  "prefix_out_of_range",
  "range_reserved",
  "range_overlaps_vnr",
  "range_overlaps_route",
  "range_excludes_node",
  "range_reserves_node_address",
] as const;

export const stableInventoryViolationFields = ["address", "cidr", "prefix"] as const;

export const operationalSettingFields = [
  "connectivityRetentionDays",
  "defaultEnrollmentLifetimeSeconds",
  "heartbeatIntervalSeconds",
  "innerMtu",
  "maximumNodes",
  "offlineAfterSeconds",
  "runtimeEventRetentionDays",
  "suspectAfterSeconds",
  "trafficColdAfterSeconds",
  "trafficHotBitsPerSecond",
  "trafficHotPacketsPerSecond",
  "trafficHysteresisSeconds",
  "trafficSaturatedQueuePercent",
] as const;

export const trafficStates = ["unknown", "cold", "warm", "hot", "saturated"] as const;

const methods = new Set(["get", "post", "put", "patch", "delete", "options", "head", "trace"]);

type JsonObject = Record<string, unknown>;

export interface ContractSummary {
  readonly pathCount: number;
  readonly operationCount: number;
  readonly schemaCount: number;
}

export interface GeneratedArtifact {
  readonly url: URL;
  readonly source: string;
}

export async function loadContract(): Promise<JsonObject> {
  const source = await Bun.file(openApiUrl).text();
  const value: unknown = parse(source);
  return objectAt(value, "document");
}

export async function loadBootstrapContract(): Promise<JsonObject> {
  const source = await Bun.file(bootstrapOpenApiUrl).text();
  const value: unknown = parse(source);
  return objectAt(value, "bootstrap document");
}

export async function validateContract(): Promise<ContractSummary> {
  const validation = await validateOpenApi(fileURLToPath(openApiUrl));
  if (!validation.valid) {
    throw new Error(compileErrors(validation));
  }
  if (validation.warnings.length > 0) {
    throw new Error(`OpenAPI validation emitted warnings:\n${compileErrors(validation)}`);
  }

  const document = await loadContract();
  const paths = objectAt(document.paths, "paths");
  assertEqual(document.openapi, "3.1.1", "OpenAPI version");
  assertEqual(objectAt(document.info, "info").version, "1.1.0", "contract version");

  const actualPaths = Object.keys(paths).sort();
  assertArrayEqual(actualPaths, [...expectedPaths], "canonical path set");

  const servers = arrayAt(document.servers, "servers");
  assertEqual(objectAt(servers[0], "servers[0]").url, "/api/v1", "API base path");

  const components = objectAt(document.components, "components");
  const securitySchemes = objectAt(components.securitySchemes, "components.securitySchemes");
  assertArrayEqual(Object.keys(securitySchemes), ["sessionCookie"], "security scheme set");

  const operationIds = new Set<string>();
  const actualOperations: string[] = [];
  let operationCount = 0;
  for (const [path, pathValue] of Object.entries(paths)) {
    const pathItem = objectAt(pathValue, `paths.${path}`);
    for (const [method, operationValue] of Object.entries(pathItem)) {
      if (!methods.has(method)) continue;
      operationCount += 1;
      const operation = objectAt(operationValue, `${method.toUpperCase()} ${path}`);
      const operationId = stringAt(operation.operationId, `${method.toUpperCase()} ${path}.operationId`);
      actualOperations.push(`${method.toUpperCase()} ${path} ${operationId}`);
      if (operationIds.has(operationId)) throw new Error(`Duplicate operationId: ${operationId}`);
      operationIds.add(operationId);

      const isPublic = Array.isArray(operation.security) && operation.security.length === 0;
      const isUnsafe = method !== "get" && method !== "head" && method !== "options";
      const parameters = collectParameters(document, pathItem, operation);

      if (method === "post") requireHeader(parameters, "Idempotency-Key", operationId);
      if (isUnsafe) requireHeader(parameters, "Origin", operationId);
      if (isUnsafe && !isPublic) requireHeader(parameters, "X-CSRF-Token", operationId);
      if ((method === "patch" || method === "delete") && !isPublic) {
        requireHeader(parameters, "If-Match", operationId);
      }
      if (operation["x-ntip-dangerous"] === true) {
        const roles = arrayAt(operation["x-ntip-roles"], `${operationId}.x-ntip-roles`);
        assertArrayEqual(roles, ["superuser"], `${operationId} dangerous role set`);
        if (operation["x-ntip-etag-precondition"] !== false) {
          requireHeader(parameters, "If-Match", operationId);
        } else if (operationId !== "createNodeBootstrap") {
          throw new Error(`${operationId} cannot waive the dangerous-operation ETag precondition`);
        }
        const requestBody = objectAt(operation.requestBody, `${operationId}.requestBody`);
        const content = objectAt(requestBody.content, `${operationId}.requestBody.content`);
        const jsonBody = objectAt(content["application/json"], `${operationId}.application/json`);
        const schema = resolveObjectRef(document, objectAt(jsonBody.schema, `${operationId}.schema`));
        const properties = objectAt(schema.properties, `${operationId}.schema.properties`);
        if (!("confirmation" in properties)) {
          throw new Error(`${operationId} dangerous request must require typed confirmation`);
        }
        const required = arrayAt(schema.required, `${operationId}.schema.required`);
        if (!required.includes("confirmation")) {
          throw new Error(`${operationId} dangerous request must require typed confirmation`);
        }
      }

      if (operation["x-ntip-one-time-response"] === true) {
        assertEqual(
          operation["x-ntip-reauthentication"],
          "required",
          `${operationId} reauthentication policy`,
        );
        assertEqual(
          operation["x-ntip-idempotency-replay"],
          "forbidden",
          `${operationId} idempotency replay policy`,
        );
        if (method !== "post") throw new Error(`${operationId} one-time disclosure must use POST`);
        requireHeader(parameters, "Idempotency-Key", operationId);
      }

      const responses = objectAt(operation.responses, `${operationId}.responses`);
      if (Object.keys(responses).length === 0) throw new Error(`${operationId} has no responses`);
    }
  }
  assertArrayEqual(actualOperations.sort(), [...expectedOperations], "canonical operation set");

  const schemas = objectAt(components.schemas, "components.schemas");
  const errorCode = objectAt(schemas.ErrorCode, "components.schemas.ErrorCode");
  const errorCodes = arrayAt(errorCode.enum, "ErrorCode.enum").map(String).sort();
  assertArrayEqual(errorCodes, [...stableErrorCodes], "stable error code set");

  const fieldViolation = objectAt(schemas.FieldViolation, "components.schemas.FieldViolation");
  const fieldViolationProperties = objectAt(fieldViolation.properties, "FieldViolation.properties");
  const fieldProperty = objectAt(fieldViolationProperties.field, "FieldViolation.field");
  const violationCodeProperty = objectAt(fieldViolationProperties.code, "FieldViolation.code");
  const fieldDescription = stringAt(fieldProperty.description, "FieldViolation.field.description");
  const violationCodeDescription = stringAt(
    violationCodeProperty.description,
    "FieldViolation.code.description",
  );
  for (const field of stableInventoryViolationFields) {
    assertIncludes(fieldDescription, `\`${field}\``, `FieldViolation field ${field}`);
  }
  for (const code of stableInventoryViolationCodes) {
    assertIncludes(violationCodeDescription, `\`${code}\``, `FieldViolation code ${code}`);
  }
  if ("enum" in violationCodeProperty) {
    throw new Error("FieldViolation.code must remain open to additive future values");
  }

  const responses = objectAt(components.responses, "components.responses");
  const badRequestDescription = stringAt(
    objectAt(responses.BadRequest, "components.responses.BadRequest").description,
    "BadRequest.description",
  );
  assertIncludes(badRequestDescription, "HTTP 400", "inventory parse response status");
  assertIncludes(badRequestDescription, "`validation_failed`", "inventory parse response code");
  const conflictDescription = stringAt(
    objectAt(responses.Conflict, "components.responses.Conflict").description,
    "Conflict.description",
  );
  assertIncludes(conflictDescription, "HTTP 409", "inventory invariant response status");
  assertIncludes(conflictDescription, "`invariant_violation`", "inventory invariant response code");
  assertIncludes(conflictDescription, "`conflict`", "inventory address conflict response code");

  const operationalSettings = objectAt(schemas.OperationalSettings, "components.schemas.OperationalSettings");
  const settingProperties = objectAt(operationalSettings.properties, "OperationalSettings.properties");
  assertArrayEqual(Object.keys(settingProperties).sort(), [...operationalSettingFields], "operational setting field set");
  assertArrayEqual(
    arrayAt(operationalSettings.required, "OperationalSettings.required").map(String).sort(),
    [...operationalSettingFields],
    "required operational setting field set",
  );

  const trafficState = objectAt(schemas.TrafficState, "components.schemas.TrafficState");
  assertArrayEqual(arrayAt(trafficState.enum, "TrafficState.enum").map(String), [...trafficStates], "traffic state set");

  for (const requestSchema of [
    "AuditExportRequest",
    "AuditPruneRequest",
    "ChangePasswordRequest",
    "ConnectivityCheckCreate",
    "DangerousConfirmation",
    "LoginRequest",
    "NodeBootstrapCreate",
    "NodeCreate",
    "NodeUpdate",
    "ReauthenticateRequest",
    "RestartRequest",
    "RouteCreate",
    "RouteUpdate",
    "SettingsUpdate",
    "ShutdownRequest",
    "UserCreate",
    "UserUpdate",
    "VnrCreate",
    "VnrUpdate",
  ]) {
    const schema = objectAt(schemas[requestSchema], `components.schemas.${requestSchema}`);
    assertEqual(schema.additionalProperties, false, `${requestSchema}.additionalProperties`);
  }

  const runtimeSchemaText = JSON.stringify(schemas.NodeRuntime);
  for (const forbidden of ["publicKey", "privateKey", "sessionId", "softwareVersion"]) {
    if (runtimeSchemaText.includes(forbidden)) {
      throw new Error(`NodeRuntime exposes forbidden field ${forbidden}`);
    }
  }

  return {
    pathCount: actualPaths.length,
    operationCount,
    schemaCount: Object.keys(schemas).length,
  };
}

export async function validateBootstrapContract(): Promise<ContractSummary> {
  const validation = await validateOpenApi(fileURLToPath(bootstrapOpenApiUrl));
  if (!validation.valid) throw new Error(compileErrors(validation));
  if (validation.warnings.length > 0) {
    throw new Error(`Bootstrap OpenAPI validation emitted warnings:\n${compileErrors(validation)}`);
  }

  const document = await loadBootstrapContract();
  const paths = objectAt(document.paths, "bootstrap paths");
  assertEqual(document.openapi, "3.1.1", "bootstrap OpenAPI version");
  assertEqual(objectAt(document.info, "bootstrap info").version, "1.0.0", "bootstrap contract version");
  assertEqual(
    objectAt(arrayAt(document.servers, "bootstrap servers")[0], "bootstrap server").url,
    "/",
    "bootstrap base path",
  );
  assertArrayEqual(arrayAt(document.security, "bootstrap security"), [], "bootstrap global security");

  const actualPaths = Object.keys(paths).sort();
  assertArrayEqual(actualPaths, [...expectedBootstrapPaths], "bootstrap canonical path set");

  const operationIds = new Set<string>();
  const actualOperations: string[] = [];
  let operationCount = 0;
  for (const [path, pathValue] of Object.entries(paths)) {
    const pathItem = objectAt(pathValue, `bootstrap paths.${path}`);
    for (const [method, operationValue] of Object.entries(pathItem)) {
      if (!methods.has(method)) continue;
      operationCount += 1;
      const operation = objectAt(operationValue, `bootstrap ${method.toUpperCase()} ${path}`);
      const operationId = stringAt(operation.operationId, `${method.toUpperCase()} ${path}.operationId`);
      actualOperations.push(`${method.toUpperCase()} ${path} ${operationId}`);
      if (operationIds.has(operationId)) throw new Error(`Duplicate bootstrap operationId: ${operationId}`);
      operationIds.add(operationId);
      assertEqual(operation["x-ntip-cookie-independent"], true, `${operationId} cookie policy`);
      assertEqual(operation["x-ntip-cors"], "disabled", `${operationId} CORS policy`);
      assertEqual(operation["x-ntip-redirects"], "forbidden", `${operationId} redirect policy`);
      if (Object.keys(objectAt(operation.responses, `${operationId}.responses`)).length === 0) {
        throw new Error(`${operationId} has no responses`);
      }
    }
  }
  assertArrayEqual(actualOperations.sort(), [...expectedBootstrapOperations], "bootstrap canonical operation set");

  const components = objectAt(document.components, "bootstrap components");
  if (components.securitySchemes !== undefined) {
    throw new Error("Bootstrap contract must not define authentication schemes");
  }
  const schemas = objectAt(components.schemas, "bootstrap components.schemas");
  const bootstrapId = objectAt(schemas.BootstrapId, "BootstrapId");
  assertEqual(bootstrapId.pattern, "^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$", "BootstrapId pattern");
  const secretCode = objectAt(schemas.BootstrapSecretCode, "BootstrapSecretCode");
  assertEqual(
    secretCode.pattern,
    "^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{3}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{3}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{3}$",
    "BootstrapSecretCode pattern",
  );
  assertEqual(secretCode.writeOnly, true, "BootstrapSecretCode.writeOnly");

  const redeem = objectAt(objectAt(paths["/enrollment/v1/redeem"], "redeem path").post, "redeem operation");
  assertEqual(redeem["x-ntip-reject-origin"], true, "redeem Origin rejection");
  assertEqual(redeem["x-ntip-reject-transfer-encoding"], true, "redeem transfer-encoding rejection");
  assertEqual(redeem["x-ntip-max-request-body-bytes"], 128, "redeem body limit");
  const redeemBody = objectAt(redeem.requestBody, "redeem requestBody");
  const redeemContent = objectAt(redeemBody.content, "redeem request content");
  assertArrayEqual(Object.keys(redeemContent), ["application/json"], "redeem media type set");
  const redeemMedia = objectAt(redeemContent["application/json"], "redeem JSON media type");
  const redeemSchema = resolveObjectRef(document, objectAt(redeemMedia.schema, "redeem schema"));
  assertEqual(redeemSchema.additionalProperties, false, "BootstrapRedeemRequest.additionalProperties");
  assertArrayEqual(
    Object.keys(objectAt(redeemSchema.properties, "BootstrapRedeemRequest.properties")),
    ["bootstrapId", "secretCode"],
    "bootstrap redeem field set",
  );
  assertArrayEqual(
    arrayAt(redeemSchema.required, "BootstrapRedeemRequest.required"),
    ["bootstrapId", "secretCode"],
    "bootstrap redeem required fields",
  );

  const bundle = objectAt(schemas.BootstrapRedemptionBundle, "BootstrapRedemptionBundle");
  assertEqual(bundle.additionalProperties, false, "BootstrapRedemptionBundle.additionalProperties");
  assertArrayEqual(
    Object.keys(objectAt(bundle.properties, "BootstrapRedemptionBundle.properties")),
    [
      "schemaVersion",
      "bootstrapId",
      "nodeName",
      "masterEndpoint",
      "expiresAt",
      "enrollmentCredential",
      "archives",
    ],
    "bootstrap redemption bundle field set",
  );
  const credential = objectAt(schemas.InternalEnrollmentCredential, "InternalEnrollmentCredential");
  assertEqual(credential.readOnly, true, "InternalEnrollmentCredential.readOnly");
  assertEqual(credential.pattern, "^ntip-enroll-v1\\.[A-Za-z0-9_-]{107}$", "internal credential pattern");

  const unavailable = objectAt(schemas.BootstrapUnavailableError, "BootstrapUnavailableError");
  const unavailableProperties = objectAt(unavailable.properties, "BootstrapUnavailableError.properties");
  assertEqual(
    objectAt(unavailableProperties.code, "BootstrapUnavailableError.code").const,
    "bootstrap_unavailable",
    "generic unavailable code",
  );
  assertEqual(
    objectAt(unavailableProperties.message, "BootstrapUnavailableError.message").const,
    "Bootstrap invitation is unavailable.",
    "generic unavailable message",
  );

  const asset = objectAt(
    objectAt(paths["/enrollment/assets/{versioned-file}"], "asset path").get,
    "asset operation",
  );
  assertEqual(asset["x-ntip-owner"], "dashboard-gateway", "bootstrap asset owner");

  return {
    pathCount: actualPaths.length,
    operationCount,
    schemaCount: Object.keys(schemas).length,
  };
}

export async function renderGeneratedArtifacts(): Promise<readonly GeneratedArtifact[]> {
  const document = await loadContract();
  const bootstrapDocument = await loadBootstrapContract();
  const ast = await openapiTS(openApiUrl, {
    alphabetize: true,
    immutable: true,
    rootTypes: true,
    rootTypesNoSchemaPrefix: true,
    silent: true,
  });
  const schemaSource = `${COMMENT_HEADER}// Source: openapi/ntip-v1.yaml\n\n${astToString(ast)}`;
  const bootstrapAst = await openapiTS(bootstrapOpenApiUrl, {
    alphabetize: true,
    immutable: true,
    rootTypes: true,
    rootTypesNoSchemaPrefix: true,
    silent: true,
  });
  const bootstrapSchemaSource = `${COMMENT_HEADER}// Source: openapi/ntip-bootstrap-v1.yaml\n\n${astToString(bootstrapAst)}`;
  const clientSource = `/**
 * This file is generated from openapi/ntip-v1.yaml.
 * Do not make direct changes to the file.
 */

import createClient from "openapi-fetch";
import type { Client, ClientOptions } from "openapi-fetch";
import type { paths } from "./schema";

export type NtipApiClient = Client<paths>;

export function createNtipApiClient(options: ClientOptions = {}): NtipApiClient {
  return createClient<paths>({
    baseUrl: "/api/v1",
    credentials: "same-origin",
    ...options,
  });
}
`;
  const bootstrapClientSource = `/**
 * This file is generated from openapi/ntip-bootstrap-v1.yaml.
 * Do not make direct changes to the file.
 */

import createClient from "openapi-fetch";
import type { Client, ClientOptions } from "openapi-fetch";
import type { paths } from "./bootstrap-schema";

export type NtipBootstrapClient = Client<paths>;

export function createNtipBootstrapClient(options: ClientOptions = {}): NtipBootstrapClient {
  return createClient<paths>({
    baseUrl: "",
    credentials: "omit",
    redirect: "error",
    ...options,
  });
}
`;
  return [
    { url: generatedSchemaUrl, source: ensureFinalNewline(schemaSource) },
    { url: generatedClientUrl, source: ensureFinalNewline(clientSource) },
    { url: generatedOpenApiJsonUrl, source: `${JSON.stringify(document, null, 2)}\n` },
    { url: generatedBootstrapSchemaUrl, source: ensureFinalNewline(bootstrapSchemaSource) },
    { url: generatedBootstrapClientUrl, source: ensureFinalNewline(bootstrapClientSource) },
    {
      url: generatedBootstrapOpenApiJsonUrl,
      source: `${JSON.stringify(bootstrapDocument, null, 2)}\n`,
    },
  ];
}

function collectParameters(document: JsonObject, pathItem: JsonObject, operation: JsonObject): JsonObject[] {
  const raw = [...optionalArray(pathItem.parameters), ...optionalArray(operation.parameters)];
  return raw.map((parameter, index) => resolveObjectRef(document, objectAt(parameter, `parameter[${index}]`)));
}

function resolveObjectRef(document: JsonObject, value: JsonObject): JsonObject {
  if (!("$ref" in value)) return value;
  const ref = stringAt(value.$ref, "$ref");
  if (!ref.startsWith("#/")) throw new Error(`External contract reference is not allowed: ${ref}`);
  let current: unknown = document;
  for (const encodedPart of ref.slice(2).split("/")) {
    const part = encodedPart.replaceAll("~1", "/").replaceAll("~0", "~");
    current = objectAt(current, ref)[part];
  }
  return objectAt(current, ref);
}

function requireHeader(parameters: JsonObject[], headerName: string, operationId: string): void {
  const found = parameters.some(
    (parameter) => parameter.in === "header" && parameter.name === headerName && parameter.required === true,
  );
  if (!found) throw new Error(`${operationId} must require ${headerName}`);
}

function objectAt(value: unknown, label: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as JsonObject;
}

function arrayAt(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function optionalArray(value: unknown): unknown[] {
  return value === undefined ? [] : arrayAt(value, "parameters");
}

function stringAt(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string`);
  return value;
}

function assertEqual(actual: unknown, expected: unknown, label: string): void {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
  }
}

function assertArrayEqual(actual: readonly unknown[], expected: readonly unknown[], label: string): void {
  if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
  }
}

function assertIncludes(actual: string, expected: string, label: string): void {
  if (!actual.includes(expected)) {
    throw new Error(`${label}: expected ${JSON.stringify(actual)} to include ${JSON.stringify(expected)}`);
  }
}

function ensureFinalNewline(source: string): string {
  return `${source.trimEnd()}\n`;
}
