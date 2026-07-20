import { compileErrors, validate as validateOpenApi } from "@readme/openapi-parser";
import { fileURLToPath } from "node:url";
import openapiTS, { COMMENT_HEADER, astToString } from "openapi-typescript";
import { parse } from "yaml";

export const packageRoot = new URL("../", import.meta.url);
export const openApiUrl = new URL("openapi/ntip-v1.yaml", packageRoot);
export const generatedSchemaUrl = new URL("src/generated/schema.ts", packageRoot);
export const generatedClientUrl = new URL("src/generated/client.ts", packageRoot);
export const generatedOpenApiJsonUrl = new URL("src/generated/openapi.json", packageRoot);

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
  "/events",
  "/health/live",
  "/health/ready",
  "/nodes",
  "/nodes/{id}",
  "/nodes/{id}/actions/reset-enrollment",
  "/nodes/{id}/enrollment-credentials",
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
  "DELETE /routes/{id} deleteRoute",
  "DELETE /sessions/{id} revokeSession",
  "DELETE /users/{id} tombstoneUser",
  "DELETE /vnrs/{name} deleteVnr",
  "GET /audit listAuditEntries",
  "GET /auth/me getAuthContext",
  "GET /connectivity-checks listConnectivityChecks",
  "GET /connectivity-checks/{id} getConnectivityCheck",
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
  "POST /nodes/{id}/actions/reset-enrollment resetNodeEnrollment",
  "POST /nodes/{id}/enrollment-credentials issueEnrollmentCredential",
  "POST /operations/restart restartService",
  "POST /operations/shutdown shutdownService",
  "POST /routes createRoute",
  "POST /settings/revisions/{id}/rollback rollbackSettings",
  "POST /users createUser",
  "POST /users/{id}/password-reset resetUserPassword",
  "POST /vnrs createVnr",
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
  assertEqual(objectAt(document.info, "info").version, "1.0.0", "contract version");

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
        requireHeader(parameters, "If-Match", operationId);
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

      const responses = objectAt(operation.responses, `${operationId}.responses`);
      if (Object.keys(responses).length === 0) throw new Error(`${operationId} has no responses`);
    }
  }
  assertArrayEqual(actualOperations.sort(), [...expectedOperations], "canonical operation set");

  const schemas = objectAt(components.schemas, "components.schemas");
  const errorCode = objectAt(schemas.ErrorCode, "components.schemas.ErrorCode");
  const errorCodes = arrayAt(errorCode.enum, "ErrorCode.enum").map(String).sort();
  assertArrayEqual(errorCodes, [...stableErrorCodes], "stable error code set");

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
    "EnrollmentCredentialRequest",
    "LoginRequest",
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

export async function renderGeneratedArtifacts(): Promise<readonly GeneratedArtifact[]> {
  const document = await loadContract();
  const ast = await openapiTS(openApiUrl, {
    alphabetize: true,
    immutable: true,
    rootTypes: true,
    rootTypesNoSchemaPrefix: true,
    silent: true,
  });
  const schemaSource = `${COMMENT_HEADER}// Source: openapi/ntip-v1.yaml\n\n${astToString(ast)}`;
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
  return [
    { url: generatedSchemaUrl, source: ensureFinalNewline(schemaSource) },
    { url: generatedClientUrl, source: ensureFinalNewline(clientSource) },
    { url: generatedOpenApiJsonUrl, source: `${JSON.stringify(document, null, 2)}\n` },
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

function ensureFinalNewline(source: string): string {
  return `${source.trimEnd()}\n`;
}
