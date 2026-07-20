"use client";

import type { components } from "@ntip/contracts";

type ErrorResponse = components["schemas"]["ErrorResponse"];
type FieldViolation = components["schemas"]["FieldViolation"];

function isErrorResponse(value: unknown): value is ErrorResponse {
  if (typeof value !== "object" || value === null || !("error" in value)) return false;
  const error = value.error;
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof error.code === "string" &&
    "message" in error &&
    typeof error.message === "string"
  );
}

export class ClientApiError extends Error {
  readonly code: string;
  readonly requestId: string | null;
  readonly status: number;
  readonly violations: readonly FieldViolation[];

  constructor(
    status: number,
    code: string,
    message: string,
    requestId: string | null,
    violations: readonly FieldViolation[] = [],
  ) {
    super(message);
    this.name = "ClientApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.violations = violations;
  }
}

export async function errorFromResponse(response: Response): Promise<ClientApiError> {
  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    // Preserve the HTTP status when an upstream error body is malformed.
  }

  if (isErrorResponse(payload)) {
    return new ClientApiError(
      response.status,
      payload.error.code,
      payload.error.message,
      payload.error.requestId,
      payload.error.violations ?? [],
    );
  }

  return new ClientApiError(
    response.status,
    "invalid_upstream_response",
    "The management API returned an invalid response.",
    response.headers.get("x-request-id"),
  );
}

export async function requireOk(response: Response): Promise<Response> {
  if (!response.ok) throw await errorFromResponse(response);
  return response;
}

export async function readJson<T>(response: Response): Promise<T> {
  await requireOk(response);
  try {
    return (await response.json()) as T;
  } catch {
    throw new ClientApiError(
      502,
      "invalid_upstream_response",
      "The management API returned invalid JSON.",
      response.headers.get("x-request-id"),
    );
  }
}

export async function getJson<T>(path: `/api/v1/${string}`, signal?: AbortSignal): Promise<{
  readonly data: T;
  readonly etag: string | null;
}> {
  const requestInit: RequestInit = {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
    redirect: "error",
  };
  if (signal !== undefined) requestInit.signal = signal;
  const response = await fetch(path, requestInit);
  return { data: await readJson<T>(response), etag: response.headers.get("etag") };
}

export function actionableError(error: unknown): string {
  if (!(error instanceof ClientApiError)) {
    return error instanceof Error ? error.message : "The request failed.";
  }

  switch (error.code) {
    case "precondition_failed":
      return "This VNR changed after it was loaded. Review the current values and try again.";
    case "precondition_required":
      return "A current resource version is required. Refresh the page and try again.";
    case "reauthentication_required":
      return "Your recent password confirmation expired. Enter your password and try again.";
    case "invalid_credentials":
      return "The password was not accepted.";
    case "conflict":
    case "invariant_violation":
      return error.message;
    case "service_unavailable":
      return "The management service is unavailable. Existing values remain visible; try again shortly.";
    case "authentication_required":
      return "Your session is no longer valid. Sign in again.";
    default:
      return error.message;
  }
}
