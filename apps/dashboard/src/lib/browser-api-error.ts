"use client";

import type { components } from "@ntip/contracts";

export type ApiFieldViolation = components["schemas"]["FieldViolation"];

interface ParsedApiError {
  readonly code: string;
  readonly message: string;
  readonly requestId: string | null;
  readonly violations: readonly ApiFieldViolation[];
}

export interface ActionableApiErrorOptions {
  readonly resourceLabel?: string;
  readonly includeRequestId?: boolean;
}

export class BrowserApiError extends Error {
  readonly code: string;
  readonly requestId: string | null;
  readonly status: number;
  readonly violations: readonly ApiFieldViolation[];

  constructor(
    status: number,
    code: string,
    message: string,
    requestId: string | null,
    violations: readonly ApiFieldViolation[] = [],
  ) {
    super(message);
    this.name = "BrowserApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.violations = violations;
  }
}

export async function browserApiErrorFromResponse(response: Response): Promise<BrowserApiError> {
  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    // A malformed upstream body is represented by a stable client-side error.
  }

  const parsed = parseApiError(payload);
  if (parsed !== null) {
    return new BrowserApiError(
      response.status,
      parsed.code,
      parsed.message,
      parsed.requestId ?? response.headers.get("x-request-id"),
      parsed.violations,
    );
  }

  return new BrowserApiError(
    response.status,
    "invalid_upstream_response",
    fallbackMessageForStatus(response.status),
    response.headers.get("x-request-id"),
  );
}

export async function requireBrowserApiOk(response: Response): Promise<Response> {
  if (!response.ok) throw await browserApiErrorFromResponse(response);
  return response;
}

export async function readBrowserApiJson<T>(response: Response): Promise<T> {
  await requireBrowserApiOk(response);
  try {
    return (await response.json()) as T;
  } catch {
    throw new BrowserApiError(
      502,
      "invalid_upstream_response",
      "The management API returned invalid JSON. Refresh the page and try again.",
      response.headers.get("x-request-id"),
    );
  }
}

export function actionableApiError(error: unknown, options: ActionableApiErrorOptions = {}): string {
  if (!(error instanceof BrowserApiError)) {
    if (error instanceof TypeError) {
      return "Could not reach the management API. Check your connection and try again.";
    }
    if (error instanceof Error && error.message.trim().length > 0) return error.message;
    return "The request failed. Review the current values and try again.";
  }

  const resourceLabel = options.resourceLabel?.trim() || "resource";
  const message = (() => {
    switch (error.code) {
      case "precondition_failed":
        return `This ${resourceLabel} changed after it was loaded. Review the current values and try again.`;
      case "precondition_required":
        return "A current resource version is required. Refresh the page and try again.";
      case "reauthentication_required":
        return "Your recent password confirmation expired. Enter your password and try again.";
      case "invalid_credentials":
        return "The password was not accepted.";
      case "service_unavailable":
        return "The management service is unavailable. Existing values remain visible; try again shortly.";
      case "authentication_required":
        return "Your session is no longer valid. Sign in again.";
      case "rate_limited":
        return "Too many requests were attempted. Wait briefly and try again.";
      case "invalid_upstream_response":
        return fallbackMessageForStatus(error.status);
      default:
        return error.message.trim().length > 0
          ? error.message
          : fallbackMessageForStatus(error.status);
    }
  })();

  if (options.includeRequestId === true && error.requestId !== null) {
    return `${message} (request ${error.requestId})`;
  }
  return message;
}

function parseApiError(value: unknown): ParsedApiError | null {
  if (!isRecord(value) || !isRecord(value.error)) return null;
  const error = value.error;
  if (typeof error.code !== "string" || typeof error.message !== "string") return null;

  const violations = Array.isArray(error.violations)
    ? error.violations.flatMap((violation) => {
        const parsed = parseViolation(violation);
        return parsed === null ? [] : [parsed];
      })
    : [];

  return {
    code: error.code,
    message: error.message,
    requestId: typeof error.requestId === "string" ? error.requestId : null,
    violations,
  };
}

function parseViolation(value: unknown): ApiFieldViolation | null {
  if (!isRecord(value)) return null;
  if (
    typeof value.field !== "string" ||
    typeof value.code !== "string" ||
    typeof value.message !== "string"
  ) {
    return null;
  }
  return { field: value.field, code: value.code, message: value.message };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function fallbackMessageForStatus(status: number): string {
  switch (status) {
    case 401:
      return "Your session is no longer valid. Sign in again.";
    case 403:
      return "You do not have permission to perform this operation.";
    case 409:
      return "The request conflicts with the current configuration. Refresh and try again.";
    case 412:
      return "This resource changed after it was loaded. Refresh and try again.";
    case 428:
      return "A current resource version is required. Refresh and try again.";
    case 429:
      return "Too many requests were attempted. Wait briefly and try again.";
    case 503:
      return "The management service is temporarily unavailable. Try again shortly.";
    default:
      return `The management API could not complete the request (HTTP ${status}).`;
  }
}
