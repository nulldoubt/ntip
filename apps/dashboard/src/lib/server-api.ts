import "server-only";

import { loadDashboardRuntimeConfig } from "@ntip/config";
import type { components } from "@ntip/contracts";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { internalApiHeaders } from "@/lib/server-api-headers";

type ErrorResponse = components["schemas"]["ErrorResponse"];

const sessionCookieName = "__Host-ntip_session";
const runtimeConfig = loadDashboardRuntimeConfig();

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

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;

  constructor(status: number, code: string, message: string, requestId: string | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

/**
 * Server Components can load this module through more than one bundled chunk,
 * so an `instanceof ApiError` check is not reliable at route boundaries.
 * Match the deliberately small, immutable transport-error shape instead.
 */
export function isApiErrorStatus(error: unknown, status: number): error is ApiError {
  return (
    typeof error === "object" &&
    error !== null &&
    "name" in error &&
    error.name === "ApiError" &&
    "status" in error &&
    error.status === status &&
    "code" in error &&
    typeof error.code === "string"
  );
}

export interface ApiGetResult<T> {
  readonly data: T;
  readonly etag: string | null;
  readonly requestId: string | null;
}

async function sessionHeaders(): Promise<Headers> {
  const session = (await cookies()).get(sessionCookieName)?.value;
  return internalApiHeaders(session);
}

export async function apiGetResult<T>(path: `/${string}`): Promise<ApiGetResult<T>> {
  // Keep Next's dynamic-request signal outside the transport error boundary so
  // cookie-backed routes are classified as dynamic during production builds.
  const headers = await sessionHeaders();
  let response: Response;
  try {
    response = await fetch(`${runtimeConfig.apiInternalOrigin}/api/v1${path}`, {
      method: "GET",
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(8_000),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "The management API is unavailable";
    throw new ApiError(503, "service_unavailable", message);
  }

  const requestId = response.headers.get("x-request-id");
  if (!response.ok) {
    // Layouts and pages are rendered in parallel. Redirect every protected
    // Server Component read on an authoritative 401 so a child data fetch
    // cannot escape the layout's authentication boundary as a logged error.
    if (response.status === 401) redirect("/login");

    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      // A malformed upstream error remains a stable dashboard-side failure.
    }
    if (isErrorResponse(payload)) {
      throw new ApiError(response.status, payload.error.code, payload.error.message, payload.error.requestId);
    }
    throw new ApiError(response.status, "invalid_upstream_response", "The management API returned an invalid response", requestId);
  }

  try {
    return {
      data: (await response.json()) as T,
      etag: response.headers.get("etag"),
      requestId,
    };
  } catch {
    throw new ApiError(502, "invalid_upstream_response", "The management API returned invalid JSON", requestId);
  }
}

export async function apiGet<T>(path: `/${string}`): Promise<T> {
  return (await apiGetResult<T>(path)).data;
}
