"use client";

import type { components } from "@ntip/contracts";

type ErrorResponse = components["schemas"]["ErrorResponse"];

function isErrorResponse(value: unknown): value is ErrorResponse {
  if (typeof value !== "object" || value === null || !("error" in value)) return false;
  const error = value.error;
  return (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof error.message === "string"
  );
}

export async function responseError(response: Response): Promise<Error> {
  let value: unknown = null;
  try {
    value = await response.json();
  } catch {
    // Preserve a stable client message when an upstream response is malformed.
  }
  const requestId = response.headers.get("x-request-id");
  const message = isErrorResponse(value)
    ? value.error.message
    : `Request failed with status ${response.status}`;
  return new Error(requestId === null ? message : `${message} (request ${requestId})`);
}

export async function fetchJson<T>(input: string, signal?: AbortSignal): Promise<T> {
  const init: RequestInit = {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    cache: "no-store",
  };
  if (signal !== undefined) init.signal = signal;
  const response = await fetch(input, init);
  if (!response.ok) throw await responseError(response);
  return (await response.json()) as T;
}

export async function fetchJsonWithEtag<T>(input: string): Promise<Readonly<{ data: T; etag: string }>> {
  const response = await fetch(input, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw await responseError(response);
  const etag = response.headers.get("etag");
  if (etag === null || etag.length === 0) throw new Error("The management API did not return a resource ETag");
  return { data: (await response.json()) as T, etag };
}

export function freshIdempotencyKey(): string {
  return crypto.randomUUID();
}

export async function reauthenticate(csrfToken: string, password: string): Promise<void> {
  const response = await fetch("/api/v1/auth/reauth", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "Idempotency-Key": freshIdempotencyKey(),
      "X-CSRF-Token": csrfToken,
    },
    body: JSON.stringify({ password }),
  });
  if (!response.ok) throw await responseError(response);
}
