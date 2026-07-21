"use client";

import {
  browserApiErrorFromResponse,
  readBrowserApiJson,
  requireBrowserApiOk,
} from "@/lib/browser-api-error";

export const responseError = browserApiErrorFromResponse;

export async function fetchJson<T>(input: string, signal?: AbortSignal): Promise<T> {
  const init: RequestInit = {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    cache: "no-store",
  };
  if (signal !== undefined) init.signal = signal;
  const response = await fetch(input, init);
  return readBrowserApiJson<T>(response);
}

export async function fetchJsonWithEtag<T>(input: string): Promise<Readonly<{ data: T; etag: string }>> {
  const response = await fetch(input, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  await requireBrowserApiOk(response);
  const etag = response.headers.get("etag");
  if (etag === null || etag.length === 0) throw new Error("The management API did not return a resource ETag");
  return { data: await readBrowserApiJson<T>(response), etag };
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
