"use client";

import type { components } from "@ntip/contracts";
import { createMutationAttempt, type MutationMethod, type MutationResponseKind } from "@/lib/behavior/mutation";

type ErrorResponse = components["schemas"]["ErrorResponse"];

export class SecurityApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "SecurityApiError";
    this.status = status;
    this.code = code;
  }
}

async function responseError(response: Response): Promise<SecurityApiError> {
  const payload = await response.json().catch(() => null) as ErrorResponse | null;
  return new SecurityApiError(
    response.status,
    payload?.error.code ?? "invalid_upstream_response",
    payload?.error.message ?? `Management request failed (${response.status})`,
  );
}

export async function securityGet<T>(path: `/api/v1/${string}`): Promise<T> {
  const response = await fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw await responseError(response);
  return await response.json() as T;
}

export async function getUserWithEtag(id: string): Promise<{
  data: components["schemas"]["User"];
  etag: string;
}> {
  const response = await fetch(`/api/v1/users/${encodeURIComponent(id)}`, {
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw await responseError(response);
  const etag = response.headers.get("etag");
  if (etag === null) throw new SecurityApiError(502, "missing_precondition", "The user response did not include an ETag");
  return { data: await response.json() as components["schemas"]["User"], etag };
}

export async function securityReauthenticate(csrfToken: string, password: string): Promise<void> {
  await securityMutation({
    body: { password },
    csrfToken,
    method: "POST",
    path: "/api/v1/auth/reauth",
    responseKind: "json",
  });
}

export async function securityMutation<TResponse = void, TBody = never>(options: Readonly<{
  body?: TBody;
  csrfToken: string;
  ifMatch?: string;
  method: MutationMethod;
  path: `/api/v1/${string}`;
  responseKind?: MutationResponseKind;
}>): Promise<TResponse> {
  const attempt = createMutationAttempt({
    ...(options.body === undefined ? {} : { body: options.body }),
    csrfToken: options.csrfToken,
    ...(options.ifMatch === undefined ? {} : { ifMatch: options.ifMatch, requiresIfMatch: true }),
    method: options.method,
    ...(options.responseKind === undefined ? {} : { responseKind: options.responseKind }),
    url: new URL(options.path, window.location.origin),
  });
  const response = await fetch(attempt.buildRequest());
  if (!response.ok) throw await responseError(response);
  if (response.status === 204) return undefined as TResponse;
  return await response.json() as TResponse;
}

export function downloadTemporaryPassword(username: string, temporaryPassword: string): void {
  const contents = `NTIP temporary management password\nUsername: ${username}\nTemporary password: ${temporaryPassword}\n\nThis password must be changed at first sign-in. Store and transmit it securely.\n`;
  const blob = new Blob([contents], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `ntip-${username}-temporary-password.txt`;
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  requestAnimationFrame(() => URL.revokeObjectURL(url));
}
