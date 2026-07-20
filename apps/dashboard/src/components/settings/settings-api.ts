"use client";

import type { components } from "@ntip/contracts";
import { createMutationAttempt, type MutationMethod } from "@/lib/behavior/mutation";

type ErrorResponse = components["schemas"]["ErrorResponse"];

export class SettingsApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "SettingsApiError";
    this.status = status;
    this.code = code;
  }
}

async function responseError(response: Response): Promise<SettingsApiError> {
  const payload = await response.json().catch(() => null) as ErrorResponse | null;
  return new SettingsApiError(
    response.status,
    payload?.error.code ?? "invalid_upstream_response",
    payload?.error.message ?? `Management request failed (${response.status})`,
  );
}

export async function settingsGet<T>(path: `/api/v1/${string}`): Promise<T> {
  const response = await fetch(path, { cache: "no-store", credentials: "same-origin", headers: { Accept: "application/json" } });
  if (!response.ok) throw await responseError(response);
  return await response.json() as T;
}

export async function getSettingsWithEtag(): Promise<{ data: components["schemas"]["SettingsState"]; etag: string }> {
  const response = await fetch("/api/v1/settings", { cache: "no-store", credentials: "same-origin", headers: { Accept: "application/json" } });
  if (!response.ok) throw await responseError(response);
  const etag = response.headers.get("etag");
  if (etag === null) throw new SettingsApiError(502, "missing_precondition", "The settings response did not include an ETag");
  return { data: await response.json() as components["schemas"]["SettingsState"], etag };
}

export async function settingsReauthenticate(csrfToken: string, password: string): Promise<void> {
  await settingsMutation({ body: { password }, csrfToken, method: "POST", path: "/api/v1/auth/reauth" });
}

export async function settingsMutation<TResponse, TBody>(options: Readonly<{
  body: TBody;
  csrfToken: string;
  ifMatch?: string;
  method: MutationMethod;
  path: `/api/v1/${string}`;
}>): Promise<TResponse> {
  const attempt = createMutationAttempt({
    body: options.body,
    csrfToken: options.csrfToken,
    ...(options.ifMatch === undefined ? {} : { ifMatch: options.ifMatch, requiresIfMatch: true }),
    method: options.method,
    url: new URL(options.path, window.location.origin),
  });
  const response = await fetch(attempt.buildRequest());
  if (!response.ok) throw await responseError(response);
  return await response.json() as TResponse;
}
