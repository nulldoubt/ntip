"use client";

import type { components } from "@ntip/contracts";
import { createMutationAttempt, type MutationMethod } from "@/lib/behavior/mutation";

type ErrorResponse = components["schemas"]["ErrorResponse"];

export class ActivityApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ActivityApiError";
    this.status = status;
    this.code = code;
  }
}

async function responseError(response: Response): Promise<ActivityApiError> {
  const payload = await response.json().catch(() => null) as ErrorResponse | null;
  return new ActivityApiError(
    response.status,
    payload?.error.code ?? "invalid_upstream_response",
    payload?.error.message ?? `Management request failed (${response.status})`,
  );
}

export async function getActivityJson<T>(path: `/api/v1/${string}`): Promise<T> {
  const response = await fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw await responseError(response);
  return await response.json() as T;
}

export async function getAuditHead(): Promise<{
  data: components["schemas"]["AuditPage"];
  etag: string;
}> {
  const response = await fetch("/api/v1/audit?limit=1", {
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw await responseError(response);
  const etag = response.headers.get("etag");
  if (etag === null) throw new ActivityApiError(502, "missing_precondition", "The audit response did not include an ETag");
  return { data: await response.json() as components["schemas"]["AuditPage"], etag };
}

export async function reauthenticate(csrfToken: string, password: string): Promise<void> {
  const attempt = createMutationAttempt({
    body: { password },
    csrfToken,
    method: "POST",
    url: new URL("/api/v1/auth/reauth", window.location.origin),
  });
  const response = await fetch(attempt.buildRequest());
  if (!response.ok) throw await responseError(response);
}

export async function activityMutation<TResponse, TBody>(options: Readonly<{
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

export async function exportAudit(options: Readonly<{
  csrfToken: string;
  etag: string;
  throughAuditId: string;
}>): Promise<{ exportId: string; filename: string }> {
  const attempt = createMutationAttempt({
    body: { throughAuditId: options.throughAuditId, confirmation: "export audit" },
    csrfToken: options.csrfToken,
    ifMatch: options.etag,
    method: "POST",
    requiresIfMatch: true,
    responseKind: "one-time",
    url: new URL("/api/v1/audit/export", window.location.origin),
  });
  const response = await fetch(attempt.buildRequest());
  if (!response.ok) throw await responseError(response);

  const exportId = response.headers.get("x-ntip-audit-export-id");
  if (exportId === null) throw new ActivityApiError(502, "missing_export_receipt", "The export response did not include its durable receipt ID");

  const contentDisposition = response.headers.get("content-disposition") ?? "";
  const filenameMatch = /^attachment; filename="([A-Za-z0-9._-]+)"$/.exec(contentDisposition);
  const filename = filenameMatch?.[1] ?? `ntip-audit-${options.throughAuditId}.ndjson`;
  const body = await response.blob();
  const url = URL.createObjectURL(body);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  requestAnimationFrame(() => URL.revokeObjectURL(url));
  return { exportId, filename };
}
