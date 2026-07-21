"use client";

import {
  actionableApiError,
  browserApiErrorFromResponse,
  BrowserApiError,
  readBrowserApiJson,
  requireBrowserApiOk,
} from "@/lib/browser-api-error";

export { BrowserApiError as ClientApiError };
export const errorFromResponse = browserApiErrorFromResponse;
export const requireOk = requireBrowserApiOk;
export const readJson = readBrowserApiJson;

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
  return actionableApiError(error, { resourceLabel: "VNR" });
}
