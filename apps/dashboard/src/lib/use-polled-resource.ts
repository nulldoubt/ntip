"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import {
  PollingController,
  type PollingSnapshot,
} from "@/lib/behavior/polling";

type ApiErrorPayload = Readonly<{
  error?: Readonly<{ message?: unknown }>;
}>;

async function fetchJson<T>(path: string, signal: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
    signal,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as ApiErrorPayload | null;
    const message = typeof payload?.error?.message === "string"
      ? payload.error.message
      : `Management API request failed (${response.status})`;
    throw new Error(message);
  }
  return await response.json() as T;
}

export function usePolledResource<T>(
  path: `/api/v1/${string}`,
  intervalMilliseconds: number,
  initialData: T,
): PollingSnapshot<T> & Readonly<{ refresh(): void }> {
  const [controller] = useState(() => new PollingController<T>({
    fetch: (signal) => fetchJson<T>(path, signal),
    initialData,
    intervalMilliseconds,
  }));

  useEffect(() => {
    controller.start();
    return () => controller.stop();
  }, [controller]);

  const snapshot = useSyncExternalStore(
    controller.subscribe,
    controller.getSnapshot,
    controller.getSnapshot,
  );
  return { ...snapshot, refresh: () => controller.refresh() };
}
