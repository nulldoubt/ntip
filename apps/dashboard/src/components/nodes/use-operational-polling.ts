"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import { PollingController, type PollingSnapshot } from "@/lib/behavior/polling";

export type OperationalPolling<T> = PollingSnapshot<T> & Readonly<{ refresh: () => void }>;

/** Uses the shared two-slot scheduler for an operational read that spans cursors. */
export function useOperationalPolling<T>(
  initialData: T,
  fetchCurrent: (signal: AbortSignal) => Promise<T>,
  intervalMilliseconds: number,
): OperationalPolling<T> {
  const [controller] = useState(() => new PollingController<T>({
    initialData,
    intervalMilliseconds,
    // Callers provide a module-level function, so this identity is stable for
    // the lifetime of the controller.
    fetch: fetchCurrent,
  }));

  useEffect(() => {
    controller.start();
    return () => controller.stop();
  }, [controller]);

  const snapshot = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  return { ...snapshot, refresh: () => controller.refresh() };
}
