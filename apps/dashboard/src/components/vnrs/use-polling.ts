"use client";

import { PollingController, type PollingSnapshot } from "@/lib/behavior/polling";
import { useEffect, useState, useSyncExternalStore } from "react";

export function usePolling<T>(
  initialData: T,
  fetchData: (signal: AbortSignal) => Promise<T>,
  intervalMilliseconds: number,
): Readonly<{ refresh: () => void; snapshot: PollingSnapshot<T> }> {
  const [controller] = useState(
    () => new PollingController({ fetch: fetchData, initialData, intervalMilliseconds }),
  );

  useEffect(() => {
    controller.start();
    return () => controller.stop();
  }, [controller]);

  const snapshot = useSyncExternalStore(
    controller.subscribe,
    controller.getSnapshot,
    controller.getSnapshot,
  );

  return { refresh: () => controller.refresh(), snapshot };
}
