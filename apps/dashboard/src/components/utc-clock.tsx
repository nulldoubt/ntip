"use client";

import { useSyncExternalStore } from "react";

function subscribe(listener: () => void): () => void {
  const timer = window.setInterval(listener, 1_000);
  return () => window.clearInterval(timer);
}

function snapshot(): string {
  return new Intl.DateTimeFormat("en", {
    timeZone: "UTC",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).format(new Date());
}

export function UtcClock() {
  const value = useSyncExternalStore(subscribe, snapshot, () => "--:--:--");
  return <time className="font-mono text-[0.6875rem] tabular-nums text-muted-foreground">{value} UTC</time>;
}
