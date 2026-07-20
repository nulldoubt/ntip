import type { components } from "@ntip/contracts";

type Liveness = components["schemas"]["LivenessState"];
type EnrollmentState = components["schemas"]["EnrollmentState"];
type ConnectivityStatus = components["schemas"]["ConnectivityCheckStatus"];

export type StatusTone = "healthy" | "warning" | "critical" | "neutral" | "info" | "copper";

export function livenessTone(state: Liveness): StatusTone {
  switch (state) {
    case "online": return "healthy";
    case "suspect": return "warning";
    case "offline": return "critical";
    case "unknown": return "neutral";
  }
}

export function enrollmentTone(state: EnrollmentState): StatusTone {
  switch (state) {
    case "enrolled": return "healthy";
    case "credential_issued": return "warning";
    case "unenrolled": return "neutral";
  }
}

export function connectivityTone(state: ConnectivityStatus): StatusTone {
  switch (state) {
    case "succeeded": return "healthy";
    case "queued":
    case "running": return "info";
    case "timed_out":
    case "failed": return "critical";
    case "interrupted": return "warning";
  }
}

export function readableState(state: string): string {
  return state.replaceAll("_", " ");
}

export function formatUtc(value: string | null): string {
  if (value === null) return "Not observed";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Invalid time";
  return `${new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(date)} UTC`;
}

export function shortId(value: string): string {
  return value.length <= 12 ? value : `${value.slice(0, 8)}…${value.slice(-4)}`;
}
