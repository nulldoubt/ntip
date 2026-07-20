"use client";

import type { components } from "@ntip/contracts";
import {
  Badge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  cn,
} from "@ntip/ui";
import {
  Activity,
  ArrowUpRight,
  CircleAlert,
  CircleCheck,
  CircleHelp,
  Clock3,
  Network,
  Route,
  Server,
  Settings2,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";
import type { PollingFreshness, PollingPauseReason, PollingPhase } from "@/lib/behavior/polling";
import { usePolledResource } from "@/lib/use-polled-resource";

type Overview = components["schemas"]["Overview"];
type Topology = components["schemas"]["Topology"];
type EventPage = components["schemas"]["EventPage"];
type Liveness = components["schemas"]["LivenessState"];
type Traffic = components["schemas"]["TrafficState"];

type FreshnessProps = Readonly<{
  hasData?: boolean;
  error: string | null;
  freshness: PollingFreshness;
  lastSuccessAt: number | null;
  pauseReason: PollingPauseReason | null;
  phase: PollingPhase;
}>;

function formatUtc(timestamp: string | number): string {
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) return "Invalid time";
  return `${new Intl.DateTimeFormat("en", {
    timeZone: "UTC",
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).format(parsed)} UTC`;
}

function formatAge(timestamp: string | number): string {
  const milliseconds = Date.now() - new Date(timestamp).getTime();
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return formatUtc(timestamp);
  const seconds = Math.floor(milliseconds / 1_000);
  if (seconds < 10) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

function shortId(id: string): string {
  return id.length <= 12 ? id : `${id.slice(0, 8)}…${id.slice(-4)}`;
}

function livenessTone(liveness: Liveness): "healthy" | "warning" | "critical" | "neutral" {
  switch (liveness) {
    case "online":
      return "healthy";
    case "suspect":
      return "warning";
    case "offline":
      return "critical";
    case "unknown":
      return "neutral";
  }
}

function trafficTone(traffic: Traffic): "healthy" | "warning" | "critical" | "neutral" | "info" {
  switch (traffic) {
    case "warm":
      return "healthy";
    case "hot":
      return "warning";
    case "saturated":
      return "critical";
    case "cold":
      return "info";
    case "unknown":
      return "neutral";
  }
}

function FreshnessBadge({ hasData = true, error, freshness, lastSuccessAt, pauseReason, phase }: FreshnessProps) {
  if (!hasData || freshness === "empty") {
    return <Badge tone="critical">Unavailable</Badge>;
  }

  if (freshness === "stale") {
    const detail = error
      ?? (pauseReason === "offline"
        ? "Polling paused while this workstation is offline"
        : pauseReason === "hidden"
          ? "Polling paused while this page is hidden"
          : "Awaiting the first live refresh");
    return (
      <Badge tone="warning" title={detail}>
        {pauseReason === "offline" ? "Offline · last-known-good" : "Last-known-good"}
      </Badge>
    );
  }

  return (
    <Badge tone="healthy" title={lastSuccessAt === null ? undefined : `Refreshed ${formatUtc(lastSuccessAt)}`}>
      {phase === "polling" ? "Refreshing" : "Live"}
    </Badge>
  );
}

function Metric({
  label,
  value,
  detail,
  icon: Icon,
  emphasis = false,
}: Readonly<{
  label: string;
  value: string;
  detail: string;
  icon: typeof Network;
  emphasis?: boolean;
}>) {
  return (
    <div className="min-w-0 px-4 py-4 first:pl-0 last:pr-0">
      <div className="flex items-center justify-between gap-3">
        <p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.085em] text-muted-foreground">
          {label}
        </p>
        <Icon aria-hidden="true" className={cn("size-4", emphasis ? "text-primary" : "text-muted-foreground")} strokeWidth={1.7} />
      </div>
      <p className="mt-3 font-mono text-2xl font-medium tabular-nums tracking-tight">{value}</p>
      <p className="mt-1 truncate text-xs text-muted-foreground">{detail}</p>
    </div>
  );
}

function RuntimeBar({ count, total, className }: Readonly<{ count: number; total: number; className: string }>) {
  const width = total === 0 ? 0 : Math.max(1.5, (count / total) * 100);
  return <span aria-hidden="true" className={cn("block h-full", className)} style={{ width: `${width}%` }} />;
}

function RuntimeSummary({ overview }: Readonly<{ overview: Overview }>) {
  const entries = [
    { label: "Online", count: overview.runtime.online, bar: "bg-success", text: "text-success" },
    { label: "Suspect", count: overview.runtime.suspect, bar: "bg-warning", text: "text-warning" },
    { label: "Offline", count: overview.runtime.offline, bar: "bg-destructive", text: "text-destructive" },
    { label: "Unknown", count: overview.runtime.unknown, bar: "bg-muted-foreground", text: "text-muted-foreground" },
  ] as const;
  const total = entries.reduce((sum, entry) => sum + entry.count, 0);

  return (
    <section className="border border-border bg-card" aria-labelledby="runtime-summary-title">
      <header className="flex h-11 items-center justify-between border-b border-border px-4">
        <div className="flex items-center gap-2">
          <Activity aria-hidden="true" className="size-4 text-primary" />
          <h2 id="runtime-summary-title" className="text-sm font-semibold">Runtime state</h2>
        </div>
        <span className="font-mono text-[0.6875rem] text-muted-foreground">{total} observed</span>
      </header>
      <div className="p-4">
        <div className="flex h-2 overflow-hidden bg-muted" aria-hidden="true">
          {entries.map((entry) => (
            <RuntimeBar key={entry.label} count={entry.count} total={total} className={entry.bar} />
          ))}
        </div>
        <dl className="mt-5 grid grid-cols-2 gap-x-8 gap-y-4">
          {entries.map((entry) => (
            <div key={entry.label} className="flex items-center justify-between border-b border-border pb-2">
              <dt className="flex items-center gap-2 text-xs text-muted-foreground">
                <span className={cn("size-1.5 rounded-full", entry.bar)} aria-hidden="true" />
                {entry.label}
              </dt>
              <dd className={cn("font-mono text-sm font-semibold tabular-nums", entry.text)}>{entry.count}</dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  );
}

function ServicePosture({ overview }: Readonly<{ overview: Overview }>) {
  const needsAttention = overview.runtime.suspect + overview.runtime.offline;
  return (
    <section className="border border-border bg-card" aria-labelledby="service-posture-title">
      <header className="flex h-11 items-center gap-2 border-b border-border px-4">
        <ShieldAlert aria-hidden="true" className="size-4 text-primary" />
        <h2 id="service-posture-title" className="text-sm font-semibold">Service posture</h2>
      </header>
      <dl className="divide-y divide-border px-4">
        <div className="flex min-h-12 items-center justify-between gap-4 py-2">
          <dt className="text-xs text-muted-foreground">Operational attention</dt>
          <dd>
            <Badge tone={needsAttention === 0 ? "healthy" : "warning"}>
              {needsAttention === 0 ? "Nominal" : `${needsAttention} nodes`}
            </Badge>
          </dd>
        </div>
        <div className="flex min-h-12 items-center justify-between gap-4 py-2">
          <dt className="text-xs text-muted-foreground">Restart state</dt>
          <dd>
            <Badge tone={overview.pendingRestart ? "warning" : "neutral"}>
              {overview.pendingRestart ? "Restart pending" : "No restart pending"}
            </Badge>
          </dd>
        </div>
        <div className="flex min-h-12 items-center justify-between gap-4 py-2">
          <dt className="text-xs text-muted-foreground">Desired settings</dt>
          <dd className="font-mono text-[0.6875rem] text-foreground" title={overview.desiredSettingsRevisionId}>
            {shortId(overview.desiredSettingsRevisionId)}
          </dd>
        </div>
        <div className="flex min-h-12 items-center justify-between gap-4 py-2">
          <dt className="text-xs text-muted-foreground">Effective settings</dt>
          <dd className="font-mono text-[0.6875rem] text-foreground" title={overview.effectiveSettingsRevisionId}>
            {shortId(overview.effectiveSettingsRevisionId)}
          </dd>
        </div>
      </dl>
    </section>
  );
}

function NodeRuntimeTable({ topology, freshness }: Readonly<{ topology: Topology | null; freshness: FreshnessProps }>) {
  const nodeById = new Map(topology?.nodes.map((node) => [node.id, node]) ?? []);
  const rows = topology?.runtime ?? [];

  return (
    <section className="border border-border bg-card" aria-labelledby="node-state-title">
      <header className="flex min-h-11 items-center justify-between gap-4 border-b border-border px-4 py-2">
        <div className="flex items-center gap-2">
          <Server aria-hidden="true" className="size-4 text-primary" />
          <h2 id="node-state-title" className="text-sm font-semibold">Node state</h2>
        </div>
        <div className="flex items-center gap-3" aria-live="polite">
          <FreshnessBadge {...freshness} />
          <Link href="/nodes" className="inline-flex items-center gap-1 text-xs font-medium text-primary-strong hover:underline">
            View nodes <ArrowUpRight aria-hidden="true" className="size-3.5" />
          </Link>
        </div>
      </header>
      {topology === null ? (
        <p className="px-4 py-8 text-sm text-muted-foreground">Runtime detail is temporarily unavailable.</p>
      ) : rows.length === 0 ? (
        <p className="px-4 py-8 text-sm text-muted-foreground">No runtime observations have been recorded.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>Node</TableHead>
              <TableHead>VNR</TableHead>
              <TableHead>Liveness</TableHead>
              <TableHead>Session</TableHead>
              <TableHead>Traffic</TableHead>
              <TableHead>Observed endpoint</TableHead>
              <TableHead className="text-right">Observed</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.slice(0, 10).map((observation) => {
              const node = nodeById.get(observation.nodeId);
              return (
                <TableRow key={observation.nodeId}>
                  <TableCell>
                    <Link href={`/nodes/${observation.nodeId}`} className="font-medium hover:text-primary-strong hover:underline">
                      {node?.name ?? shortId(observation.nodeId)}
                    </Link>
                    <p className="mt-0.5 font-mono text-[0.625rem] text-muted-foreground">{node?.address ?? "Address unavailable"}</p>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{node?.vnrName ?? "Unknown"}</TableCell>
                  <TableCell><Badge tone={livenessTone(observation.liveness)}>{observation.liveness}</Badge></TableCell>
                  <TableCell className="text-xs capitalize">{observation.sessionState}</TableCell>
                  <TableCell><Badge tone={trafficTone(observation.trafficState)}>{observation.trafficState}</Badge></TableCell>
                  <TableCell className="font-mono text-[0.6875rem] text-muted-foreground">
                    {observation.observedEndpoint ?? "Not observed"}
                  </TableCell>
                  <TableCell className="text-right text-xs text-muted-foreground">
                    <time suppressHydrationWarning dateTime={observation.observedAt} title={formatUtc(observation.observedAt)}>
                      {formatAge(observation.observedAt)}
                    </time>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}
    </section>
  );
}

function EventFeed({ events, freshness }: Readonly<{ events: EventPage | null; freshness: FreshnessProps }>) {
  function eventIcon(severity: components["schemas"]["EventSeverity"]) {
    if (severity === "critical") return <CircleAlert aria-hidden="true" className="size-4 text-destructive" />;
    if (severity === "warning") return <CircleHelp aria-hidden="true" className="size-4 text-warning" />;
    return <CircleCheck aria-hidden="true" className="size-4 text-info" />;
  }

  return (
    <section className="border border-border bg-card" aria-labelledby="recent-activity-title">
      <header className="flex min-h-11 items-center justify-between gap-4 border-b border-border px-4 py-2">
        <div className="flex items-center gap-2">
          <Clock3 aria-hidden="true" className="size-4 text-primary" />
          <h2 id="recent-activity-title" className="text-sm font-semibold">Recent activity</h2>
        </div>
        <div className="flex items-center gap-3" aria-live="polite">
          <FreshnessBadge {...freshness} />
          <Link href="/activity" className="inline-flex items-center gap-1 text-xs font-medium text-primary-strong hover:underline">
            View activity <ArrowUpRight aria-hidden="true" className="size-3.5" />
          </Link>
        </div>
      </header>
      {events === null ? (
        <p className="px-4 py-8 text-sm text-muted-foreground">Activity is temporarily unavailable.</p>
      ) : events.items.length === 0 ? (
        <p className="px-4 py-8 text-sm text-muted-foreground">No retained events.</p>
      ) : (
        <ol className="divide-y divide-border">
          {events.items.slice(0, 6).map((event) => (
            <li key={event.id} className="grid grid-cols-[1rem_minmax(0,1fr)_auto] items-start gap-3 px-4 py-3">
              <span className="mt-0.5">{eventIcon(event.severity)}</span>
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{event.summary ?? event.kind}</p>
                <p className="mt-1 truncate font-mono text-[0.625rem] text-muted-foreground">
                  {event.resourceType}{event.resourceId === null ? "" : `:${event.resourceId}`}
                </p>
              </div>
              <time suppressHydrationWarning dateTime={event.occurredAt} title={formatUtc(event.occurredAt)} className="text-xs text-muted-foreground">
                {formatAge(event.occurredAt)}
              </time>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

export function OverviewLive({
  initialOverview,
  initialTopology,
  initialEvents,
}: Readonly<{
  initialOverview: Overview;
  initialTopology: Topology | null;
  initialEvents: EventPage | null;
}>) {
  const overviewPolling = usePolledResource<Overview>("/api/v1/overview", 10_000, initialOverview);
  const topologyPolling = usePolledResource<Topology | null>("/api/v1/topology", 10_000, initialTopology);
  const eventPolling = usePolledResource<EventPage | null>("/api/v1/events?limit=6", 15_000, initialEvents);
  const overview = overviewPolling.data ?? initialOverview;
  const topology = topologyPolling.data;
  const events = eventPolling.data;
  const attention = overview.runtime.suspect + overview.runtime.offline;

  return (
    <div className="mx-auto w-full max-w-[112rem] p-5">
      <header className="mb-5 flex items-end justify-between gap-8">
        <div>
          <p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.11em] text-primary-strong">
            Control plane register
          </p>
          <h1 className="mt-1 text-xl font-semibold tracking-tight">Network overview</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Inventory generation <span className="font-mono text-foreground">{overview.generation}</span>
          </p>
        </div>
        <div className="text-right">
          <div className="flex items-center justify-end gap-2" aria-live="polite">
            <FreshnessBadge
              error={overviewPolling.error}
              freshness={overviewPolling.freshness}
              lastSuccessAt={overviewPolling.lastSuccessAt}
              pauseReason={overviewPolling.pauseReason}
              phase={overviewPolling.phase}
            />
            <p className="flex items-center justify-end gap-2 text-xs font-medium">
              <span className={cn("size-1.5 rounded-full", attention === 0 ? "bg-success" : "bg-warning")} aria-hidden="true" />
              {attention === 0 ? "No nodes need attention" : `${attention} nodes need attention`}
            </p>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Observed <time suppressHydrationWarning dateTime={overview.observedAt} title={formatUtc(overview.observedAt)}>{formatAge(overview.observedAt)}</time>
          </p>
        </div>
      </header>

      <section className="grid grid-cols-5 divide-x divide-border border-y border-border" aria-label="Inventory summary">
        <Metric label="VNRs" value={overview.inventory.vnrs.toLocaleString()} detail="configured networks" icon={Network} />
        <Metric label="Nodes" value={overview.inventory.nodes.toLocaleString()} detail="configured identities" icon={Server} />
        <Metric label="Routes" value={overview.inventory.routes.toLocaleString()} detail="owned prefixes" icon={Route} />
        <Metric label="Online" value={overview.runtime.online.toLocaleString()} detail={`${attention} need attention`} icon={Activity} emphasis />
        <Metric label="Generation" value={overview.generation.toLocaleString()} detail="durable projection" icon={Settings2} />
      </section>

      <div className="mt-5 grid grid-cols-2 gap-4">
        <RuntimeSummary overview={overview} />
        <ServicePosture overview={overview} />
      </div>

      <div className="mt-4">
        <NodeRuntimeTable
          topology={topology}
          freshness={{
            hasData: topology !== null,
            error: topologyPolling.error,
            freshness: topologyPolling.freshness,
            lastSuccessAt: topologyPolling.lastSuccessAt,
            pauseReason: topologyPolling.pauseReason,
            phase: topologyPolling.phase,
          }}
        />
      </div>

      <div className="mt-4">
        <EventFeed
          events={events}
          freshness={{
            hasData: events !== null,
            error: eventPolling.error,
            freshness: eventPolling.freshness,
            lastSuccessAt: eventPolling.lastSuccessAt,
            pauseReason: eventPolling.pauseReason,
            phase: eventPolling.phase,
          }}
        />
      </div>

      <footer className="mt-4 flex items-center justify-between border-t border-border pt-3 text-[0.6875rem] text-muted-foreground">
        <span>Operational data refreshes every 10 seconds; activity refreshes every 15 seconds.</span>
        <time dateTime={overview.observedAt}>{formatUtc(overview.observedAt)}</time>
      </footer>
    </div>
  );
}
