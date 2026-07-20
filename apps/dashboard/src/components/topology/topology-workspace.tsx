"use client";

import type { components } from "@ntip/contracts";
import {
  Badge,
  Button,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  cn,
} from "@ntip/ui";
import {
  Box,
  Focus,
  Minus,
  Network,
  Plus,
  RefreshCw,
  Route as RouteIcon,
  Search,
  Server,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useRef, useState, type KeyboardEvent, type PointerEvent as ReactPointerEvent, type ReactNode, type WheelEvent } from "react";
import { createTopologyModel, type TopologyEntityKind } from "@/lib/behavior/topology";
import { usePolledResource } from "@/lib/use-polled-resource";
import { formatUtc, livenessTone, shortId } from "@/components/nodes/node-presenters";

type Topology = components["schemas"]["Topology"];
type Node = components["schemas"]["Node"];
type NodeRuntime = components["schemas"]["NodeRuntime"];
type Route = components["schemas"]["Route"];
type Vnr = components["schemas"]["Vnr"];
type Liveness = components["schemas"]["LivenessState"];

type TopologyWorkspaceProps = Readonly<{ initialTopology: Topology }>;

type ViewTransform = Readonly<{ x: number; y: number; zoom: number }>;
type DragState = Readonly<{ pointerId: number; startX: number; startY: number; originX: number; originY: number }>;

const BOX_WIDTH: Readonly<Record<TopologyEntityKind, number>> = {
  master: 168,
  vnr: 190,
  node: 206,
  route: 190,
};
const BOX_HEIGHT = 48;

function latestRuntime(items: readonly NodeRuntime[]): ReadonlyMap<string, NodeRuntime> {
  const result = new Map<string, NodeRuntime>();
  for (const runtime of items) {
    const current = result.get(runtime.nodeId);
    if (current === undefined || current.observedAt < runtime.observedAt) result.set(runtime.nodeId, runtime);
  }
  return result;
}

function filterTopology(source: Topology, query: string, selectedVnr: string, selectedLiveness: string): Topology {
  const normalized = query.trim().toLowerCase();
  const runtimeByNode = latestRuntime(source.runtime);
  const routeByNode = new Map<string, Route[]>();
  for (const route of source.routes) {
    const current = routeByNode.get(route.nodeId) ?? [];
    current.push(route);
    routeByNode.set(route.nodeId, current);
  }

  const includedNodes = source.nodes.filter((node) => {
    if (selectedVnr !== "all" && node.vnrName !== selectedVnr) return false;
    const runtime = runtimeByNode.get(node.id);
    if (selectedLiveness !== "all" && (runtime?.liveness ?? "unknown") !== selectedLiveness) return false;
    if (normalized.length === 0) return true;
    const vnr = source.vnrs.find((item) => item.name === node.vnrName);
    const routeMatch = (routeByNode.get(node.id) ?? []).some((route) => route.prefix.toLowerCase().includes(normalized));
    return routeMatch || [node.id, node.name, node.address, node.vnrName, vnr?.cidr ?? ""].some((value) => value.toLowerCase().includes(normalized));
  });
  const nodeVnrs = new Set(includedNodes.map((node) => node.vnrName));
  const vnrs = source.vnrs.filter((vnr) => {
    if (selectedVnr !== "all" && vnr.name !== selectedVnr) return false;
    return nodeVnrs.has(vnr.name) || (normalized.length > 0 && [vnr.name, vnr.cidr].some((value) => value.toLowerCase().includes(normalized)));
  });
  const vnrNames = new Set(vnrs.map((vnr) => vnr.name));
  const nodes = includedNodes.filter((node) => vnrNames.has(node.vnrName));
  const finalNodeIds = new Set(nodes.map((node) => node.id));

  return {
    generation: source.generation,
    observedAt: source.observedAt,
    vnrs,
    nodes,
    routes: source.routes.filter((route) => finalNodeIds.has(route.nodeId)),
    runtime: source.runtime.filter((runtime) => finalNodeIds.has(runtime.nodeId)),
  };
}

function entityIcon(kind: TopologyEntityKind): ReactNode {
  switch (kind) {
    case "master": return <Box aria-hidden="true" className="size-4" />;
    case "vnr": return <Network aria-hidden="true" className="size-4" />;
    case "node": return <Server aria-hidden="true" className="size-4" />;
    case "route": return <RouteIcon aria-hidden="true" className="size-4" />;
  }
}

function keyActivate(event: KeyboardEvent<SVGGElement>, activate: () => void) {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    activate();
  }
}

function TopologyMap({ topology, selectedKey, onSelect }: Readonly<{ topology: Topology; selectedKey: string; onSelect: (key: string) => void }>) {
  const model = useMemo(() => createTopologyModel(topology), [topology]);
  const [transform, setTransform] = useState<ViewTransform>({ x: 16, y: 28, zoom: 1 });
  const drag = useRef<DragState | null>(null);
  const entityByKey = useMemo(() => new Map(model.entities.map((entity) => [entity.key, entity])), [model.entities]);
  const runtimeByNode = useMemo(() => latestRuntime(topology.runtime), [topology.runtime]);

  function zoomBy(delta: number) {
    setTransform((current) => ({ ...current, zoom: Math.min(1.8, Math.max(0.6, Number((current.zoom + delta).toFixed(2)))) }));
  }

  function onWheel(event: WheelEvent<SVGSVGElement>) {
    event.preventDefault();
    zoomBy(event.deltaY > 0 ? -0.1 : 0.1);
  }

  function onPointerDown(event: ReactPointerEvent<SVGSVGElement>) {
    if ((event.target as Element).closest("[data-topology-entity]") !== null) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    drag.current = { pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, originX: transform.x, originY: transform.y };
  }

  function onPointerMove(event: ReactPointerEvent<SVGSVGElement>) {
    const active = drag.current;
    if (active === null || active.pointerId !== event.pointerId) return;
    setTransform((current) => ({ ...current, x: active.originX + event.clientX - active.startX, y: active.originY + event.clientY - active.startY }));
  }

  function onPointerEnd(event: ReactPointerEvent<SVGSVGElement>) {
    if (drag.current?.pointerId === event.pointerId) drag.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
  }

  return (
    <div className="relative min-h-[32rem] overflow-hidden bg-background">
      <div className="absolute right-3 top-3 z-10 flex border border-border bg-card" aria-label="Topology view controls">
        <Button type="button" variant="ghost" size="icon" aria-label="Zoom out" onClick={() => zoomBy(-0.1)}><Minus aria-hidden="true" /></Button>
        <span className="flex min-w-14 items-center justify-center border-x border-border font-mono text-[0.6875rem] tabular-nums">{Math.round(transform.zoom * 100)}%</span>
        <Button type="button" variant="ghost" size="icon" aria-label="Zoom in" onClick={() => zoomBy(0.1)}><Plus aria-hidden="true" /></Button>
        <Button type="button" variant="ghost" size="icon" aria-label="Reset view" onClick={() => setTransform({ x: 16, y: 28, zoom: 1 })}><Focus aria-hidden="true" /></Button>
      </div>
      <svg
        className="h-[32rem] w-full cursor-grab touch-none select-none active:cursor-grabbing"
        viewBox="0 0 1160 600"
        preserveAspectRatio="xMinYMin meet"
        role="img"
        aria-labelledby="topology-map-title topology-map-description"
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerEnd}
        onPointerCancel={onPointerEnd}
      >
        <title id="topology-map-title">NTIP topology map</title>
        <desc id="topology-map-description">Read-only relationships from the synthesized Master through VNRs and Nodes to owned routes. Use Tab to inspect each entity. A complete table follows the map.</desc>
        <g transform={`translate(${transform.x} ${transform.y}) scale(${transform.zoom})`}>
          {model.edges.map((edge) => {
            const source = entityByKey.get(edge.sourceKey);
            const target = entityByKey.get(edge.targetKey);
            if (source === undefined || target === undefined) return null;
            const startX = source.x + BOX_WIDTH[source.kind];
            const endX = target.x;
            const middle = (startX + endX) / 2;
            return <path key={edge.key} d={`M ${startX} ${source.y} C ${middle} ${source.y}, ${middle} ${target.y}, ${endX} ${target.y}`} fill="none" stroke="var(--border-strong)" strokeWidth="1.25" vectorEffect="non-scaling-stroke" />;
          })}
          {model.entities.map((entity) => {
            const selected = entity.key === selectedKey;
            const runtime = entity.kind === "node" ? runtimeByNode.get(entity.entityId) : undefined;
            return (
              <g
                key={entity.key}
                data-topology-entity=""
                role="button"
                tabIndex={0}
                aria-pressed={selected}
                aria-label={`${entity.kind}: ${entity.label}`}
                transform={`translate(${entity.x} ${entity.y - BOX_HEIGHT / 2})`}
                onClick={() => onSelect(entity.key)}
                onFocus={() => onSelect(entity.key)}
                onKeyDown={(event) => keyActivate(event, () => onSelect(entity.key))}
                className="cursor-pointer outline-none"
              >
                <rect width={BOX_WIDTH[entity.kind]} height={BOX_HEIGHT} rx="3" fill={selected ? "var(--primary-muted)" : "var(--card)"} stroke={selected ? "var(--primary)" : "var(--border)"} strokeWidth={selected ? "2" : "1"} vectorEffect="non-scaling-stroke" />
                <foreignObject x="10" y="8" width={BOX_WIDTH[entity.kind] - 20} height="34" pointerEvents="none">
                  <div className="flex h-full items-start gap-2 text-foreground">
                    <span className={cn("mt-0.5", selected ? "text-primary-strong" : "text-muted-foreground")}>{entityIcon(entity.kind)}</span>
                    <span className="min-w-0">
                      <span className="block truncate text-xs font-semibold">{entity.label}</span>
                      <span className="mt-0.5 block truncate font-mono text-[0.5625rem] uppercase tracking-[0.06em] text-muted-foreground">{entity.kind}{runtime === undefined ? "" : ` · ${runtime.liveness}`}</span>
                    </span>
                  </div>
                </foreignObject>
                {runtime === undefined ? null : <circle cx={BOX_WIDTH.node - 10} cy="10" r="3.5" fill={runtime.liveness === "online" ? "var(--success)" : runtime.liveness === "suspect" ? "var(--warning)" : runtime.liveness === "offline" ? "var(--destructive)" : "var(--muted-foreground)"} />}
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}

function Inspector({ topology, selectedKey }: Readonly<{ topology: Topology; selectedKey: string }>) {
  const runtimeByNode = useMemo(() => latestRuntime(topology.runtime), [topology.runtime]);
  const [kind, entityId = ""] = selectedKey.includes(":") ? selectedKey.split(":", 2) : [selectedKey, "master"];
  let title = "Master";
  let subtitle = "Synthesized topology root";
  let rows: readonly [string, ReactNode][] = [
    ["VNRs", topology.vnrs.length],
    ["Nodes", topology.nodes.length],
    ["Routes", topology.routes.length],
    ["Generation", topology.generation],
    ["Observed", formatUtc(topology.observedAt)],
  ];
  if (kind === "vnr") {
    const vnr = topology.vnrs.find((item) => item.name === entityId);
    if (vnr !== undefined) {
      title = vnr.name;
      subtitle = "Virtual network range";
      rows = [["CIDR", vnr.cidr], ["Nodes", topology.nodes.filter((node) => node.vnrName === vnr.name).length], ["Generation", vnr.generation], ["Updated", formatUtc(vnr.updatedAt)]];
    }
  } else if (kind === "node") {
    const node = topology.nodes.find((item) => item.id === entityId);
    const runtime = runtimeByNode.get(entityId);
    if (node !== undefined) {
      title = node.name;
      subtitle = "Node identity";
      rows = [["Address", node.address], ["VNR", node.vnrName], ["Enrollment", readableEnrollment(node.enrollmentState)], ["Liveness", runtime?.liveness ?? "Not observed"], ["Session", runtime?.sessionState ?? "Not observed"], ["Endpoint", runtime?.observedEndpoint ?? "Not observed"], ["Observed", runtime === undefined ? "Not observed" : formatUtc(runtime.observedAt)]];
    }
  } else if (kind === "route") {
    const route = topology.routes.find((item) => item.id === entityId);
    if (route !== undefined) {
      title = route.prefix;
      subtitle = "Owned routed prefix";
      rows = [["Owner", route.nodeName], ["Node ID", shortId(route.nodeId)], ["Generation", route.generation], ["Updated", formatUtc(route.updatedAt)]];
    }
  }

  return (
    <aside className="border-l border-border bg-card" aria-labelledby="inspector-title">
      <header className="border-b border-border p-4"><p className="font-mono text-[0.625rem] font-semibold uppercase tracking-[0.1em] text-primary">Inspector</p><h3 id="inspector-title" className="mt-1 truncate text-base font-semibold">{title}</h3><p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p></header>
      <dl className="divide-y divide-border">
        {rows.map(([label, value]) => <div key={label} className="p-4"><dt className="text-xs text-muted-foreground">{label}</dt><dd className="mt-1 break-words font-mono text-xs">{value}</dd></div>)}
      </dl>
      {kind === "node" ? <div className="border-t border-border p-3"><Button asChild variant="outline" className="w-full"><Link href={`/nodes/${entityId}`}>Open Node</Link></Button></div> : null}
    </aside>
  );
}

function readableEnrollment(value: string): string {
  return value.replaceAll("_", " ");
}

function TopologyTable({ topology, onSelect }: Readonly<{ topology: Topology; onSelect: (key: string) => void }>) {
  const runtimeByNode = useMemo(() => latestRuntime(topology.runtime), [topology.runtime]);
  const rows = useMemo(() => {
    const result: Array<{ key: string; vnr: Vnr | null; node: Node | null; route: Route | null; runtime: NodeRuntime | null }> = [];
    for (const vnr of [...topology.vnrs].sort((a, b) => a.name.localeCompare(b.name))) {
      const nodes = topology.nodes.filter((node) => node.vnrName === vnr.name).sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
      if (nodes.length === 0) result.push({ key: `vnr:${vnr.name}`, vnr, node: null, route: null, runtime: null });
      for (const node of nodes) {
        const routes = topology.routes.filter((route) => route.nodeId === node.id).sort((a, b) => a.prefix.localeCompare(b.prefix) || a.id.localeCompare(b.id));
        if (routes.length === 0) result.push({ key: `node:${node.id}`, vnr, node, route: null, runtime: runtimeByNode.get(node.id) ?? null });
        for (const route of routes) result.push({ key: `route:${route.id}`, vnr, node, route, runtime: runtimeByNode.get(node.id) ?? null });
      }
    }
    return result;
  }, [runtimeByNode, topology.nodes, topology.routes, topology.vnrs]);

  return (
    <section className="border border-border bg-card" aria-labelledby="topology-table-title">
      <header className="flex h-11 items-center justify-between border-b border-border px-3"><h3 id="topology-table-title" className="text-sm font-semibold">Accessible topology table</h3><span className="text-xs text-muted-foreground">Complete equivalent of the filtered map</span></header>
      <Table>
        <TableHeader><TableRow><TableHead>VNR</TableHead><TableHead>Node</TableHead><TableHead>Runtime</TableHead><TableHead>Route</TableHead><TableHead>Relationship</TableHead></TableRow></TableHeader>
        <TableBody>
          {rows.map((row) => <TableRow key={row.key} tabIndex={0} className="cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring" onClick={() => onSelect(row.key)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(row.key); } }}><TableCell><button type="button" className="text-left font-medium hover:underline" onClick={(event) => { event.stopPropagation(); onSelect(`vnr:${row.vnr?.name ?? ""}`); }}>{row.vnr?.name ?? "Unassigned"}</button><div className="font-mono text-[0.625rem] text-muted-foreground">{row.vnr?.cidr ?? "No VNR"}</div></TableCell><TableCell>{row.node === null ? <span className="text-muted-foreground">No Nodes</span> : <button type="button" className="text-left font-medium hover:underline" onClick={(event) => { event.stopPropagation(); onSelect(`node:${row.node!.id}`); }}>{row.node.name}<span className="block font-mono text-[0.625rem] font-normal text-muted-foreground">{row.node.address}</span></button>}</TableCell><TableCell>{row.runtime === null ? <Badge tone="neutral">Not observed</Badge> : <div className="flex items-center gap-2"><Badge tone={livenessTone(row.runtime.liveness)}>{row.runtime.liveness}</Badge><span className="text-xs text-muted-foreground">{row.runtime.sessionState}</span></div>}</TableCell><TableCell>{row.route === null ? <span className="text-muted-foreground">No routes</span> : <button type="button" className="font-mono text-xs hover:underline" onClick={(event) => { event.stopPropagation(); onSelect(`route:${row.route!.id}`); }}>{row.route.prefix}</button>}</TableCell><TableCell className="text-xs text-muted-foreground">Master → {row.vnr?.name ?? "unassigned"}{row.node === null ? "" : ` → ${row.node.name}`}{row.route === null ? "" : ` → ${row.route.prefix}`}</TableCell></TableRow>)}
          {rows.length === 0 ? <TableRow><TableCell colSpan={5} className="h-24 text-center text-muted-foreground">No topology relationships match the current filters.</TableCell></TableRow> : null}
        </TableBody>
      </Table>
    </section>
  );
}

export function TopologyWorkspace({ initialTopology }: TopologyWorkspaceProps) {
  const polling = usePolledResource<Topology>("/api/v1/topology", 10_000, initialTopology);
  const source = polling.data ?? initialTopology;
  const [query, setQuery] = useState("");
  const [vnrFilter, setVnrFilter] = useState("all");
  const [livenessFilter, setLivenessFilter] = useState("all");
  const [selectedKey, setSelectedKey] = useState("master");
  const filtered = useMemo(() => filterTopology(source, query, vnrFilter, livenessFilter), [livenessFilter, query, source, vnrFilter]);

  return (
    <div className="space-y-5 p-5">
      <div className="flex items-start justify-between gap-5">
        <div><p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.1em] text-primary">Read model</p><h2 className="mt-1 text-xl font-semibold tracking-tight">Topology</h2><p className="mt-1 text-sm text-muted-foreground">Deterministic Master, VNR, Node, and route relationships. Read-only by design.</p></div>
        <div className="flex items-center gap-2"><Badge tone={polling.freshness === "fresh" ? "healthy" : "warning"}>{polling.freshness === "fresh" ? "Fresh" : "Last-known-good"}</Badge><span className="font-mono text-[0.6875rem] text-muted-foreground">gen:{source.generation}</span><Button variant="ghost" size="icon" aria-label="Refresh topology" onClick={polling.refresh}><RefreshCw aria-hidden="true" className={polling.phase === "polling" ? "animate-spin" : undefined} /></Button></div>
      </div>

      <section className="border border-border bg-card" aria-labelledby="topology-view-title">
        <header className="flex min-h-12 items-center justify-between gap-4 border-b border-border px-3"><div><h3 id="topology-view-title" className="text-sm font-semibold">Relationship view</h3><p className="text-[0.6875rem] text-muted-foreground">Observed {formatUtc(source.observedAt)}</p></div><span className="text-xs text-muted-foreground">Pan by dragging empty space. Zoom with the wheel or controls.</span></header>
        <div className="grid grid-cols-[minmax(0,1fr)_17rem]">
          <div className="min-w-0">
            <div className="flex items-center gap-3 border-b border-border p-3">
              <div className="relative min-w-64 flex-1"><Search aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" /><Input aria-label="Filter topology" value={query} onChange={(event) => setQuery(event.target.value)} className="pl-9" placeholder="Filter VNR, Node, address, ID, or route" /></div>
              <Select value={vnrFilter} onValueChange={setVnrFilter}><SelectTrigger aria-label="Filter topology by VNR" className="w-48"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All VNRs</SelectItem>{source.vnrs.map((vnr) => <SelectItem key={vnr.name} value={vnr.name}>{vnr.name}</SelectItem>)}</SelectContent></Select>
              <Select value={livenessFilter} onValueChange={setLivenessFilter}><SelectTrigger aria-label="Filter topology by liveness" className="w-44"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All liveness</SelectItem>{(["online", "suspect", "offline", "unknown"] as const satisfies readonly Liveness[]).map((state) => <SelectItem key={state} value={state}>{state}</SelectItem>)}</SelectContent></Select>
            </div>
            <TopologyMap topology={filtered} selectedKey={selectedKey} onSelect={setSelectedKey} />
          </div>
          <Inspector topology={source} selectedKey={selectedKey} />
        </div>
      </section>

      <TopologyTable topology={filtered} onSelect={setSelectedKey} />
    </div>
  );
}
