"use client";

import type { components } from "@ntip/contracts";
import {
  Alert,
  AlertDescription,
  Badge,
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  Input,
  Label,
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
} from "@ntip/ui";
import { AlertCircle, ArrowRight, Plus, RefreshCw, Search, Server } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState, type FormEvent } from "react";
import { useAuth } from "@/components/auth-context";
import { createMutationAttempt } from "@/lib/behavior/mutation";
import { fetchJson, responseError } from "@/components/nodes/browser-api";
import {
  enrollmentTone,
  formatUtc,
  livenessTone,
  readableState,
  shortId,
} from "@/components/nodes/node-presenters";
import { useOperationalPolling, type OperationalPolling } from "@/components/nodes/use-operational-polling";

type Node = components["schemas"]["Node"];
type NodeCreate = components["schemas"]["NodeCreate"];
type NodePage = components["schemas"]["NodePage"];
type NodeRuntime = components["schemas"]["NodeRuntime"];
type NodeRuntimePage = components["schemas"]["NodeRuntimePage"];
type Vnr = components["schemas"]["Vnr"];

type NodesWorkspaceProps = Readonly<{
  initialNodes: NodePage;
  initialRuntime: NodeRuntimePage;
  vnrs: readonly Vnr[];
}>;

function latestRuntime(items: readonly NodeRuntime[]): ReadonlyMap<string, NodeRuntime> {
  const byNode = new Map<string, NodeRuntime>();
  for (const runtime of items) {
    const current = byNode.get(runtime.nodeId);
    if (current === undefined || current.observedAt < runtime.observedAt) byNode.set(runtime.nodeId, runtime);
  }
  return byNode;
}

async function fetchRuntimeRegister(signal: AbortSignal): Promise<NodeRuntimePage> {
  const items: NodeRuntime[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | null = null;
  let observedAt = new Date(0).toISOString();
  do {
    const suffix: string = cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`;
    const page = await fetchJson<NodeRuntimePage>(`/api/v1/runtime/nodes?limit=200${suffix}`, signal);
    items.push(...page.items);
    observedAt = page.observedAt;
    cursor = page.nextCursor;
    if (cursor !== null) {
      if (seenCursors.has(cursor)) throw new Error("The runtime cursor did not advance");
      seenCursors.add(cursor);
    }
  } while (cursor !== null);
  return { items, nextCursor: null, observedAt };
}

function PollingStatus({ runtime }: Readonly<{ runtime: OperationalPolling<NodeRuntimePage> }>) {
  const stale = runtime.freshness !== "fresh";
  const detail = runtime.pauseReason === "hidden"
    ? "Polling paused while this tab is hidden"
    : runtime.pauseReason === "offline"
      ? "Polling paused while the browser is offline"
      : runtime.error;
  return (
    <div className="flex items-center gap-2">
      <Badge tone={stale ? "warning" : "healthy"}>{stale ? "Runtime stale" : "Runtime fresh"}</Badge>
      {detail === null ? null : <span className="max-w-72 truncate text-xs text-muted-foreground" title={detail}>{detail}</span>}
      <Button type="button" variant="ghost" size="icon" aria-label="Refresh Node runtime" onClick={runtime.refresh}>
        <RefreshCw aria-hidden="true" className={runtime.phase === "polling" ? "animate-spin" : undefined} />
      </Button>
    </div>
  );
}

function CreateNodeDialog({ vnrs }: Readonly<{ vnrs: readonly Vnr[] }>) {
  const { auth, can } = useAuth();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [vnrName, setVnrName] = useState(vnrs[0]?.name ?? "");

  if (!can("inventory:write")) return null;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    const data = new FormData(event.currentTarget);
    const body: NodeCreate = {
      name: String(data.get("name") ?? "").trim(),
      address: String(data.get("address") ?? "").trim(),
      vnrName,
    };
    try {
      const attempt = createMutationAttempt({
        method: "POST",
        url: "/api/v1/nodes",
        csrfToken: auth.csrfToken,
        body,
      });
      const response = await fetch(attempt.buildRequest());
      if (!response.ok) throw await responseError(response);
      const node = (await response.json()) as Node;
      setOpen(false);
      router.push(`/nodes/${node.id}`);
      router.refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Node creation failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => { setOpen(next); if (!next) setError(null); }}>
      <DialogTrigger asChild>
        <Button disabled={vnrs.length === 0}><Plus aria-hidden="true" />Add Node</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create Node</DialogTitle>
          <DialogDescription>Create the inventory record first. Enrollment credentials are issued separately.</DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          {error === null ? null : (
            <Alert tone="critical"><AlertCircle aria-hidden="true" /><AlertDescription>{error}</AlertDescription></Alert>
          )}
          <div className="grid gap-1.5">
            <Label htmlFor="node-name">Name</Label>
            <Input id="node-name" name="name" required maxLength={63} autoComplete="off" placeholder="edge-berlin-01" />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="node-address">Address</Label>
            <Input id="node-address" name="address" required inputMode="decimal" autoComplete="off" placeholder="10.42.0.2" />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="node-vnr">VNR</Label>
            <Select value={vnrName} onValueChange={setVnrName} required>
              <SelectTrigger id="node-vnr"><SelectValue placeholder="Select a VNR" /></SelectTrigger>
              <SelectContent>
                {vnrs.map((vnr) => <SelectItem key={vnr.name} value={vnr.name}>{vnr.name} · {vnr.cidr}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
            <Button type="submit" disabled={pending || vnrName.length === 0}>{pending ? "Creating" : "Create Node"}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function NodesWorkspace({ initialNodes, initialRuntime, vnrs }: NodesWorkspaceProps) {
  const [nodes, setNodes] = useState<readonly Node[]>(initialNodes.items);
  const [nextCursor, setNextCursor] = useState<string | null>(initialNodes.nextCursor);
  const [loadingMore, setLoadingMore] = useState(false);
  const [pageError, setPageError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [enrollmentFilter, setEnrollmentFilter] = useState("all");
  const runtime = useOperationalPolling(initialRuntime, fetchRuntimeRegister, 10_000);
  const runtimeByNode = useMemo(() => latestRuntime(runtime.data?.items ?? []), [runtime.data]);
  const visibleNodes = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return nodes.filter((node) => {
      if (enrollmentFilter !== "all" && node.enrollmentState !== enrollmentFilter) return false;
      return normalized.length === 0 || [node.name, node.address, node.vnrName, node.id].some((value) => value.toLowerCase().includes(normalized));
    });
  }, [enrollmentFilter, nodes, query]);

  async function loadMore() {
    if (nextCursor === null || loadingMore) return;
    setLoadingMore(true);
    setPageError(null);
    try {
      const page = await fetchJson<NodePage>(`/api/v1/nodes?limit=50&cursor=${encodeURIComponent(nextCursor)}`);
      setNodes((current) => {
        const seen = new Set(current.map((node) => node.id));
        return [...current, ...page.items.filter((node) => !seen.has(node.id))];
      });
      setNextCursor(page.nextCursor);
    } catch (reason) {
      setPageError(reason instanceof Error ? reason.message : "Could not load more Nodes");
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <div className="space-y-5 p-5">
      <div className="flex items-start justify-between gap-5">
        <div>
          <p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.1em] text-primary">Inventory</p>
          <h2 className="mt-1 text-xl font-semibold tracking-tight">Nodes</h2>
          <p className="mt-1 text-sm text-muted-foreground">Configured identities joined with current authenticated runtime observations.</p>
        </div>
        <CreateNodeDialog vnrs={vnrs} />
      </div>

      <section className="border border-border bg-card" aria-labelledby="node-inventory-title">
        <header className="flex min-h-12 items-center justify-between gap-4 border-b border-border px-3">
          <div className="flex items-center gap-2">
            <Server aria-hidden="true" className="size-4 text-primary" />
            <h3 id="node-inventory-title" className="text-sm font-semibold">Node register</h3>
            <span className="font-mono text-[0.6875rem] text-muted-foreground">{visibleNodes.length} shown</span>
          </div>
          <PollingStatus runtime={runtime} />
        </header>
        <div className="flex items-center gap-3 border-b border-border p-3">
          <div className="relative max-w-sm flex-1">
            <Search aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input aria-label="Filter Nodes" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter name, address, VNR, or ID" className="pl-9" />
          </div>
          <Select value={enrollmentFilter} onValueChange={setEnrollmentFilter}>
            <SelectTrigger aria-label="Filter enrollment state" className="w-48"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All enrollment states</SelectItem>
              <SelectItem value="enrolled">Enrolled</SelectItem>
              <SelectItem value="credential_issued">Credential issued</SelectItem>
              <SelectItem value="unenrolled">Unenrolled</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {pageError === null ? null : (
          <Alert tone="critical" className="m-3"><AlertCircle aria-hidden="true" /><AlertDescription>{pageError}</AlertDescription></Alert>
        )}

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Node</TableHead>
              <TableHead>Address</TableHead>
              <TableHead>VNR</TableHead>
              <TableHead>Enrollment</TableHead>
              <TableHead>Runtime</TableHead>
              <TableHead>Observed endpoint</TableHead>
              <TableHead className="w-12"><span className="sr-only">Open</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {visibleNodes.map((node) => {
              const observation = runtimeByNode.get(node.id);
              return (
                <TableRow key={node.id}>
                  <TableCell>
                    <Link href={`/nodes/${node.id}`} className="font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">{node.name}</Link>
                    <div className="font-mono text-[0.625rem] text-muted-foreground" title={node.id}>{shortId(node.id)}</div>
                  </TableCell>
                  <TableCell className="font-mono text-xs tabular-nums">{node.address}</TableCell>
                  <TableCell>{node.vnrName}</TableCell>
                  <TableCell><Badge tone={enrollmentTone(node.enrollmentState)}>{readableState(node.enrollmentState)}</Badge></TableCell>
                  <TableCell>
                    {observation === undefined ? <Badge tone="neutral">Not observed</Badge> : (
                      <div className="flex items-center gap-2">
                        <Badge tone={livenessTone(observation.liveness)}>{observation.liveness}</Badge>
                        <span className="text-xs text-muted-foreground">{observation.sessionState}</span>
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="max-w-56 truncate font-mono text-xs" title={observation?.observedEndpoint ?? undefined}>
                    {observation?.observedEndpoint ?? "Not observed"}
                    {observation === undefined ? null : <div className="font-sans text-[0.625rem] text-muted-foreground">{formatUtc(observation.observedAt)}</div>}
                  </TableCell>
                  <TableCell><Button asChild variant="ghost" size="icon"><Link href={`/nodes/${node.id}`} aria-label={`Open ${node.name}`}><ArrowRight aria-hidden="true" /></Link></Button></TableCell>
                </TableRow>
              );
            })}
            {visibleNodes.length === 0 ? (
              <TableRow><TableCell colSpan={7} className="h-24 text-center text-muted-foreground">No Nodes match the current filters.</TableCell></TableRow>
            ) : null}
          </TableBody>
        </Table>
        <footer className="flex min-h-12 items-center justify-between border-t border-border px-3">
          <span className="text-xs text-muted-foreground">Runtime observations refresh every 10 seconds.</span>
          {nextCursor === null ? <span className="text-xs text-muted-foreground">End of register</span> : (
            <Button type="button" variant="outline" size="sm" disabled={loadingMore} onClick={() => void loadMore()}>{loadingMore ? "Loading" : "Load more"}</Button>
          )}
        </footer>
      </section>
    </div>
  );
}
