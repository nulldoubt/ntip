"use client";

import type { components } from "@ntip/contracts";
import {
  Alert,
  AlertDescription,
  AlertTitle,
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@ntip/ui";
import {
  AlertTriangle,
  ArrowRight,
  CircleAlert,
  Network,
  Plus,
  RefreshCw,
  Server,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useAuth } from "@/components/auth-context";
import {
  fieldError,
  InlineFieldError,
  InventoryErrorSummary,
  inventoryFormErrorState,
  type InventoryFormErrorState,
} from "@/components/network/inventory-form-errors";
import { SegmentedCidrSelect } from "@/components/network/segmented-network-input";
import { actionableError, getJson, readJson } from "@/components/vnrs/client-api";
import type { Topology, Vnr, VnrListData, VnrPage } from "@/components/vnrs/vnr-types";
import { createMutationAttempt } from "@/lib/behavior/mutation";
import { createEmptyCidrSelection, type SegmentedCidrSelection } from "@/lib/network/segmented-network";
import { usePolledResource } from "@/lib/use-polled-resource";

type VnrCreate = components["schemas"]["VnrCreate"];
type LivenessState = components["schemas"]["LivenessState"];

const namePattern = "[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}";
function formatUtc(timestamp: string): string {
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) return "Invalid time";
  return `${new Intl.DateTimeFormat("en", {
    timeZone: "UTC",
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).format(parsed)} UTC`;
}

function livenessTone(liveness: LivenessState): "healthy" | "warning" | "critical" | "neutral" {
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

function VnrLiveness({ topology, vnrName }: Readonly<{ topology: Topology | null; vnrName: string }>) {
  if (topology === null) return <Badge tone="neutral">Unavailable</Badge>;
  const nodes = topology.nodes.filter((node) => node.vnrName === vnrName);
  if (nodes.length === 0) return <Badge tone="neutral">No Nodes</Badge>;

  const runtimeByNode = new Map(topology.runtime.map((runtime) => [runtime.nodeId, runtime]));
  const counts: Record<LivenessState, number> = { online: 0, suspect: 0, offline: 0, unknown: 0 };
  for (const node of nodes) counts[runtimeByNode.get(node.id)?.liveness ?? "unknown"] += 1;

  const dominant: LivenessState = counts.offline > 0
    ? "offline"
    : counts.suspect > 0
      ? "suspect"
      : counts.unknown > 0
        ? "unknown"
        : "online";
  return (
    <Badge tone={livenessTone(dominant)}>
      {counts.online} / {nodes.length} online
    </Badge>
  );
}

function CreateVnrDialog() {
  const { auth } = useAuth();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [cidr, setCidr] = useState<SegmentedCidrSelection>(() => createEmptyCidrSelection("vnr"));
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<InventoryFormErrorState | null>(null);
  const errorSummaryRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (error !== null) errorSummaryRef.current?.focus();
  }, [error]);

  function reset() {
    setName("");
    setCidr(createEmptyCidrSelection("vnr"));
    setPending(false);
    setError(null);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (cidr.value === null) return;
    setPending(true);
    setError(null);
    const body: VnrCreate = { name: name.trim(), cidr: cidr.value };

    try {
      const attempt = createMutationAttempt({
        body,
        csrfToken: auth.csrfToken,
        method: "POST",
        url: new URL("/api/v1/vnrs", window.location.origin),
      });
      const created = await readJson<Vnr>(await fetch(attempt.buildRequest()));
      setOpen(false);
      reset();
      router.push(`/vnrs/${encodeURIComponent(created.name)}`);
      router.refresh();
    } catch (reason) {
      setError(inventoryFormErrorState(reason, "VNR"));
      setPending(false);
    }
  }

  const nameViolation = fieldError(error, "name");
  const cidrViolation = fieldError(error, "cidr");

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (pending) return;
        setOpen(nextOpen);
        if (!nextOpen) reset();
      }}
    >
      <DialogTrigger asChild>
        <Button type="button">
          <Plus aria-hidden="true" /> Create VNR
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create virtual network range</DialogTitle>
          <DialogDescription>
            The name is permanent. The CIDR can be changed later if inventory invariants remain valid.
          </DialogDescription>
        </DialogHeader>
        <form className="grid gap-5" onSubmit={(event) => void submit(event)}>
          <div className="grid gap-1.5">
            <Label htmlFor="create-vnr-name">Name</Label>
            <Input
              id="create-vnr-name"
              name="name"
              autoComplete="off"
              autoFocus
              maxLength={63}
              pattern={namePattern}
              placeholder="berlin-edge"
              required
              value={name}
              disabled={pending}
              onChange={(event) => setName(event.target.value)}
              aria-invalid={nameViolation !== null || undefined}
              aria-describedby={`create-vnr-name-help${nameViolation === null ? "" : " create-vnr-name-error"}`}
            />
            <p id="create-vnr-name-help" className="text-xs text-muted-foreground">
              1–63 letters, numbers, underscores, periods, or hyphens.
            </p>
            <InlineFieldError id="create-vnr-name-error" violation={nameViolation} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="create-vnr-cidr">IPv4 CIDR</Label>
            <SegmentedCidrSelect
              id="create-vnr-cidr"
              ariaLabel="VNR IPv4 CIDR"
              ariaDescribedBy={`create-vnr-cidr-help${cidrViolation === null ? "" : " create-vnr-cidr-error"}`}
              invalid={cidrViolation !== null}
              disabled={pending}
              required
              selection={cidr}
              onSelectionChange={setCidr}
            />
            <p id="create-vnr-cidr-help" className="text-xs text-muted-foreground">
              Select four octets and a /1–/30 prefix. New VNRs default to /24.
            </p>
            <InlineFieldError id="create-vnr-cidr-error" violation={cidrViolation} />
          </div>
          <InventoryErrorSummary ref={errorSummaryRef} error={error} title="VNR was not created" />
          <p className="sr-only" aria-live="polite">{pending ? "Creating VNR" : ""}</p>
          <DialogFooter>
            <Button type="button" variant="ghost" disabled={pending} onClick={() => { setOpen(false); reset(); }}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending || cidr.value === null}>
              {pending ? <RefreshCw aria-hidden="true" className="animate-spin" /> : <Plus aria-hidden="true" />}
              {pending ? "Creating" : "Create VNR"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function deduplicateVnrs(items: readonly Vnr[]): readonly Vnr[] {
  const byName = new Map<string, Vnr>();
  for (const item of items) byName.set(item.name, item);
  return [...byName.values()];
}

export function VnrListClient({ initialData }: Readonly<{ initialData: VnrListData }>) {
  const { can } = useAuth();
  const pagePolling = usePolledResource("/api/v1/vnrs?limit=50", 30_000, initialData.page);
  const topologyPolling = usePolledResource<Topology | null>("/api/v1/topology", 30_000, initialData.topology);
  const current: VnrListData = {
    page: pagePolling.data ?? initialData.page,
    topology: topologyPolling.data,
    topologyError: topologyPolling.data === null
      ? (topologyPolling.error ?? initialData.topologyError)
      : null,
  };
  const [expansion, setExpansion] = useState<Readonly<{
    baseLastSuccessAt: number | null;
    items: readonly Vnr[];
    nextCursor: string | null;
  }> | null>(null);
  const [loadPending, setLoadPending] = useState(false);
  const [loadFailure, setLoadFailure] = useState<Readonly<{
    baseLastSuccessAt: number | null;
    message: string;
  }> | null>(null);
  const currentExpansion = expansion?.baseLastSuccessAt === pagePolling.lastSuccessAt ? expansion : null;
  const nextCursor = currentExpansion?.nextCursor ?? current.page.nextCursor;
  const loadError = loadFailure?.baseLastSuccessAt === pagePolling.lastSuccessAt ? loadFailure.message : null;

  const rows = useMemo(
    () => deduplicateVnrs([...current.page.items, ...(currentExpansion?.items ?? [])]),
    [current.page.items, currentExpansion?.items],
  );

  async function loadMore() {
    if (nextCursor === null || loadPending) return;
    setLoadPending(true);
    setLoadFailure(null);
    const query = new URLSearchParams({ cursor: nextCursor, limit: "50" });
    try {
      const nextPage = (await getJson<VnrPage>(`/api/v1/vnrs?${query.toString()}`)).data;
      setExpansion((previous) => {
        const previousItems = previous?.baseLastSuccessAt === pagePolling.lastSuccessAt ? previous.items : [];
        return {
          baseLastSuccessAt: pagePolling.lastSuccessAt,
          items: deduplicateVnrs([...previousItems, ...nextPage.items]),
          nextCursor: nextPage.nextCursor,
        };
      });
    } catch (error) {
      setLoadFailure({
        baseLastSuccessAt: pagePolling.lastSuccessAt,
        message: actionableError(error),
      });
    } finally {
      setLoadPending(false);
    }
  }

  return (
    <div className="mx-auto w-full max-w-[94rem] space-y-5 p-5">
      <header className="flex items-end justify-between gap-6 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Network aria-hidden="true" className="size-4 text-primary" />
            <p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.085em] text-muted-foreground">
              Inventory
            </p>
          </div>
          <h2 className="mt-2 text-xl font-semibold tracking-tight">Virtual network ranges</h2>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Address domains owned by the Master. Names stay immutable after creation.
          </p>
        </div>
        {can("inventory:write") ? <CreateVnrDialog /> : null}
      </header>

      {pagePolling.error !== null ? (
        <Alert tone="warning">
          <AlertTriangle aria-hidden="true" />
          <AlertTitle>Live refresh failed</AlertTitle>
          <AlertDescription>
            The table retains the last known values. {pagePolling.error}
          </AlertDescription>
        </Alert>
      ) : null}
      {current.topologyError !== null ? (
        <Alert tone="info">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>Node health context is unavailable</AlertTitle>
          <AlertDescription>{current.topologyError} VNR inventory remains current.</AlertDescription>
        </Alert>
      ) : null}

      <section className="border border-border bg-card" aria-labelledby="vnr-table-title">
        <header className="flex min-h-11 items-center justify-between gap-4 border-b border-border px-3">
          <div className="flex items-center gap-2">
            <h3 id="vnr-table-title" className="text-sm font-semibold">Configured VNRs</h3>
            <Badge tone={pagePolling.error === null ? "neutral" : "warning"}>
              {pagePolling.error === null ? `${rows.length} loaded` : `${rows.length} retained`}
            </Badge>
          </div>
          <span className="font-mono text-[0.6875rem] text-muted-foreground">
            {pagePolling.phase === "polling" || topologyPolling.phase === "polling" ? "refreshing" : "30s refresh"}
          </span>
        </header>

        {rows.length === 0 ? (
          <div className="grid min-h-52 place-items-center px-6 py-12 text-center">
            <div>
              <Network aria-hidden="true" className="mx-auto size-6 text-muted-foreground" strokeWidth={1.5} />
              <p className="mt-3 text-sm font-semibold">No VNRs configured</p>
              <p className="mt-1 text-xs text-muted-foreground">
                {can("inventory:write") ? "Create the first virtual network range to begin inventory setup." : "An operator can create the first virtual network range."}
              </p>
            </div>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Name</TableHead>
                <TableHead>Network</TableHead>
                <TableHead>Master address</TableHead>
                <TableHead>Nodes</TableHead>
                <TableHead>Liveness</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead><span className="sr-only">Open VNR</span></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((vnr) => {
                const nodeCount = current.topology?.nodes.filter((node) => node.vnrName === vnr.name).length;
                return (
                  <TableRow key={vnr.name}>
                    <TableCell>
                      <Link
                        href={`/vnrs/${encodeURIComponent(vnr.name)}`}
                        className="font-semibold hover:text-primary-strong hover:underline"
                      >
                        {vnr.name}
                      </Link>
                      {vnr.publicRangeWarning ? (
                        <Badge tone="warning" className="ms-2">Public range</Badge>
                      ) : null}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{vnr.cidr}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{vnr.masterAddress}</TableCell>
                    <TableCell>
                      {nodeCount === undefined ? (
                        <span className="text-xs text-muted-foreground">Unavailable</span>
                      ) : (
                        <Link
                          href={`/nodes?vnrName=${encodeURIComponent(vnr.name)}`}
                          className="inline-flex items-center gap-1.5 text-xs font-medium hover:text-primary-strong hover:underline"
                        >
                          <Server aria-hidden="true" className="size-3.5 text-muted-foreground" />
                          {nodeCount}
                        </Link>
                      )}
                    </TableCell>
                    <TableCell><VnrLiveness topology={current.topology} vnrName={vnr.name} /></TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{formatUtc(vnr.updatedAt)}</TableCell>
                    <TableCell className="text-right">
                      <Button asChild size="icon" variant="ghost">
                        <Link href={`/vnrs/${encodeURIComponent(vnr.name)}`} aria-label={`Open ${vnr.name}`}>
                          <ArrowRight aria-hidden="true" />
                        </Link>
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}

        <footer className="flex min-h-12 items-center justify-between gap-4 border-t border-border px-3">
          <p className="text-xs text-muted-foreground">
            {nextCursor === null ? "End of available results." : "More results are available."}
          </p>
          {nextCursor !== null ? (
            <Button type="button" size="sm" variant="outline" disabled={loadPending} onClick={() => void loadMore()}>
              {loadPending ? <RefreshCw aria-hidden="true" className="animate-spin" /> : null}
              {loadPending ? "Loading" : "Load more"}
            </Button>
          ) : null}
        </footer>
      </section>

      {loadError !== null ? (
        <Alert tone="warning">
          <AlertTriangle aria-hidden="true" />
          <AlertTitle>More results could not be loaded</AlertTitle>
          <AlertDescription>{loadError} Already loaded rows remain visible.</AlertDescription>
        </Alert>
      ) : null}
      <p className="sr-only" aria-live="polite">
        {loadPending ? "Loading more VNRs" : loadError ?? `${rows.length} VNRs loaded`}
      </p>
    </div>
  );
}
