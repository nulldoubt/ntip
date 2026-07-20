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
  ArrowLeft,
  CircleAlert,
  Clock3,
  KeyRound,
  Network,
  Pencil,
  RefreshCw,
  Route,
  Server,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState, type FormEvent } from "react";
import { useAuth } from "@/components/auth-context";
import { actionableError, ClientApiError, getJson, readJson, requireOk } from "@/components/vnrs/client-api";
import { usePolling } from "@/components/vnrs/use-polling";
import type { EntityTag, NodeRuntime, Topology, Vnr, VnrDetailData } from "@/components/vnrs/vnr-types";
import { createMutationAttempt } from "@/lib/behavior/mutation";

type VnrUpdate = components["schemas"]["VnrUpdate"];
type ReauthenticationStatus = components["schemas"]["ReauthenticationStatus"];
type LivenessState = components["schemas"]["LivenessState"];
type RuntimeSessionState = components["schemas"]["RuntimeSessionState"];

const cidrPattern = "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/(?:[0-9]|[12][0-9]|3[0-2])";

function detailPath(name: string): `/api/v1/${string}` {
  return `/api/v1/vnrs/${encodeURIComponent(name)}`;
}

async function fetchVnrDetail(name: string, signal: AbortSignal): Promise<VnrDetailData> {
  const detail = await getJson<Vnr>(detailPath(name), signal);
  const topology = (await getJson<Topology>("/api/v1/topology", signal)).data;
  return { vnr: detail.data, etag: detail.etag, topology, topologyError: null };
}

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
    second: "2-digit",
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

function sessionTone(sessionState: RuntimeSessionState): "healthy" | "warning" | "neutral" | "info" {
  switch (sessionState) {
    case "established":
      return "healthy";
    case "enrolling":
    case "connecting":
      return "info";
    case "disconnected":
      return "neutral";
  }
}

function UpdateVnrDialog({
  etag,
  onUpdated,
  refresh,
  vnr,
}: Readonly<{
  etag: EntityTag | null;
  onUpdated: (data: VnrDetailData) => void;
  refresh: () => void;
  vnr: Vnr;
}>) {
  const { auth } = useAuth();
  const [open, setOpen] = useState(false);
  const [cidr, setCidr] = useState(vnr.cidr);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [violations, setViolations] = useState<readonly components["schemas"]["FieldViolation"][]>([]);

  function reset() {
    setCidr(vnr.cidr);
    setPending(false);
    setError(null);
    setViolations([]);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (etag === null) {
      setError("A current resource version is unavailable. Refresh the page and try again.");
      return;
    }

    setPending(true);
    setError(null);
    setViolations([]);
    const body: VnrUpdate = { cidr: cidr.trim() };
    try {
      const attempt = createMutationAttempt({
        body,
        csrfToken: auth.csrfToken,
        ifMatch: etag,
        method: "PATCH",
        requiresIfMatch: true,
        url: new URL(detailPath(vnr.name), window.location.origin),
      });
      const response = await fetch(attempt.buildRequest());
      const updated = await readJson<Vnr>(response);
      onUpdated({
        vnr: updated,
        etag: response.headers.get("etag"),
        topology: null,
        topologyError: "Refreshing Node context after the CIDR change.",
      });
      setOpen(false);
      reset();
      refresh();
    } catch (reason) {
      setError(actionableError(reason));
      setViolations(reason instanceof ClientApiError ? reason.violations : []);
      setPending(false);
      if (reason instanceof ClientApiError && (reason.status === 412 || reason.status === 428)) refresh();
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (pending) return;
        setOpen(nextOpen);
        if (nextOpen) setCidr(vnr.cidr);
        else reset();
      }}
    >
      <DialogTrigger asChild>
        <Button type="button" variant="outline" disabled={etag === null}>
          <Pencil aria-hidden="true" /> Change CIDR
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Change {vnr.name} CIDR</DialogTitle>
          <DialogDescription>
            A validated CIDR change retires affected active associations and publishes one durable generation. The VNR name remains unchanged.
          </DialogDescription>
        </DialogHeader>
        <form className="grid gap-5" onSubmit={(event) => void submit(event)}>
          <div className="grid gap-1.5">
            <Label htmlFor="update-vnr-cidr">IPv4 CIDR</Label>
            <Input
              id="update-vnr-cidr"
              className="font-mono"
              autoComplete="off"
              autoFocus
              inputMode="decimal"
              pattern={cidrPattern}
              required
              value={cidr}
              onChange={(event) => setCidr(event.target.value)}
              aria-describedby="update-vnr-cidr-help"
            />
            <p id="update-vnr-cidr-help" className="text-xs text-muted-foreground">
              Existing Node addresses and routes must remain valid and non-overlapping.
            </p>
          </div>
          {error !== null ? (
            <Alert tone="critical">
              <CircleAlert aria-hidden="true" />
              <AlertTitle>VNR was not updated</AlertTitle>
              <AlertDescription>
                <p>{error}</p>
                {violations.length > 0 ? (
                  <ul className="mt-2 list-disc space-y-1 ps-4">
                    {violations.map((violation) => (
                      <li key={`${violation.field}:${violation.code}`}>{violation.field}: {violation.message}</li>
                    ))}
                  </ul>
                ) : null}
              </AlertDescription>
            </Alert>
          ) : null}
          <p className="sr-only" aria-live="polite">{pending ? "Updating VNR" : ""}</p>
          <DialogFooter>
            <Button type="button" variant="ghost" disabled={pending} onClick={() => setOpen(false)}>Cancel</Button>
            <Button type="submit" disabled={pending || cidr.trim() === vnr.cidr}>
              {pending ? <RefreshCw aria-hidden="true" className="animate-spin" /> : <Pencil aria-hidden="true" />}
              {pending ? "Updating" : "Apply CIDR"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

type DeletePhase = "idle" | "reauthenticating" | "refreshing" | "deleting";

function DeleteVnrDialog({ nodeCount, vnr }: Readonly<{ nodeCount: number | null; vnr: Vnr }>) {
  const { auth } = useAuth();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [phase, setPhase] = useState<DeletePhase>("idle");
  const [error, setError] = useState<string | null>(null);

  const pending = phase !== "idle";
  const phaseLabel = phase === "reauthenticating"
    ? "Confirming password"
    : phase === "refreshing"
      ? "Reading the current VNR version"
      : phase === "deleting"
        ? "Deleting VNR"
        : "";

  function reset() {
    setPassword("");
    setConfirmation("");
    setPhase("idle");
    setError(null);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (confirmation !== vnr.name) {
      setError(`Type ${vnr.name} exactly to confirm deletion.`);
      return;
    }

    setError(null);
    try {
      setPhase("reauthenticating");
      const reauthAttempt = createMutationAttempt({
        body: { password },
        csrfToken: auth.csrfToken,
        method: "POST",
        url: new URL("/api/v1/auth/reauth", window.location.origin),
      });
      await readJson<ReauthenticationStatus>(await fetch(reauthAttempt.buildRequest()));

      setPhase("refreshing");
      const fresh = await getJson<Vnr>(detailPath(vnr.name));
      if (fresh.etag === null) {
        throw new ClientApiError(
          428,
          "precondition_required",
          "The API did not provide a current resource version.",
          null,
        );
      }

      setPhase("deleting");
      const deleteAttempt = createMutationAttempt({
        body: { confirmation: vnr.name },
        csrfToken: auth.csrfToken,
        ifMatch: fresh.etag,
        method: "DELETE",
        requiresIfMatch: true,
        responseKind: "empty",
        url: new URL(detailPath(vnr.name), window.location.origin),
      });
      await requireOk(await fetch(deleteAttempt.buildRequest()));
      reset();
      setOpen(false);
      router.replace("/vnrs");
      router.refresh();
    } catch (reason) {
      setPassword("");
      setError(actionableError(reason));
      setPhase("idle");
    }
  }

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
        <Button type="button" variant="quietDanger">
          <Trash2 aria-hidden="true" /> Delete VNR
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete {vnr.name}</DialogTitle>
          <DialogDescription>
            This permanently removes the unused VNR. Confirm your password, then the dashboard rereads the VNR and uses its fresh resource version for deletion.
          </DialogDescription>
        </DialogHeader>
        <form className="grid gap-5" onSubmit={(event) => void submit(event)}>
          {nodeCount !== null && nodeCount > 0 ? (
            <Alert tone="warning">
              <ShieldAlert aria-hidden="true" />
              <AlertTitle>Inventory dependencies remain</AlertTitle>
              <AlertDescription>
                {nodeCount} {nodeCount === 1 ? "Node is" : "Nodes are"} currently assigned. The service will reject deletion until dependencies are removed or moved.
              </AlertDescription>
            </Alert>
          ) : null}
          <div className="grid gap-1.5">
            <Label htmlFor="delete-vnr-password">Current password</Label>
            <Input
              id="delete-vnr-password"
              type="password"
              autoComplete="current-password"
              autoFocus
              minLength={14}
              maxLength={256}
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              disabled={pending}
            />
            <p className="text-xs text-muted-foreground">Password confirmation authorizes dangerous operations for up to five minutes.</p>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="delete-vnr-confirmation">Type <span className="font-mono">{vnr.name}</span> to confirm</Label>
            <Input
              id="delete-vnr-confirmation"
              autoComplete="off"
              className="font-mono"
              required
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
              disabled={pending}
              aria-invalid={confirmation.length > 0 && confirmation !== vnr.name}
            />
          </div>
          {error !== null ? (
            <Alert tone="critical">
              <CircleAlert aria-hidden="true" />
              <AlertTitle>VNR was not deleted</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}
          <p className="text-xs text-muted-foreground">
            The typed name, current ETag, actor, and outcome are included in the immutable audit trail.
          </p>
          <p className="sr-only" aria-live="assertive">{phaseLabel}</p>
          <DialogFooter>
            <Button type="button" variant="ghost" disabled={pending} onClick={() => setOpen(false)}>Cancel</Button>
            <Button
              type="submit"
              variant="destructive"
              disabled={pending || password.length < 14 || confirmation !== vnr.name}
            >
              {pending ? <RefreshCw aria-hidden="true" className="animate-spin" /> : <Trash2 aria-hidden="true" />}
              {phaseLabel || "Delete permanently"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function NodeState({ runtime }: Readonly<{ runtime: NodeRuntime | undefined }>) {
  if (runtime === undefined) return <Badge tone="neutral">Unknown</Badge>;
  return <Badge tone={livenessTone(runtime.liveness)}>{runtime.liveness}</Badge>;
}

export function VnrDetailClient({ initialData }: Readonly<{ initialData: VnrDetailData }>) {
  const { can } = useAuth();
  const { refresh, snapshot } = usePolling(
    initialData,
    (signal) => fetchVnrDetail(initialData.vnr.name, signal),
    30_000,
  );
  const [override, setOverride] = useState<Readonly<{
    baselineLastSuccessAt: number | null;
    data: VnrDetailData;
  }> | null>(null);
  const currentOverride = override?.baselineLastSuccessAt === snapshot.lastSuccessAt ? override.data : null;
  const current = currentOverride ?? snapshot.data ?? initialData;

  const nodes = useMemo(
    () => current.topology?.nodes.filter((node) => node.vnrName === current.vnr.name) ?? [],
    [current.topology, current.vnr.name],
  );
  const runtimeByNode = useMemo(
    () => new Map(current.topology?.runtime.map((runtime) => [runtime.nodeId, runtime]) ?? []),
    [current.topology],
  );
  const routeCount = useMemo(() => {
    if (current.topology === null) return null;
    const nodeIds = new Set(nodes.map((node) => node.id));
    return current.topology.routes.filter((route) => nodeIds.has(route.nodeId)).length;
  }, [current.topology, nodes]);
  const onlineCount = nodes.filter((node) => runtimeByNode.get(node.id)?.liveness === "online").length;

  return (
    <div className="mx-auto w-full max-w-[94rem] space-y-5 p-5">
      <header className="border-b border-border pb-4">
        <Link href="/vnrs" className="inline-flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground hover:underline">
          <ArrowLeft aria-hidden="true" className="size-3.5" /> VNRs
        </Link>
        <div className="mt-3 flex items-end justify-between gap-6">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Network aria-hidden="true" className="size-4 text-primary" />
              <p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.085em] text-muted-foreground">Virtual network range</p>
            </div>
            <div className="mt-2 flex min-w-0 items-center gap-3">
              <h2 className="truncate text-xl font-semibold tracking-tight">{current.vnr.name}</h2>
              {current.vnr.publicRangeWarning ? <Badge tone="warning">Public range</Badge> : null}
            </div>
            <p className="mt-1 font-mono text-sm text-muted-foreground">{current.vnr.cidr}</p>
          </div>
          {can("inventory:write") ? (
            <UpdateVnrDialog
              etag={current.etag}
              onUpdated={(data) => setOverride({ baselineLastSuccessAt: snapshot.lastSuccessAt, data })}
              refresh={refresh}
              vnr={current.vnr}
            />
          ) : null}
        </div>
      </header>

      {snapshot.error !== null ? (
        <Alert tone="warning">
          <AlertTriangle aria-hidden="true" />
          <AlertTitle>Live refresh failed</AlertTitle>
          <AlertDescription>The page retains the last known values. {snapshot.error}</AlertDescription>
        </Alert>
      ) : null}
      {current.etag === null && can("inventory:write") ? (
        <Alert tone="critical">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>Resource version unavailable</AlertTitle>
          <AlertDescription>Changes are disabled because the API did not return the required ETag. Refresh after the service is healthy.</AlertDescription>
        </Alert>
      ) : null}
      {current.topologyError !== null ? (
        <Alert tone="info">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>Node context is not current</AlertTitle>
          <AlertDescription>{current.topologyError} VNR inventory values remain available.</AlertDescription>
        </Alert>
      ) : null}
      {current.vnr.publicRangeWarning ? (
        <Alert tone="warning">
          <AlertTriangle aria-hidden="true" />
          <AlertTitle>Public address range</AlertTitle>
          <AlertDescription>This VNR uses a publicly routable IPv4 range. Confirm that the overlap with external routing is intentional.</AlertDescription>
        </Alert>
      ) : null}

      <section className="grid grid-cols-4 divide-x divide-border border border-border bg-card" aria-label="VNR summary">
        <div className="p-4">
          <p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.075em] text-muted-foreground">Master address</p>
          <p className="mt-2 font-mono text-sm font-semibold">{current.vnr.masterAddress}</p>
        </div>
        <div className="p-4">
          <p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.075em] text-muted-foreground">Nodes</p>
          <p className="mt-2 font-mono text-sm font-semibold tabular-nums">{current.topology === null ? "Unavailable" : nodes.length}</p>
        </div>
        <div className="p-4">
          <p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.075em] text-muted-foreground">Online</p>
          <p className="mt-2 font-mono text-sm font-semibold tabular-nums">{current.topology === null ? "Unavailable" : `${onlineCount} / ${nodes.length}`}</p>
        </div>
        <div className="p-4">
          <p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.075em] text-muted-foreground">Owned routes</p>
          <p className="mt-2 font-mono text-sm font-semibold tabular-nums">{routeCount ?? "Unavailable"}</p>
        </div>
      </section>

      <div className="grid grid-cols-[minmax(0,2fr)_minmax(18rem,1fr)] gap-5">
        <section className="border border-border bg-card" aria-labelledby="vnr-nodes-title">
          <header className="flex min-h-11 items-center justify-between border-b border-border px-3">
            <div className="flex items-center gap-2">
              <Server aria-hidden="true" className="size-4 text-primary" />
              <h3 id="vnr-nodes-title" className="text-sm font-semibold">Assigned Nodes</h3>
            </div>
            <Link
              href={`/nodes?vnrName=${encodeURIComponent(current.vnr.name)}`}
              className="text-xs font-medium text-primary-strong hover:underline"
            >
              Open Nodes inventory
            </Link>
          </header>
          {current.topology === null ? (
            <p className="px-4 py-10 text-sm text-muted-foreground">Node assignments are temporarily unavailable.</p>
          ) : nodes.length === 0 ? (
            <div className="grid min-h-44 place-items-center px-6 py-10 text-center">
              <div>
                <Server aria-hidden="true" className="mx-auto size-6 text-muted-foreground" strokeWidth={1.5} />
                <p className="mt-3 text-sm font-semibold">No Nodes assigned</p>
                <p className="mt-1 text-xs text-muted-foreground">This VNR has no current Node dependencies.</p>
              </div>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Node</TableHead>
                  <TableHead>Address</TableHead>
                  <TableHead>Liveness</TableHead>
                  <TableHead>Session</TableHead>
                  <TableHead>Enrollment</TableHead>
                  <TableHead>Observed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {nodes.map((node) => {
                  const runtime = runtimeByNode.get(node.id);
                  return (
                    <TableRow key={node.id}>
                      <TableCell>
                        <Link href={`/nodes/${node.id}`} className="font-semibold hover:text-primary-strong hover:underline">{node.name}</Link>
                        <p className="mt-0.5 font-mono text-[0.625rem] text-muted-foreground">{node.id}</p>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{node.address}</TableCell>
                      <TableCell><NodeState runtime={runtime} /></TableCell>
                      <TableCell><Badge tone={runtime === undefined ? "neutral" : sessionTone(runtime.sessionState)}>{runtime?.sessionState ?? "unknown"}</Badge></TableCell>
                      <TableCell><Badge tone={node.enrollmentState === "enrolled" ? "healthy" : node.enrollmentState === "credential_issued" ? "info" : "neutral"}>{node.enrollmentState.replace("_", " ")}</Badge></TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{runtime === undefined ? "No observation" : formatUtc(runtime.observedAt)}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </section>

        <aside className="space-y-5">
          <section className="border border-border bg-card" aria-labelledby="vnr-record-title">
            <header className="flex min-h-11 items-center gap-2 border-b border-border px-3">
              <Clock3 aria-hidden="true" className="size-4 text-primary" />
              <h3 id="vnr-record-title" className="text-sm font-semibold">Record</h3>
            </header>
            <dl className="divide-y divide-border px-3">
              <div className="py-3">
                <dt className="text-xs text-muted-foreground">Immutable name</dt>
                <dd className="mt-1 font-mono text-xs">{current.vnr.name}</dd>
              </div>
              <div className="py-3">
                <dt className="text-xs text-muted-foreground">Generation</dt>
                <dd className="mt-1 font-mono text-xs tabular-nums">{current.vnr.generation}</dd>
              </div>
              <div className="py-3">
                <dt className="text-xs text-muted-foreground">Created</dt>
                <dd className="mt-1 text-xs">{formatUtc(current.vnr.createdAt)}</dd>
              </div>
              <div className="py-3">
                <dt className="text-xs text-muted-foreground">Updated</dt>
                <dd className="mt-1 text-xs">{formatUtc(current.vnr.updatedAt)}</dd>
              </div>
              <div className="py-3">
                <dt className="text-xs text-muted-foreground">Refresh state</dt>
                <dd className="mt-1">
                  <Badge tone={snapshot.error === null ? "neutral" : "warning"}>
                    {snapshot.phase === "polling" ? "Refreshing" : snapshot.error === null ? "Current" : "Retained"}
                  </Badge>
                </dd>
              </div>
            </dl>
          </section>

          <section className="border border-border bg-card" aria-labelledby="vnr-routing-title">
            <header className="flex min-h-11 items-center gap-2 border-b border-border px-3">
              <Route aria-hidden="true" className="size-4 text-primary" />
              <h3 id="vnr-routing-title" className="text-sm font-semibold">Routing posture</h3>
            </header>
            <div className="space-y-3 p-3 text-xs text-muted-foreground">
              <p>Routes are owned by Nodes assigned to this VNR. Prefix and owner changes remain transactional.</p>
              <Link href={`/nodes?vnrName=${encodeURIComponent(current.vnr.name)}`} className="inline-flex items-center gap-1.5 font-medium text-primary-strong hover:underline">
                <Network aria-hidden="true" className="size-3.5" /> Inspect route owners
              </Link>
            </div>
          </section>
        </aside>
      </div>

      {can("inventory:delete") ? (
        <section className="flex items-center justify-between gap-6 border border-destructive-border bg-destructive-muted px-4 py-3" aria-labelledby="vnr-danger-title">
          <div>
            <div className="flex items-center gap-2">
              <KeyRound aria-hidden="true" className="size-4 text-destructive" />
              <h3 id="vnr-danger-title" className="text-sm font-semibold">Danger zone</h3>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">Deletion requires a recent password confirmation, the exact VNR name, and a fresh resource version.</p>
          </div>
          <DeleteVnrDialog nodeCount={current.topology === null ? null : nodes.length} vnr={current.vnr} />
        </section>
      ) : null}
    </div>
  );
}
