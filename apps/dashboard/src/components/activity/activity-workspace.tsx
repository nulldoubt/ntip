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
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  cn,
} from "@ntip/ui";
import {
  Activity,
  Archive,
  CircleAlert,
  Download,
  KeyRound,
  LoaderCircle,
  Play,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { useAuth } from "@/components/auth-context";
import { usePolledResource } from "@/lib/use-polled-resource";
import {
  ActivityApiError,
  activityMutation,
  exportAudit,
  getActivityJson,
  getAuditHead,
  reauthenticate,
} from "./activity-api";

type EventPage = components["schemas"]["EventPage"];
type EventItem = components["schemas"]["Event"];
type ConnectivityCheckPage = components["schemas"]["ConnectivityCheckPage"];
type ConnectivityCheck = components["schemas"]["ConnectivityCheck"];
type AuditPage = components["schemas"]["AuditPage"];
type AuditEntry = components["schemas"]["AuditEntry"];
type AuditPruneResult = components["schemas"]["AuditPruneResult"];
type Node = components["schemas"]["Node"];

type ExportReceipt = Readonly<{
  exportId: string;
  filename: string;
  throughAuditId: string;
}>;

function formatTimestamp(value: string | null): string {
  if (value === null) return "Not yet";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

function errorMessage(reason: unknown): string {
  return reason instanceof Error ? reason.message : "The request failed";
}

function mergeById<T extends { id: string }>(primary: readonly T[], older: readonly T[]): T[] {
  const seen = new Set<string>();
  return [...primary, ...older].filter((item) => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });
}

function Freshness({
  error,
  freshness,
  lastSuccessAt,
  pauseReason,
}: Readonly<{
  error: string | null;
  freshness: "empty" | "fresh" | "stale";
  lastSuccessAt: number | null;
  pauseReason: "hidden" | "offline" | null;
}>) {
  const stale = freshness !== "fresh" || error !== null || pauseReason !== null;
  return (
    <div className="flex min-h-8 items-center gap-2 text-xs text-muted-foreground" aria-live="polite">
      <span className={cn("size-1.5 rounded-full", stale ? "bg-warning" : "bg-success")} aria-hidden="true" />
      <span>
        {pauseReason === "offline"
          ? "Offline. Showing last known data."
          : pauseReason === "hidden"
            ? "Polling paused while hidden."
            : error ?? (lastSuccessAt === null ? "Initial server snapshot" : `Updated ${formatTimestamp(new Date(lastSuccessAt).toISOString())}`)}
      </span>
    </div>
  );
}

function EmptyLedger({ children }: Readonly<{ children: string }>) {
  return <div className="border-y border-border px-4 py-12 text-center text-sm text-muted-foreground">{children}</div>;
}

function severityTone(severity: EventItem["severity"]): "info" | "warning" | "critical" {
  if (severity === "critical") return "critical";
  if (severity === "warning") return "warning";
  return "info";
}

function checkTone(status: ConnectivityCheck["status"]): "healthy" | "warning" | "critical" | "neutral" | "info" {
  if (status === "succeeded") return "healthy";
  if (status === "queued" || status === "running") return "info";
  if (status === "timed_out" || status === "interrupted") return "warning";
  if (status === "failed") return "critical";
  return "neutral";
}

function outcomeTone(outcome: AuditEntry["outcome"]): "healthy" | "warning" | "critical" {
  if (outcome === "succeeded") return "healthy";
  if (outcome === "rejected") return "warning";
  return "critical";
}

export function ActivityWorkspace({
  initialAudit,
  initialAuditEtag,
  initialChecks,
  initialEvents,
  nodes,
}: Readonly<{
  initialAudit: AuditPage;
  initialAuditEtag: string | null;
  initialChecks: ConnectivityCheckPage;
  initialEvents: EventPage;
  nodes: readonly Node[];
}>) {
  const { auth, can } = useAuth();
  const events = usePolledResource<EventPage>("/api/v1/events?limit=50", 15_000, initialEvents);
  const checks = usePolledResource<ConnectivityCheckPage>("/api/v1/connectivity-checks?limit=50", 10_000, initialChecks);
  const audit = usePolledResource<AuditPage>("/api/v1/audit?limit=50", 15_000, initialAudit);

  const [olderEvents, setOlderEvents] = useState<EventItem[]>([]);
  const [eventCursorOverride, setEventCursorOverride] = useState<string | null | undefined>(undefined);
  const [olderChecks, setOlderChecks] = useState<ConnectivityCheck[]>([]);
  const [checkCursorOverride, setCheckCursorOverride] = useState<string | null | undefined>(undefined);
  const [olderAudit, setOlderAudit] = useState<AuditEntry[]>([]);
  const [auditCursorOverride, setAuditCursorOverride] = useState<string | null | undefined>(undefined);
  const [loadingMore, setLoadingMore] = useState<"events" | "checks" | "audit" | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const eventPage = events.data ?? initialEvents;
  const checkPage = checks.data ?? initialChecks;
  const auditPage = audit.data ?? initialAudit;
  const eventItems = useMemo(() => mergeById(eventPage.items, olderEvents), [eventPage.items, olderEvents]);
  const checkItems = useMemo(() => mergeById(checkPage.items, olderChecks), [checkPage.items, olderChecks]);
  const auditItems = useMemo(() => mergeById(auditPage.items, olderAudit), [auditPage.items, olderAudit]);
  const eventCursor = eventCursorOverride === undefined ? eventPage.nextCursor : eventCursorOverride;
  const checkCursor = checkCursorOverride === undefined ? checkPage.nextCursor : checkCursorOverride;
  const auditCursor = auditCursorOverride === undefined ? auditPage.nextCursor : auditCursorOverride;

  async function loadMore(kind: "events" | "checks" | "audit") {
    const cursor = kind === "events" ? eventCursor : kind === "checks" ? checkCursor : auditCursor;
    if (cursor === null) return;
    setLoadingMore(kind);
    setLoadError(null);
    try {
      if (kind === "events") {
        const page = await getActivityJson<EventPage>(`/api/v1/events?limit=50&cursor=${encodeURIComponent(cursor)}`);
        setOlderEvents((current) => mergeById(current, page.items));
        setEventCursorOverride(page.nextCursor);
      } else if (kind === "checks") {
        const page = await getActivityJson<ConnectivityCheckPage>(`/api/v1/connectivity-checks?limit=50&cursor=${encodeURIComponent(cursor)}`);
        setOlderChecks((current) => mergeById(current, page.items));
        setCheckCursorOverride(page.nextCursor);
      } else {
        const page = await getActivityJson<AuditPage>(`/api/v1/audit?limit=50&cursor=${encodeURIComponent(cursor)}`);
        setOlderAudit((current) => mergeById(current, page.items));
        setAuditCursorOverride(page.nextCursor);
      }
    } catch (error) {
      setLoadError(errorMessage(error));
    } finally {
      setLoadingMore(null);
    }
  }

  return (
    <div className="mx-auto w-full max-w-[104rem] p-5 lg:p-6">
      <div className="mb-5 flex items-start justify-between gap-6">
        <div>
          <p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.12em] text-primary-strong">Operations ledger</p>
          <h2 className="mt-1 text-xl font-semibold tracking-tight">Activity</h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-muted-foreground">
            Runtime transitions, Master-originated checks, and immutable operator history.
          </p>
        </div>
        <Button type="button" variant="outline" size="sm" onClick={() => { events.refresh(); checks.refresh(); audit.refresh(); }}>
          <RefreshCw aria-hidden="true" /> Refresh
        </Button>
      </div>

      {loadError !== null ? (
        <Alert tone="critical" className="mb-4">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>Older entries could not be loaded</AlertTitle>
          <AlertDescription>{loadError}</AlertDescription>
        </Alert>
      ) : null}

      <Tabs defaultValue="events">
        <TabsList aria-label="Activity sources" className="w-full justify-start">
          <TabsTrigger value="events"><Activity aria-hidden="true" className="me-2 inline size-4" />Events</TabsTrigger>
          <TabsTrigger value="checks"><Play aria-hidden="true" className="me-2 inline size-4" />Connectivity checks</TabsTrigger>
          <TabsTrigger value="audit"><ShieldCheck aria-hidden="true" className="me-2 inline size-4" />Audit</TabsTrigger>
        </TabsList>

        <TabsContent value="events" className="pt-3">
          <div className="flex items-center justify-between border-b border-border pb-2">
            <Freshness {...events} />
            <span className="font-mono text-[0.6875rem] text-muted-foreground">poll 15s</span>
          </div>
          {eventItems.length === 0 ? <EmptyLedger>No retained runtime or security transitions.</EmptyLedger> : (
            <Table>
              <TableHeader><TableRow>
                <TableHead className="w-44">Occurred</TableHead><TableHead className="w-24">Severity</TableHead>
                <TableHead>Transition</TableHead><TableHead>Resource</TableHead><TableHead>Summary</TableHead>
              </TableRow></TableHeader>
              <TableBody>{eventItems.map((event) => (
                <TableRow key={event.id}>
                  <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">{formatTimestamp(event.occurredAt)}</TableCell>
                  <TableCell><Badge tone={severityTone(event.severity)}>{event.severity}</Badge></TableCell>
                  <TableCell className="font-mono text-xs">{event.kind}</TableCell>
                  <TableCell><span className="text-xs text-muted-foreground">{event.resourceType}</span>{event.resourceId !== null ? <span className="ms-2 font-mono text-xs">{event.resourceId}</span> : null}</TableCell>
                  <TableCell className="max-w-xl text-sm">{event.summary ?? "No summary supplied"}</TableCell>
                </TableRow>
              ))}</TableBody>
            </Table>
          )}
          {eventCursor !== null ? <div className="flex justify-center border-t border-border pt-3"><Button variant="outline" size="sm" disabled={loadingMore !== null} onClick={() => void loadMore("events")}>{loadingMore === "events" ? <LoaderCircle className="animate-spin" /> : null}Load more</Button></div> : null}
        </TabsContent>

        <TabsContent value="checks" className="pt-3">
          <div className="flex items-center justify-between border-b border-border pb-2">
            <Freshness {...checks} />
            <div className="flex items-center gap-3">
              <span className="font-mono text-[0.6875rem] text-muted-foreground">active poll 10s</span>
              {can("connectivity:run") ? <CreateCheck nodes={nodes} csrfToken={auth.csrfToken} onCreated={() => checks.refresh()} /> : null}
            </div>
          </div>
          {checkItems.length === 0 ? <EmptyLedger>No connectivity checks have been run.</EmptyLedger> : (
            <Table>
              <TableHeader><TableRow>
                <TableHead className="w-44">Created</TableHead><TableHead>Status</TableHead><TableHead>Node</TableHead>
                <TableHead>Address</TableHead><TableHead>Timeout</TableHead><TableHead>Round trip</TableHead><TableHead>Failure</TableHead>
              </TableRow></TableHeader>
              <TableBody>{checkItems.map((check) => (
                <TableRow key={check.id}>
                  <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">{formatTimestamp(check.createdAt)}</TableCell>
                  <TableCell><Badge tone={checkTone(check.status)}>{check.status.replaceAll("_", " ")}</Badge></TableCell>
                  <TableCell className="font-mono text-xs">{check.nodeId ?? "deleted"}</TableCell>
                  <TableCell className="font-mono text-xs">{check.nodeAddress}</TableCell>
                  <TableCell>{check.timeoutMilliseconds} ms</TableCell>
                  <TableCell>{check.roundTripMilliseconds === null ? "Not available" : `${check.roundTripMilliseconds} ms`}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{check.failureCode ?? "none"}</TableCell>
                </TableRow>
              ))}</TableBody>
            </Table>
          )}
          {checkCursor !== null ? <div className="flex justify-center border-t border-border pt-3"><Button variant="outline" size="sm" disabled={loadingMore !== null} onClick={() => void loadMore("checks")}>{loadingMore === "checks" ? <LoaderCircle className="animate-spin" /> : null}Load more</Button></div> : null}
        </TabsContent>

        <TabsContent value="audit" className="pt-3">
          <div className="flex items-center justify-between border-b border-border pb-2">
            <Freshness {...audit} />
            <div className="flex items-center gap-3">
              <span className="font-mono text-[0.6875rem] text-muted-foreground">poll 15s</span>
              {can("audit:manage") ? <AuditControls csrfToken={auth.csrfToken} entries={auditItems} initialEtag={initialAuditEtag} onPruned={() => audit.refresh()} /> : null}
            </div>
          </div>
          {auditItems.length === 0 ? <EmptyLedger>No audit entries are visible for this role.</EmptyLedger> : (
            <Table>
              <TableHeader><TableRow>
                <TableHead className="w-44">Occurred</TableHead><TableHead>Actor</TableHead><TableHead>Action</TableHead>
                <TableHead>Resource</TableHead><TableHead>Outcome</TableHead><TableHead>Request</TableHead>
              </TableRow></TableHeader>
              <TableBody>{auditItems.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">{formatTimestamp(entry.occurredAt)}</TableCell>
                  <TableCell><div className="text-sm">{entry.actorUsername ?? entry.actorType}</div><div className="font-mono text-[0.6875rem] text-muted-foreground">{entry.actorType}</div></TableCell>
                  <TableCell className="font-mono text-xs">{entry.action}</TableCell>
                  <TableCell><span className="text-xs text-muted-foreground">{entry.resourceType}</span>{entry.resourceId !== null ? <span className="ms-2 font-mono text-xs">{entry.resourceId}</span> : null}</TableCell>
                  <TableCell><Badge tone={outcomeTone(entry.outcome)}>{entry.outcome}</Badge></TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{entry.requestId ?? "local"}</TableCell>
                </TableRow>
              ))}</TableBody>
            </Table>
          )}
          {auditCursor !== null ? <div className="flex justify-center border-t border-border pt-3"><Button variant="outline" size="sm" disabled={loadingMore !== null} onClick={() => void loadMore("audit")}>{loadingMore === "audit" ? <LoaderCircle className="animate-spin" /> : null}Load more</Button></div> : null}
        </TabsContent>
      </Tabs>
    </div>
  );
}

function CreateCheck({ nodes, csrfToken, onCreated }: Readonly<{ nodes: readonly Node[]; csrfToken: string; onCreated(): void }>) {
  const [open, setOpen] = useState(false);
  const [nodeId, setNodeId] = useState(nodes[0]?.id ?? "");
  const [timeout, setTimeoutValue] = useState("3000");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await activityMutation<ConnectivityCheck, { nodeId: string; timeoutMilliseconds: number }>({
        body: { nodeId, timeoutMilliseconds: Number(timeout) },
        csrfToken,
        method: "POST",
        path: "/api/v1/connectivity-checks",
      });
      setOpen(false);
      onCreated();
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setPending(false);
    }
  }

  return <Dialog open={open} onOpenChange={setOpen}>
    <Button type="button" size="sm" onClick={() => setOpen(true)} disabled={nodes.length === 0}><Play aria-hidden="true" />Run check</Button>
    <DialogContent>
      <DialogHeader><DialogTitle>Run connectivity check</DialogTitle><DialogDescription>The Master sends one ICMP echo request to the selected existing Node address over the authenticated DATA path.</DialogDescription></DialogHeader>
      <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
        <div className="grid gap-2"><Label htmlFor="check-node">Node</Label><Select value={nodeId} onValueChange={setNodeId}><SelectTrigger id="check-node"><SelectValue placeholder="Select a Node" /></SelectTrigger><SelectContent>{nodes.map((node) => <SelectItem key={node.id} value={node.id}>{node.name} · {node.address}</SelectItem>)}</SelectContent></Select></div>
        <div className="grid gap-2"><Label htmlFor="check-timeout">Timeout in milliseconds</Label><Input id="check-timeout" type="number" min={500} max={10000} step={100} required value={timeout} onChange={(event) => setTimeoutValue(event.target.value)} /><p className="text-xs text-muted-foreground">Allowed range: 500 to 10,000 ms.</p></div>
        {error !== null ? <Alert tone="critical"><CircleAlert /><AlertTitle>Check not started</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
        <DialogFooter><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" disabled={pending || nodeId.length === 0}>{pending ? <LoaderCircle className="animate-spin" /> : <Play />}Start check</Button></DialogFooter>
      </form>
    </DialogContent>
  </Dialog>;
}

function AuditControls({ csrfToken, entries, initialEtag, onPruned }: Readonly<{ csrfToken: string; entries: readonly AuditEntry[]; initialEtag: string | null; onPruned(): void }>) {
  const [exportOpen, setExportOpen] = useState(false);
  const [pruneOpen, setPruneOpen] = useState(false);
  const [throughAuditId, setThroughAuditId] = useState(entries.at(-1)?.id ?? "");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(initialEtag === null ? "Audit ETag will be refreshed before export." : null);
  const [receipt, setReceipt] = useState<ExportReceipt | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  function resetSecretFields() {
    setPassword("");
    setConfirmation("");
  }

  async function submitExport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    setNotice(null);
    try {
      await reauthenticate(csrfToken, password);
      const fresh = await getAuditHead();
      const result = await exportAudit({ csrfToken, etag: fresh.etag, throughAuditId });
      setReceipt({ ...result, throughAuditId });
      setNotice(`Export ${result.filename} downloaded. Durable receipt ${result.exportId} is ready for an immediate matching prune.`);
      setExportOpen(false);
      resetSecretFields();
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setPending(false);
    }
  }

  async function submitPrune(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (receipt === null) return;
    setPending(true);
    setError(null);
    setNotice(null);
    try {
      await reauthenticate(csrfToken, password);
      const fresh = await getAuditHead();
      const result = await activityMutation<AuditPruneResult, { exportId: string; throughAuditId: string; confirmation: string }>({
        body: { exportId: receipt.exportId, throughAuditId: receipt.throughAuditId, confirmation: "prune audit" },
        csrfToken,
        ifMatch: fresh.etag,
        method: "POST",
        path: "/api/v1/audit/prune",
      });
      setNotice(`${result.prunedEntries} audit entries pruned through ${result.throughAuditId}.`);
      setReceipt(null);
      setPruneOpen(false);
      resetSecretFields();
      onPruned();
    } catch (reason) {
      if (reason instanceof ActivityApiError && reason.code === "precondition_failed") {
        setError("Audit changed before the prune committed. Review the current prefix and try again.");
      } else {
        setError(errorMessage(reason));
      }
    } finally {
      setPending(false);
    }
  }

  return <div className="flex items-center gap-2">
    {notice !== null ? <span className="max-w-md truncate text-xs text-success" title={notice}>{notice}</span> : null}
    {receipt !== null ? <Button type="button" size="sm" variant="quietDanger" onClick={() => { setError(null); resetSecretFields(); setPruneOpen(true); }}><Trash2 />Prune exported prefix</Button> : null}
    <Button type="button" size="sm" variant="outline" disabled={entries.length === 0} onClick={() => { setError(null); resetSecretFields(); if (throughAuditId.length === 0) setThroughAuditId(entries.at(-1)?.id ?? ""); setExportOpen(true); }}><Download />Export prefix</Button>

    <Dialog open={exportOpen} onOpenChange={setExportOpen}><DialogContent>
      <DialogHeader><DialogTitle>Export audit prefix</DialogTitle><DialogDescription>The selected immutable prefix is streamed as NDJSON. A durable receipt is committed before the response completes.</DialogDescription></DialogHeader>
      <form className="grid gap-4" onSubmit={(event) => void submitExport(event)}>
        <div className="grid gap-2"><Label htmlFor="audit-through">Through audit ID</Label><Input id="audit-through" required pattern="[a-z0-9]{32}" value={throughAuditId} onChange={(event) => setThroughAuditId(event.target.value)} className="font-mono" /><p className="text-xs text-muted-foreground">The oldest currently loaded entry is selected by default.</p></div>
        <div className="grid gap-2"><Label htmlFor="audit-export-password">Confirm your password</Label><Input id="audit-export-password" type="password" minLength={14} maxLength={256} autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></div>
        <div className="grid gap-2"><Label htmlFor="audit-export-confirmation">Type <span className="font-mono">export audit</span></Label><Input id="audit-export-confirmation" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></div>
        {error !== null ? <Alert tone="critical"><CircleAlert /><AlertTitle>Export not completed</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
        <DialogFooter><Button type="button" variant="ghost" onClick={() => setExportOpen(false)}>Cancel</Button><Button type="submit" disabled={pending || confirmation !== "export audit"}>{pending ? <LoaderCircle className="animate-spin" /> : <Archive />}Export and download</Button></DialogFooter>
      </form>
    </DialogContent></Dialog>

    <Dialog open={pruneOpen} onOpenChange={setPruneOpen}><DialogContent>
      <DialogHeader><DialogTitle>Prune exported audit prefix</DialogTitle><DialogDescription>This deletes only the prefix covered by receipt <span className="font-mono">{receipt?.exportId}</span>. The service verifies the receipt and a fresh audit ETag.</DialogDescription></DialogHeader>
      <form className="grid gap-4" onSubmit={(event) => void submitPrune(event)}>
        <Alert tone="warning"><KeyRound /><AlertTitle>Reauthentication required</AlertTitle><AlertDescription>Pruning is irreversible. Keep the downloaded export in protected storage.</AlertDescription></Alert>
        <div className="grid gap-2"><Label htmlFor="audit-prune-password">Confirm your password</Label><Input id="audit-prune-password" type="password" minLength={14} maxLength={256} autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></div>
        <div className="grid gap-2"><Label htmlFor="audit-prune-confirmation">Type <span className="font-mono">prune audit</span></Label><Input id="audit-prune-confirmation" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></div>
        {error !== null ? <Alert tone="critical"><CircleAlert /><AlertTitle>Prefix not pruned</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
        <DialogFooter><Button type="button" variant="ghost" onClick={() => setPruneOpen(false)}>Cancel</Button><Button type="submit" variant="destructive" disabled={pending || confirmation !== "prune audit"}>{pending ? <LoaderCircle className="animate-spin" /> : <Trash2 />}Prune prefix</Button></DialogFooter>
      </form>
    </DialogContent></Dialog>
  </div>;
}
