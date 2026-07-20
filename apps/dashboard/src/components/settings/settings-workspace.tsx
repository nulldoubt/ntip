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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@ntip/ui";
import {
  CircleAlert,
  CircleCheck,
  Clock3,
  History,
  LoaderCircle,
  Power,
  RefreshCw,
  RotateCcw,
  Save,
  Settings2,
  ShieldAlert,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useAuth } from "@/components/auth-context";
import {
  getSettingsWithEtag,
  SettingsApiError,
  settingsGet,
  settingsMutation,
  settingsReauthenticate,
} from "./settings-api";

type SettingsState = components["schemas"]["SettingsState"];
type SettingsRevision = components["schemas"]["SettingsRevision"];
type SettingsRevisionPage = components["schemas"]["SettingsRevisionPage"];
type OperationalSettings = components["schemas"]["OperationalSettings"];
type Overview = components["schemas"]["Overview"];
type AcceptedOperation = components["schemas"]["AcceptedOperation"];
type SettingsKey = keyof OperationalSettings;

type SettingsField = Readonly<{
  key: SettingsKey;
  label: string;
  description: string;
  min: number;
  max: number;
  unit: string;
  restart?: boolean;
}>;

const settingsFields: readonly SettingsField[] = [
  { key: "innerMtu", label: "Inner MTU", description: "Tunnel payload MTU applied with runtime acknowledgement.", min: 576, max: 65501, unit: "bytes" },
  { key: "heartbeatIntervalSeconds", label: "Heartbeat interval", description: "Nominal liveness heartbeat cadence.", min: 1, max: 65535, unit: "seconds" },
  { key: "suspectAfterSeconds", label: "Suspect after", description: "Authenticated inactivity before a Node becomes suspect.", min: 2, max: 65535, unit: "seconds" },
  { key: "offlineAfterSeconds", label: "Offline after", description: "Authenticated inactivity before a Node becomes offline.", min: 3, max: 65535, unit: "seconds" },
  { key: "defaultEnrollmentLifetimeSeconds", label: "Enrollment lifetime", description: "Default validity of newly issued enrollment credentials.", min: 60, max: 2592000, unit: "seconds" },
  { key: "trafficColdAfterSeconds", label: "Traffic cold after", description: "Idle duration before traffic state becomes cold.", min: 1, max: 65535, unit: "seconds" },
  { key: "trafficHotPacketsPerSecond", label: "Hot packet threshold", description: "Authenticated packet rate that marks traffic hot.", min: 1, max: 4294967295, unit: "packets/s" },
  { key: "trafficHotBitsPerSecond", label: "Hot bit threshold", description: "Authenticated bit rate that marks traffic hot.", min: 1, max: Number.MAX_SAFE_INTEGER, unit: "bits/s" },
  { key: "trafficSaturatedQueuePercent", label: "Saturated queue", description: "Bounded queue occupancy that marks traffic saturated.", min: 1, max: 100, unit: "%" },
  { key: "trafficHysteresisSeconds", label: "Traffic hysteresis", description: "Stability interval before traffic state transitions.", min: 1, max: 3600, unit: "seconds" },
  { key: "runtimeEventRetentionDays", label: "Runtime event retention", description: "Retention period for runtime and security transitions.", min: 1, max: 3650, unit: "days" },
  { key: "connectivityRetentionDays", label: "Connectivity retention", description: "Retention period for persisted connectivity results.", min: 1, max: 3650, unit: "days" },
  { key: "maximumNodes", label: "Maximum Node capacity", description: "Allocated Node capacity. Applying this setting requires restart.", min: 1, max: 65536, unit: "Nodes", restart: true },
] as const;

function formatTimestamp(value: string | null): string {
  if (value === null) return "Not applied";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" }).format(new Date(value));
}

function errorMessage(reason: unknown): string {
  if (reason instanceof SettingsApiError && reason.code === "precondition_failed") return "Settings changed before this request committed. Review the current desired revision and try again.";
  return reason instanceof Error ? reason.message : "The request failed";
}

function revisionTone(status: SettingsRevision["status"]): "healthy" | "warning" | "critical" | "info" {
  if (status === "active") return "healthy";
  if (status === "failed") return "critical";
  if (status === "pending_restart") return "warning";
  return "info";
}

function mergeRevisions(primary: readonly SettingsRevision[], older: readonly SettingsRevision[]): SettingsRevision[] {
  const seen = new Set<string>();
  return [...primary, ...older].filter((revision) => {
    if (seen.has(revision.id)) return false;
    seen.add(revision.id);
    return true;
  });
}

function draftFromSettings(settings: OperationalSettings): Record<SettingsKey, string> {
  return Object.fromEntries(settingsFields.map((field) => [field.key, String(settings[field.key])])) as Record<SettingsKey, string>;
}

export function SettingsWorkspace({ initialOverview, initialRevisions, initialSettings, initialSettingsEtag }: Readonly<{
  initialOverview: Overview;
  initialRevisions: SettingsRevisionPage;
  initialSettings: SettingsState;
  initialSettingsEtag: string | null;
}>) {
  const { auth, can } = useAuth();
  const [settings, setSettings] = useState(initialSettings);
  const [settingsEtag, setSettingsEtag] = useState(initialSettingsEtag);
  const [overview, setOverview] = useState(initialOverview);
  const [revisionPage, setRevisionPage] = useState(initialRevisions);
  const [olderRevisions, setOlderRevisions] = useState<SettingsRevision[]>([]);
  const [cursor, setCursor] = useState(initialRevisions.nextCursor);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastSuccessAt, setLastSuccessAt] = useState<number | null>(null);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    setError(null);
    try {
      const [freshSettings, revisions, freshOverview] = await Promise.all([
        getSettingsWithEtag(),
        settingsGet<SettingsRevisionPage>("/api/v1/settings/revisions?limit=50"),
        settingsGet<Overview>("/api/v1/overview"),
      ]);
      setSettings(freshSettings.data);
      setSettingsEtag(freshSettings.etag);
      setRevisionPage(revisions);
      setOlderRevisions([]);
      setCursor(revisions.nextCursor);
      setOverview(freshOverview);
      setLastSuccessAt(Date.now());
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    const onFocus = () => void refresh();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [refresh]);

  const revisions = useMemo(() => mergeRevisions(revisionPage.items, olderRevisions), [olderRevisions, revisionPage.items]);

  async function loadMore() {
    if (cursor === null) return;
    setRefreshing(true);
    setError(null);
    try {
      const next = await settingsGet<SettingsRevisionPage>(`/api/v1/settings/revisions?limit=50&cursor=${encodeURIComponent(cursor)}`);
      setOlderRevisions((current) => mergeRevisions(current, next.items));
      setCursor(next.nextCursor);
      setLastSuccessAt(Date.now());
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setRefreshing(false);
    }
  }

  return <div className="mx-auto w-full max-w-[104rem] p-5 lg:p-6">
    <div className="mb-5 flex items-start justify-between gap-6">
      <div><p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.12em] text-primary-strong">Runtime policy</p><h2 className="mt-1 text-xl font-semibold tracking-tight">Settings</h2><p className="mt-1 max-w-2xl text-sm leading-6 text-muted-foreground">Immutable revisions separate desired policy from settings the data plane has acknowledged.</p></div>
      <div className="flex gap-2"><Button type="button" variant="outline" size="sm" disabled={refreshing} onClick={() => void refresh()}><RefreshCw className={refreshing ? "animate-spin" : undefined} />Refresh</Button>{can("settings:write") ? <EditSettings csrfToken={auth.csrfToken} settings={settings} etag={settingsEtag} onCommitted={() => void refresh()} /> : null}</div>
    </div>

    <div className="mb-3 flex min-h-8 items-center gap-2 text-xs text-muted-foreground" aria-live="polite"><span className={`size-1.5 rounded-full ${error === null ? "bg-success" : "bg-warning"}`} />{error ?? (lastSuccessAt === null ? "Initial server snapshot. Refreshes on focus and after mutations." : `Updated ${formatTimestamp(new Date(lastSuccessAt).toISOString())}`)}</div>
    {error !== null ? <Alert tone="critical" className="mb-4"><CircleAlert /><AlertTitle>Settings data is stale</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
    {settings.pendingRestart ? <Alert tone="warning" className="mb-4"><ShieldAlert /><AlertTitle>Restart required</AlertTitle><AlertDescription>Desired revision {settings.desired.sequence} includes a capacity change that is not yet effective.</AlertDescription></Alert> : null}

    <div className="mb-6 grid gap-px border border-border bg-border lg:grid-cols-2">
      <RevisionSummary label="Desired revision" revision={settings.desired} />
      <RevisionSummary label="Effective revision" revision={settings.effective} />
    </div>

    <section className="mb-7" aria-labelledby="settings-values-heading">
      <div className="mb-2 flex items-center justify-between"><h3 id="settings-values-heading" className="text-sm font-semibold">Desired operational values</h3><span className="font-mono text-[0.6875rem] text-muted-foreground">generation {settings.desired.sequence}</span></div>
      <div className="grid gap-px border border-border bg-border md:grid-cols-2 xl:grid-cols-3">{settingsFields.map((field) => <div key={field.key} className="min-h-24 bg-card p-3"><div className="flex items-center justify-between gap-3"><span className="text-xs font-semibold">{field.label}</span>{field.restart ? <Badge tone="warning">restart</Badge> : null}</div><div className="mt-2 font-mono text-lg font-semibold tabular-nums">{settings.desired.settings[field.key]} <span className="text-[0.6875rem] font-normal text-muted-foreground">{field.unit}</span></div><p className="mt-1 text-[0.6875rem] leading-5 text-muted-foreground">{field.description}</p></div>)}</div>
    </section>

    <section className="mb-7" aria-labelledby="revision-history-heading">
      <div className="mb-2 flex items-center justify-between"><h3 id="revision-history-heading" className="inline-flex items-center gap-2 text-sm font-semibold"><History className="size-4" />Revision history</h3><span className="text-xs text-muted-foreground">Append-only full snapshots</span></div>
      <div className="border-y border-border bg-card"><Table><TableHeader><TableRow><TableHead>Sequence</TableHead><TableHead>Status</TableHead><TableHead>Created</TableHead><TableHead>Applied</TableHead><TableHead>Failure</TableHead><TableHead className="w-28"><span className="sr-only">Actions</span></TableHead></TableRow></TableHeader><TableBody>{revisions.map((revision) => <TableRow key={revision.id}><TableCell><div className="font-mono font-semibold">#{revision.sequence}</div><div className="font-mono text-[0.6875rem] text-muted-foreground">{revision.id}</div></TableCell><TableCell><Badge tone={revisionTone(revision.status)}>{revision.status.replaceAll("_", " ")}</Badge></TableCell><TableCell className="whitespace-nowrap text-xs">{formatTimestamp(revision.createdAt)}</TableCell><TableCell className="whitespace-nowrap text-xs">{formatTimestamp(revision.appliedAt)}</TableCell><TableCell className="font-mono text-xs text-destructive">{revision.failureCode ?? "none"}</TableCell><TableCell>{can("settings:write") && revision.id !== settings.desired.id ? <RollbackSettings revision={revision} csrfToken={auth.csrfToken} onCommitted={() => void refresh()} /> : null}</TableCell></TableRow>)}</TableBody></Table></div>
      {cursor !== null ? <div className="flex justify-center pt-3"><Button variant="outline" size="sm" disabled={refreshing} onClick={() => void loadMore()}>{refreshing ? <LoaderCircle className="animate-spin" /> : null}Load more</Button></div> : null}
    </section>

    {can("service:control") ? <ServiceControl csrfToken={auth.csrfToken} overview={overview} onOverviewChanged={setOverview} /> : null}
  </div>;
}

function RevisionSummary({ label, revision }: Readonly<{ label: string; revision: SettingsRevision }>) {
  return <div className="bg-card p-4"><div className="flex items-center justify-between"><span className="text-xs font-semibold uppercase tracking-[0.075em] text-muted-foreground">{label}</span><Badge tone={revisionTone(revision.status)}>{revision.status.replaceAll("_", " ")}</Badge></div><div className="mt-3 flex items-end justify-between gap-4"><div><span className="font-mono text-2xl font-semibold tabular-nums">#{revision.sequence}</span><div className="mt-1 font-mono text-[0.6875rem] text-muted-foreground">{revision.id}</div></div><div className="text-end text-xs text-muted-foreground">Created {formatTimestamp(revision.createdAt)}<br />Applied {formatTimestamp(revision.appliedAt)}</div></div></div>;
}

function EditSettings({ csrfToken, settings, etag, onCommitted }: Readonly<{ csrfToken: string; settings: SettingsState; etag: string | null; onCommitted(): void }>) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(() => draftFromSettings(settings.desired.settings));
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [accepted, setAccepted] = useState<SettingsRevision | null>(null);

  function openEditor() {
    setDraft(draftFromSettings(settings.desired.settings));
    setPassword(""); setConfirmation(""); setError(null); setAccepted(null); setOpen(true);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true); setError(null);
    try {
      await settingsReauthenticate(csrfToken, password);
      const fresh = await getSettingsWithEtag();
      const values = Object.fromEntries(settingsFields.map((field) => [field.key, Number(draft[field.key])])) as OperationalSettings;
      const result = await settingsMutation<SettingsRevision, OperationalSettings & { confirmation: "settings" }>({ body: { ...values, confirmation: "settings" }, csrfToken, ifMatch: fresh.etag, method: "PATCH", path: "/api/v1/settings" });
      setAccepted(result); setPassword(""); setConfirmation(""); onCommitted();
    } catch (reason) { setError(errorMessage(reason)); } finally { setPending(false); }
  }

  return <Dialog open={open} onOpenChange={setOpen}><Button type="button" size="sm" onClick={openEditor}><Settings2 />Edit settings</Button><DialogContent className="w-[min(58rem,calc(100vw-3rem))] max-h-[88vh] overflow-y-auto">
    {accepted !== null ? <><DialogHeader><DialogTitle>Revision #{accepted.sequence} committed</DialogTitle><DialogDescription>The immutable desired snapshot is queued for reconciliation. Its current status is shown below.</DialogDescription></DialogHeader><Alert tone={accepted.status === "failed" ? "critical" : accepted.status === "pending_restart" ? "warning" : "info"}>{accepted.status === "failed" ? <CircleAlert /> : <Clock3 />}<AlertTitle>{accepted.status.replaceAll("_", " ")}</AlertTitle><AlertDescription>{accepted.failureCode === null ? "Refresh after runtime acknowledgement to see the effective revision." : `Failure code: ${accepted.failureCode}`}</AlertDescription></Alert><DialogFooter><Button type="button" onClick={() => setOpen(false)}>Done</Button></DialogFooter></> : <>
      <DialogHeader><DialogTitle>Edit operational settings</DialogTitle><DialogDescription>A successful save appends a complete immutable snapshot. Live values become effective only after runtime acknowledgement.</DialogDescription></DialogHeader>
      <form className="grid gap-5" onSubmit={(event) => void submit(event)}>
        <div className="grid gap-3 md:grid-cols-2">{settingsFields.map((field) => <div key={field.key} className="grid gap-1.5 border-b border-border pb-3"><div className="flex items-center justify-between"><Label htmlFor={`setting-${field.key}`}>{field.label}</Label>{field.restart ? <Badge tone="warning">restart required</Badge> : null}</div><div className="relative"><Input id={`setting-${field.key}`} type="number" min={field.min} max={field.max} step={1} required value={draft[field.key]} onChange={(event) => setDraft((current) => ({ ...current, [field.key]: event.target.value }))} className="pe-24 font-mono" /><span className="pointer-events-none absolute inset-y-0 end-3 flex items-center text-xs text-muted-foreground">{field.unit}</span></div><p className="text-[0.6875rem] leading-5 text-muted-foreground">{field.description}</p></div>)}</div>
        <Alert tone="warning"><ShieldAlert /><AlertTitle>Fresh authorization required</AlertTitle><AlertDescription>The dashboard reauthenticates you and reads the current settings ETag immediately before commit.{etag === null ? " The initial ETag was unavailable and will not be reused." : ""}</AlertDescription></Alert>
        <div className="grid gap-3 md:grid-cols-2"><div className="grid gap-1.5"><Label htmlFor="settings-password">Confirm your password</Label><Input id="settings-password" type="password" minLength={14} maxLength={256} autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></div><div className="grid gap-1.5"><Label htmlFor="settings-confirmation">Type <span className="font-mono">settings</span></Label><Input id="settings-confirmation" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></div></div>
        {error !== null ? <Alert tone="critical"><CircleAlert /><AlertTitle>Revision not committed</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
        <DialogFooter><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" disabled={pending || confirmation !== "settings"}>{pending ? <LoaderCircle className="animate-spin" /> : <Save />}Commit revision</Button></DialogFooter>
      </form>
    </>}
  </DialogContent></Dialog>;
}

function RollbackSettings({ revision, csrfToken, onCommitted }: Readonly<{ revision: SettingsRevision; csrfToken: string; onCommitted(): void }>) {
  const [open, setOpen] = useState(false); const [password, setPassword] = useState(""); const [confirmation, setConfirmation] = useState(""); const [pending, setPending] = useState(false); const [error, setError] = useState<string | null>(null); const [accepted, setAccepted] = useState<SettingsRevision | null>(null);
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); setPending(true); setError(null); try { await settingsReauthenticate(csrfToken, password); const fresh = await getSettingsWithEtag(); const result = await settingsMutation<SettingsRevision, { confirmation: string }>({ body: { confirmation: revision.id }, csrfToken, ifMatch: fresh.etag, method: "POST", path: `/api/v1/settings/revisions/${encodeURIComponent(revision.id)}/rollback` }); setAccepted(result); setPassword(""); setConfirmation(""); onCommitted(); } catch (reason) { setError(errorMessage(reason)); } finally { setPending(false); } }
  return <Dialog open={open} onOpenChange={(next) => { setOpen(next); if (!next) { setAccepted(null); setError(null); } }}><Button type="button" size="sm" variant="ghost" onClick={() => setOpen(true)}><RotateCcw />Rollback</Button><DialogContent>{accepted !== null ? <><DialogHeader><DialogTitle>Rollback revision #{accepted.sequence} committed</DialogTitle><DialogDescription>A new immutable snapshot was created from revision #{revision.sequence}. The original history remains unchanged.</DialogDescription></DialogHeader><Alert tone={accepted.status === "pending_restart" ? "warning" : "info"}><CircleCheck /><AlertTitle>{accepted.status.replaceAll("_", " ")}</AlertTitle><AlertDescription>Refresh after reconciliation to see the effective revision.</AlertDescription></Alert><DialogFooter><Button onClick={() => setOpen(false)}>Done</Button></DialogFooter></> : <><DialogHeader><DialogTitle>Roll back to revision #{revision.sequence}</DialogTitle><DialogDescription>This creates a new snapshot from the selected revision. It does not rewrite history.</DialogDescription></DialogHeader><form className="grid gap-4" onSubmit={(event) => void submit(event)}><div className="grid gap-2"><Label htmlFor={`rollback-password-${revision.id}`}>Confirm your password</Label><Input id={`rollback-password-${revision.id}`} type="password" minLength={14} maxLength={256} required autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} /></div><div className="grid gap-2"><Label htmlFor={`rollback-confirm-${revision.id}`}>Type revision ID <span className="font-mono">{revision.id}</span></Label><Input id={`rollback-confirm-${revision.id}`} className="font-mono" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></div>{error !== null ? <Alert tone="critical"><CircleAlert /><AlertTitle>Rollback not committed</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}<DialogFooter><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" disabled={pending || confirmation !== revision.id}>{pending ? <LoaderCircle className="animate-spin" /> : <RotateCcw />}Create rollback revision</Button></DialogFooter></form></>}</DialogContent></Dialog>;
}

type ControlKind = "restart" | "shutdown";
type ControlNotice = Readonly<{ tone: "info" | "warning" | "critical"; title: string; message: string }>;

function ServiceControl({ csrfToken, overview, onOverviewChanged }: Readonly<{ csrfToken: string; overview: Overview; onOverviewChanged(overview: Overview): void }>) {
  const [kind, setKind] = useState<ControlKind | null>(null); const [password, setPassword] = useState(""); const [confirmation, setConfirmation] = useState(""); const [pending, setPending] = useState(false); const [error, setError] = useState<string | null>(null); const [notice, setNotice] = useState<ControlNotice | null>(null); const [recovering, setRecovering] = useState(false); const [recoveryTick, setRecoveryTick] = useState(0); const sawUnavailable = useRef(false); const recoveryStartedAt = useRef(0);

  useEffect(() => {
    if (!recovering) return;
    const timer = setTimeout(() => {
      void (async () => {
        try {
          const response = await fetch("/api/v1/health/ready", { cache: "no-store", credentials: "same-origin" });
          if (!response.ok) throw new Error("not ready");
          if (sawUnavailable.current) {
            setNotice({ tone: "info", title: "Service recovered", message: "The management service is ready after restart. Refreshing current state." });
            const fresh = await settingsGet<Overview>("/api/v1/overview");
            onOverviewChanged(fresh);
            setRecovering(false);
            return;
          }
        } catch {
          sawUnavailable.current = true;
          setNotice({ tone: "warning", title: "Restart in progress", message: "The management service is temporarily unavailable. The dashboard will keep checking readiness." });
        }
        if (Date.now() - recoveryStartedAt.current > 60_000) {
          setNotice({ tone: "warning", title: "Restart accepted", message: "Readiness was not observed within 60 seconds. Verify the systemd service before retrying any operation." });
          setRecovering(false);
          return;
        }
        setRecoveryTick((current) => current + 1);
      })();
    }, recoveryTick === 0 ? 1_500 : 2_000);
    return () => clearTimeout(timer);
  }, [onOverviewChanged, recovering, recoveryTick]);

  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); if (kind === null) return; setPending(true); setError(null); try { await settingsReauthenticate(csrfToken, password); const freshOverview = await settingsGet<Overview>("/api/v1/overview"); onOverviewChanged(freshOverview); const result = await settingsMutation<AcceptedOperation, { confirmation: ControlKind }>({ body: { confirmation: kind }, csrfToken, ifMatch: freshOverview.serviceControlEtag, method: "POST", path: kind === "restart" ? "/api/v1/operations/restart" : "/api/v1/operations/shutdown" }); setKind(null); setPassword(""); setConfirmation(""); if (result.kind === "restart") { sawUnavailable.current = false; recoveryStartedAt.current = Date.now(); setRecoveryTick(0); setRecovering(true); setNotice({ tone: "info", title: "Restart accepted", message: `Operation ${result.id} committed. Waiting for the managed service to cycle.` }); } else { setNotice({ tone: "warning", title: "Shutdown accepted", message: `Operation ${result.id} committed. The management service is expected to become unavailable.` }); } } catch (reason) { if (reason instanceof SettingsApiError && reason.code === "operation_unavailable") setError("Managed restart is unavailable for this manually launched service instance."); else setError(errorMessage(reason)); } finally { setPending(false); } }

  return <section className="border-t border-border pt-5" aria-labelledby="service-control-heading"><div className="mb-4 flex items-start justify-between gap-6"><div><h3 id="service-control-heading" className="inline-flex items-center gap-2 text-sm font-semibold"><Power className="size-4" />Service control</h3><p className="mt-1 max-w-2xl text-xs leading-5 text-muted-foreground">Restart requires systemd managed-restart support. Shutdown exits cleanly without an automatic restart.</p></div><span className="font-mono text-[0.6875rem] text-muted-foreground">etag {overview.serviceControlEtag}</span></div>{notice !== null ? <Alert tone={notice.tone} className="mb-4">{notice.tone === "critical" ? <CircleAlert /> : notice.tone === "warning" ? <Clock3 /> : <CircleCheck />}<AlertTitle>{notice.title}</AlertTitle><AlertDescription>{notice.message}</AlertDescription></Alert> : null}<div className="flex gap-2"><Button type="button" variant="outline" onClick={() => { setKind("restart"); setError(null); }}>Restart service</Button><Button type="button" variant="quietDanger" onClick={() => { setKind("shutdown"); setError(null); }}>Shutdown service</Button></div>
    <Dialog open={kind !== null} onOpenChange={(open) => { if (!open) setKind(null); }}><DialogContent><DialogHeader><DialogTitle>{kind === "restart" ? "Restart NTIP service" : "Shut down NTIP service"}</DialogTitle><DialogDescription>The audit record commits before the service exits. A fresh service-control ETag and password check are required.</DialogDescription></DialogHeader><form className="grid gap-4" onSubmit={(event) => void submit(event)}><Alert tone="warning"><ShieldAlert /><AlertTitle>Control-plane interruption</AlertTitle><AlertDescription>{kind === "restart" ? "Active management requests will be interrupted while systemd restarts ntsrv." : "The API remains unavailable until an operator starts ntsrv again."}</AlertDescription></Alert><div className="grid gap-2"><Label htmlFor="control-password">Confirm your password</Label><Input id="control-password" type="password" minLength={14} maxLength={256} required autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} /></div><div className="grid gap-2"><Label htmlFor="control-confirmation">Type <span className="font-mono">{kind}</span></Label><Input id="control-confirmation" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></div>{error !== null ? <Alert tone="critical"><CircleAlert /><AlertTitle>Operation not accepted</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}<DialogFooter><Button type="button" variant="ghost" onClick={() => setKind(null)}>Cancel</Button><Button type="submit" variant={kind === "shutdown" ? "destructive" : "default"} disabled={pending || confirmation !== kind}>{pending ? <LoaderCircle className="animate-spin" /> : <Power />}{kind === "restart" ? "Restart service" : "Shut down service"}</Button></DialogFooter></form></DialogContent></Dialog>
  </section>;
}
