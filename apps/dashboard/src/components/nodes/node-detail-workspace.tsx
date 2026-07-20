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
import {
  Activity,
  AlertCircle,
  ArrowLeft,
  Download,
  KeyRound,
  Pencil,
  Plus,
  RefreshCw,
  Route as RouteIcon,
  ShieldAlert,
  Trash2,
  Unplug,
  Wifi,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { useAuth } from "@/components/auth-context";
import {
  fetchJson,
  fetchJsonWithEtag,
  freshIdempotencyKey,
  reauthenticate,
  responseError,
} from "@/components/nodes/browser-api";
import {
  connectivityTone,
  enrollmentTone,
  formatUtc,
  livenessTone,
  readableState,
  shortId,
} from "@/components/nodes/node-presenters";
import { createMutationAttempt } from "@/lib/behavior/mutation";
import { usePolledResource } from "@/lib/use-polled-resource";

type ConnectivityCheck = components["schemas"]["ConnectivityCheck"];
type ConnectivityCheckCreate = components["schemas"]["ConnectivityCheckCreate"];
type ConnectivityCheckPage = components["schemas"]["ConnectivityCheckPage"];
type DangerousConfirmation = components["schemas"]["DangerousConfirmation"];
type EnrollmentCredentialRequest = components["schemas"]["EnrollmentCredentialRequest"];
type Node = components["schemas"]["Node"];
type NodeDetail = components["schemas"]["NodeDetail"];
type NodePage = components["schemas"]["NodePage"];
type NodeUpdate = components["schemas"]["NodeUpdate"];
type Route = components["schemas"]["Route"];
type RouteCreate = components["schemas"]["RouteCreate"];
type RouteUpdate = components["schemas"]["RouteUpdate"];
type Vnr = components["schemas"]["Vnr"];

type WorkspaceProps = Readonly<{
  initialChecks: ConnectivityCheckPage;
  initialDetail: NodeDetail;
  nodes: NodePage;
  vnrs: readonly Vnr[];
}>;

function FormError({ children }: Readonly<{ children: string | null }>) {
  return children === null ? null : (
    <Alert tone="critical"><AlertCircle aria-hidden="true" /><AlertDescription>{children}</AlertDescription></Alert>
  );
}

function Field({ label, htmlFor, children, hint }: Readonly<{ label: string; htmlFor: string; children: ReactNode; hint?: string }>) {
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {hint === undefined ? null : <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

function UpdateNodeDialog({ detail, vnrs, onChanged }: Readonly<{ detail: NodeDetail; vnrs: readonly Vnr[]; onChanged: () => void }>) {
  const { auth, can } = useAuth();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [vnrName, setVnrName] = useState(detail.node.vnrName);
  if (!can("inventory:write")) return null;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    const data = new FormData(event.currentTarget);
    const body: NodeUpdate = {
      name: String(data.get("name") ?? "").trim(),
      address: String(data.get("address") ?? "").trim(),
      vnrName,
    };
    try {
      const current = await fetchJsonWithEtag<NodeDetail>(`/api/v1/nodes/${detail.node.id}`);
      const attempt = createMutationAttempt({
        method: "PATCH",
        url: `/api/v1/nodes/${detail.node.id}`,
        csrfToken: auth.csrfToken,
        ifMatch: current.etag,
        requiresIfMatch: true,
        body,
      });
      const response = await fetch(attempt.buildRequest());
      if (!response.ok) throw await responseError(response);
      setOpen(false);
      onChanged();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Node update failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => { setOpen(next); if (next) setVnrName(detail.node.vnrName); else setError(null); }}>
      <DialogTrigger asChild><Button variant="outline"><Pencil aria-hidden="true" />Edit Node</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Edit {detail.node.name}</DialogTitle><DialogDescription>A current read supplies the precondition immediately before this update.</DialogDescription></DialogHeader>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <FormError>{error}</FormError>
          <Field label="Name" htmlFor="edit-node-name"><Input id="edit-node-name" name="name" required defaultValue={detail.node.name} autoComplete="off" /></Field>
          <Field label="Address" htmlFor="edit-node-address"><Input id="edit-node-address" name="address" required defaultValue={detail.node.address} autoComplete="off" /></Field>
          <Field label="VNR" htmlFor="edit-node-vnr">
            <Select value={vnrName} onValueChange={setVnrName}>
              <SelectTrigger id="edit-node-vnr"><SelectValue /></SelectTrigger>
              <SelectContent>{vnrs.map((vnr) => <SelectItem key={vnr.name} value={vnr.name}>{vnr.name} · {vnr.cidr}</SelectItem>)}</SelectContent>
            </Select>
          </Field>
          <DialogFooter><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" disabled={pending}>{pending ? "Saving" : "Save changes"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function ConnectivityDialog({ node, onCreated }: Readonly<{ node: Node; onCreated: () => void }>) {
  const { auth, can } = useAuth();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!can("connectivity:run")) return null;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    const value = Number(new FormData(event.currentTarget).get("timeoutMilliseconds"));
    const body: ConnectivityCheckCreate = { nodeId: node.id, timeoutMilliseconds: value };
    try {
      const attempt = createMutationAttempt({ method: "POST", url: "/api/v1/connectivity-checks", csrfToken: auth.csrfToken, body });
      const response = await fetch(attempt.buildRequest());
      if (!response.ok) throw await responseError(response);
      setOpen(false);
      onCreated();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Connectivity check could not be started");
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => { setOpen(next); if (!next) setError(null); }}>
      <DialogTrigger asChild><Button variant="outline"><Wifi aria-hidden="true" />Run check</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Check {node.name}</DialogTitle><DialogDescription>Send one Master-originated ICMP echo to this Node address through the authenticated DATA path.</DialogDescription></DialogHeader>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <FormError>{error}</FormError>
          <Alert tone="info"><Activity aria-hidden="true" /><AlertDescription>Target is fixed to {node.address}. Arbitrary destinations are not accepted.</AlertDescription></Alert>
          <Field label="Timeout in milliseconds" htmlFor="check-timeout" hint="Allowed range: 500 to 10,000 milliseconds."><Input id="check-timeout" name="timeoutMilliseconds" type="number" min={500} max={10_000} step={100} defaultValue={3_000} required /></Field>
          <DialogFooter><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" disabled={pending}>{pending ? "Starting" : "Start check"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

type EnrollmentOperation = "issue" | "reset";

function EnrollmentDialog({ node, operation, onChanged }: Readonly<{ node: Node; operation: EnrollmentOperation; onChanged: () => void }>) {
  const { auth, can } = useAuth();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!can("enrollment:manage")) return null;
  const issue = operation === "issue";

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    const data = new FormData(event.currentTarget);
    const password = String(data.get("password") ?? "");
    const confirmation = String(data.get("confirmation") ?? "");
    try {
      await reauthenticate(auth.csrfToken, password);
      const current = await fetchJsonWithEtag<NodeDetail>(`/api/v1/nodes/${node.id}`);
      if (issue) {
        const body: EnrollmentCredentialRequest = {
          confirmation,
          expiresInSeconds: Number(data.get("expiresInSeconds")),
        };
        // Construct and send exactly once with the credential media type. This
        // branch has no retry path, and the response never enters component state.
        const oneTimeRequest = new Request(`/api/v1/nodes/${node.id}/enrollment-credentials`, {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          redirect: "error",
          headers: {
            Accept: "application/vnd.ntip.enrollment-credential",
            "Content-Type": "application/json",
            "Idempotency-Key": freshIdempotencyKey(),
            "If-Match": current.etag,
            "X-CSRF-Token": auth.csrfToken,
          },
          body: JSON.stringify(body),
        });
        const response = await fetch(oneTimeRequest);
        if (!response.ok) throw await responseError(response);
        const secretBlob = await response.blob();
        const objectUrl = URL.createObjectURL(secretBlob);
        const anchor = document.createElement("a");
        anchor.href = objectUrl;
        anchor.download = `${node.name.replaceAll(/[^a-zA-Z0-9._-]/g, "_")}.ntip-enrollment`;
        anchor.hidden = true;
        document.body.append(anchor);
        anchor.click();
        anchor.remove();
        requestAnimationFrame(() => URL.revokeObjectURL(objectUrl));
      } else {
        const body: DangerousConfirmation = { confirmation };
        const attempt = createMutationAttempt({
          method: "POST",
          url: `/api/v1/nodes/${node.id}/actions/reset-enrollment`,
          csrfToken: auth.csrfToken,
          ifMatch: current.etag,
          requiresIfMatch: true,
          body,
        });
        const response = await fetch(attempt.buildRequest());
        if (!response.ok) throw await responseError(response);
      }
      setOpen(false);
      onChanged();
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "Enrollment operation failed";
      setError(issue ? `${message}. The credential request was not retried.` : message);
    } finally {
      // Clear the password and typed confirmation with the closed form instance.
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => { setOpen(next); if (!next) setError(null); }}>
      <DialogTrigger asChild>
        <Button variant={issue ? "default" : "outline"}>{issue ? <Download aria-hidden="true" /> : <Unplug aria-hidden="true" />}{issue ? "Issue credential" : "Reset enrollment"}</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{issue ? "Issue enrollment credential" : "Reset enrollment"}</DialogTitle>
          <DialogDescription>{issue ? "This replaces any unused predecessor and starts a one-time download." : "This revokes any unused credential and returns the Node to unenrolled state."}</DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <FormError>{error}</FormError>
          <Alert tone="warning"><ShieldAlert aria-hidden="true" /><AlertDescription>Reauthentication and a fresh resource ETag are required. Type the exact Node name to continue.</AlertDescription></Alert>
          {issue ? <Field label="Validity in seconds" htmlFor="credential-lifetime" hint="Allowed range: 60 seconds to 30 days."><Input id="credential-lifetime" name="expiresInSeconds" type="number" min={60} max={2_592_000} defaultValue={3_600} required /></Field> : null}
          <Field label="Current password" htmlFor={`${operation}-password`}><Input id={`${operation}-password`} name="password" type="password" minLength={14} maxLength={256} autoComplete="current-password" required /></Field>
          <Field label={`Type “${node.name}”`} htmlFor={`${operation}-confirmation`}><Input id={`${operation}-confirmation`} name="confirmation" autoComplete="off" required pattern={node.name.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&")} /></Field>
          <DialogFooter><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" variant={issue ? "default" : "destructive"} disabled={pending}>{pending ? "Authorizing" : issue ? "Issue and download" : "Reset enrollment"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function DeleteNodeDialog({ node }: Readonly<{ node: Node }>) {
  const { auth, can } = useAuth();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!can("inventory:delete")) return null;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    const data = new FormData(event.currentTarget);
    try {
      await reauthenticate(auth.csrfToken, String(data.get("password") ?? ""));
      const current = await fetchJsonWithEtag<NodeDetail>(`/api/v1/nodes/${node.id}`);
      const body: DangerousConfirmation = { confirmation: String(data.get("confirmation") ?? "") };
      const attempt = createMutationAttempt({ method: "DELETE", url: `/api/v1/nodes/${node.id}`, csrfToken: auth.csrfToken, ifMatch: current.etag, requiresIfMatch: true, body });
      const response = await fetch(attempt.buildRequest());
      if (!response.ok) throw await responseError(response);
      router.replace("/nodes");
      router.refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Node deletion failed");
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => { setOpen(next); if (!next) setError(null); }}>
      <DialogTrigger asChild><Button variant="quietDanger"><Trash2 aria-hidden="true" />Delete Node</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Delete {node.name}</DialogTitle><DialogDescription>Deletion is permanent and is refused while the Node owns routes.</DialogDescription></DialogHeader>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <FormError>{error}</FormError>
          <Alert tone="critical"><ShieldAlert aria-hidden="true" /><AlertDescription>This commits an immutable audit record. Reauthentication, exact confirmation, and a fresh ETag are required.</AlertDescription></Alert>
          <Field label="Current password" htmlFor="delete-node-password"><Input id="delete-node-password" name="password" type="password" autoComplete="current-password" minLength={14} maxLength={256} required /></Field>
          <Field label={`Type “${node.name}”`} htmlFor="delete-node-confirmation"><Input id="delete-node-confirmation" name="confirmation" autoComplete="off" required /></Field>
          <DialogFooter><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" variant="destructive" disabled={pending}>{pending ? "Deleting" : "Delete Node"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function CreateRouteDialog({ node, onChanged }: Readonly<{ node: Node; onChanged: () => void }>) {
  const { auth, can } = useAuth();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!can("inventory:write")) return null;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    const body: RouteCreate = { nodeId: node.id, prefix: String(new FormData(event.currentTarget).get("prefix") ?? "").trim() };
    try {
      const attempt = createMutationAttempt({ method: "POST", url: "/api/v1/routes", csrfToken: auth.csrfToken, body });
      const response = await fetch(attempt.buildRequest());
      if (!response.ok) throw await responseError(response);
      setOpen(false);
      onChanged();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Route creation failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => { setOpen(next); if (!next) setError(null); }}>
      <DialogTrigger asChild><Button size="sm"><Plus aria-hidden="true" />Add route</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Add route</DialogTitle><DialogDescription>The prefix will be owned by {node.name}. Overlap and reserved-address invariants are checked transactionally.</DialogDescription></DialogHeader>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <FormError>{error}</FormError>
          <Field label="IPv4 prefix" htmlFor="create-route-prefix"><Input id="create-route-prefix" name="prefix" required autoComplete="off" placeholder="192.0.2.0/24" /></Field>
          <DialogFooter><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" disabled={pending}>{pending ? "Adding" : "Add route"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function EditRouteDialog({ route, nodes, onChanged }: Readonly<{ route: Route; nodes: readonly Node[]; onChanged: () => void }>) {
  const { auth, can } = useAuth();
  const [open, setOpen] = useState(false);
  const [ownerId, setOwnerId] = useState(route.nodeId);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!can("inventory:write")) return null;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    const body: RouteUpdate = { prefix: String(new FormData(event.currentTarget).get("prefix") ?? "").trim(), nodeId: ownerId };
    try {
      const current = await fetchJsonWithEtag<Route>(`/api/v1/routes/${route.id}`);
      const attempt = createMutationAttempt({ method: "PATCH", url: `/api/v1/routes/${route.id}`, csrfToken: auth.csrfToken, ifMatch: current.etag, requiresIfMatch: true, body });
      const response = await fetch(attempt.buildRequest());
      if (!response.ok) throw await responseError(response);
      setOpen(false);
      onChanged();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Route update failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => { setOpen(next); if (next) setOwnerId(route.nodeId); else setError(null); }}>
      <DialogTrigger asChild><Button size="icon" variant="ghost" aria-label={`Edit route ${route.prefix}`}><Pencil aria-hidden="true" /></Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Edit route</DialogTitle><DialogDescription>A current route read supplies the ETag before the update commits.</DialogDescription></DialogHeader>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <FormError>{error}</FormError>
          <Field label="IPv4 prefix" htmlFor={`edit-route-prefix-${route.id}`}><Input id={`edit-route-prefix-${route.id}`} name="prefix" required defaultValue={route.prefix} autoComplete="off" /></Field>
          <Field label="Owner" htmlFor={`edit-route-owner-${route.id}`}>
            <Select value={ownerId} onValueChange={setOwnerId}><SelectTrigger id={`edit-route-owner-${route.id}`}><SelectValue /></SelectTrigger><SelectContent>{nodes.map((node) => <SelectItem key={node.id} value={node.id}>{node.name} · {node.address}</SelectItem>)}</SelectContent></Select>
          </Field>
          <DialogFooter><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" disabled={pending}>{pending ? "Saving" : "Save route"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function DeleteRouteDialog({ route, onChanged }: Readonly<{ route: Route; onChanged: () => void }>) {
  const { auth, can } = useAuth();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!can("inventory:delete")) return null;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    const data = new FormData(event.currentTarget);
    try {
      await reauthenticate(auth.csrfToken, String(data.get("password") ?? ""));
      const current = await fetchJsonWithEtag<Route>(`/api/v1/routes/${route.id}`);
      const body: DangerousConfirmation = { confirmation: String(data.get("confirmation") ?? "") };
      const attempt = createMutationAttempt({ method: "DELETE", url: `/api/v1/routes/${route.id}`, csrfToken: auth.csrfToken, ifMatch: current.etag, requiresIfMatch: true, body });
      const response = await fetch(attempt.buildRequest());
      if (!response.ok) throw await responseError(response);
      setOpen(false);
      onChanged();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Route deletion failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => { setOpen(next); if (!next) setError(null); }}>
      <DialogTrigger asChild><Button size="icon" variant="ghost" className="text-destructive" aria-label={`Delete route ${route.prefix}`}><Trash2 aria-hidden="true" /></Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Delete route {route.prefix}</DialogTitle><DialogDescription>Retires the affected association and publishes one durable generation.</DialogDescription></DialogHeader>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <FormError>{error}</FormError>
          <Alert tone="critical"><ShieldAlert aria-hidden="true" /><AlertDescription>Reauthenticate and type the exact route prefix to continue.</AlertDescription></Alert>
          <Field label="Current password" htmlFor={`delete-route-password-${route.id}`}><Input id={`delete-route-password-${route.id}`} name="password" type="password" autoComplete="current-password" minLength={14} maxLength={256} required /></Field>
          <Field label={`Type “${route.prefix}”`} htmlFor={`delete-route-confirmation-${route.id}`}><Input id={`delete-route-confirmation-${route.id}`} name="confirmation" autoComplete="off" required /></Field>
          <DialogFooter><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" variant="destructive" disabled={pending}>{pending ? "Deleting" : "Delete route"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function RuntimePanel({ detail }: Readonly<{ detail: NodeDetail }>) {
  const runtime = detail.runtime;
  return (
    <section className="border border-border bg-card" aria-labelledby="runtime-title">
      <header className="flex h-11 items-center gap-2 border-b border-border px-4"><Activity aria-hidden="true" className="size-4 text-primary" /><h3 id="runtime-title" className="text-sm font-semibold">Runtime observation</h3></header>
      {runtime === null ? <p className="p-4 text-sm text-muted-foreground">No authenticated runtime observation is available for this Node.</p> : (
        <dl className="grid grid-cols-2 divide-x divide-y divide-border">
          <div className="p-4"><dt className="text-xs text-muted-foreground">Liveness</dt><dd className="mt-2"><Badge tone={livenessTone(runtime.liveness)}>{runtime.liveness}</Badge></dd></div>
          <div className="p-4"><dt className="text-xs text-muted-foreground">Session</dt><dd className="mt-2 text-sm font-medium">{readableState(runtime.sessionState)}</dd></div>
          <div className="p-4"><dt className="text-xs text-muted-foreground">Traffic</dt><dd className="mt-2 text-sm font-medium">{runtime.trafficState}</dd></div>
          <div className="p-4"><dt className="text-xs text-muted-foreground">Observed endpoint</dt><dd className="mt-2 break-all font-mono text-xs">{runtime.observedEndpoint ?? "Not observed"}</dd></div>
          <div className="p-4"><dt className="text-xs text-muted-foreground">Authenticated RX</dt><dd className="mt-2 text-xs">{formatUtc(runtime.authenticatedRxAt)}</dd></div>
          <div className="p-4"><dt className="text-xs text-muted-foreground">Authenticated TX</dt><dd className="mt-2 text-xs">{formatUtc(runtime.authenticatedTxAt)}</dd></div>
        </dl>
      )}
    </section>
  );
}

export function NodeDetailWorkspace({ initialChecks, initialDetail, nodes, vnrs }: WorkspaceProps) {
  const detailPolling = usePolledResource<NodeDetail>(`/api/v1/nodes/${initialDetail.node.id}`, 10_000, initialDetail);
  const checksPolling = usePolledResource<ConnectivityCheckPage>(`/api/v1/connectivity-checks?limit=20&nodeId=${initialDetail.node.id}`, 10_000, initialChecks);
  const detail = detailPolling.data ?? initialDetail;
  const [olderChecks, setOlderChecks] = useState<readonly ConnectivityCheck[]>([]);
  const [nextChecksCursor, setNextChecksCursor] = useState<string | null>(initialChecks.nextCursor);
  const [loadingChecks, setLoadingChecks] = useState(false);
  const [checksError, setChecksError] = useState<string | null>(null);
  const checks = useMemo(() => {
    const current = checksPolling.data?.items ?? initialChecks.items;
    const ids = new Set(current.map((check) => check.id));
    return [...current, ...olderChecks.filter((check) => !ids.has(check.id))];
  }, [checksPolling.data, initialChecks.items, olderChecks]);

  async function loadOlderChecks() {
    if (nextChecksCursor === null || loadingChecks) return;
    setLoadingChecks(true);
    setChecksError(null);
    try {
      const page = await fetchJson<ConnectivityCheckPage>(`/api/v1/connectivity-checks?limit=20&nodeId=${detail.node.id}&cursor=${encodeURIComponent(nextChecksCursor)}`);
      setOlderChecks((current) => [...current, ...page.items]);
      setNextChecksCursor(page.nextCursor);
    } catch (reason) {
      setChecksError(reason instanceof Error ? reason.message : "Could not load older checks");
    } finally {
      setLoadingChecks(false);
    }
  }

  const stale = detailPolling.freshness !== "fresh" || checksPolling.freshness !== "fresh";
  const staleMessage = detailPolling.error ?? checksPolling.error;

  return (
    <div className="space-y-5 p-5">
      <div className="flex items-start justify-between gap-6">
        <div>
          <Link href="/nodes" className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"><ArrowLeft aria-hidden="true" className="size-3.5" />Node register</Link>
          <div className="mt-2 flex items-center gap-3"><h2 className="text-xl font-semibold tracking-tight">{detail.node.name}</h2><Badge tone={enrollmentTone(detail.node.enrollmentState)}>{readableState(detail.node.enrollmentState)}</Badge>{detail.runtime === null ? null : <Badge tone={livenessTone(detail.runtime.liveness)}>{detail.runtime.liveness}</Badge>}</div>
          <p className="mt-1 font-mono text-xs text-muted-foreground" title={detail.node.id}>id:{detail.node.id}</p>
        </div>
        <div className="flex flex-wrap justify-end gap-2">
          <UpdateNodeDialog detail={detail} vnrs={vnrs} onChanged={detailPolling.refresh} />
          <ConnectivityDialog node={detail.node} onCreated={checksPolling.refresh} />
          <EnrollmentDialog node={detail.node} operation="issue" onChanged={detailPolling.refresh} />
          <EnrollmentDialog node={detail.node} operation="reset" onChanged={detailPolling.refresh} />
          <DeleteNodeDialog node={detail.node} />
        </div>
      </div>

      {stale ? (
        <Alert tone="warning"><RefreshCw aria-hidden="true" /><AlertTitle>Last-known-good data</AlertTitle><AlertDescription>{staleMessage ?? "The operational view is refreshing. Existing values remain visible."}</AlertDescription></Alert>
      ) : null}

      <div className="grid grid-cols-[minmax(0,1fr)_minmax(23rem,0.72fr)] gap-5">
        <section className="border border-border bg-card" aria-labelledby="identity-title">
          <header className="flex h-11 items-center gap-2 border-b border-border px-4"><KeyRound aria-hidden="true" className="size-4 text-primary" /><h3 id="identity-title" className="text-sm font-semibold">Identity and ownership</h3></header>
          <dl className="grid grid-cols-2 divide-x divide-y divide-border">
            <div className="p-4"><dt className="text-xs text-muted-foreground">Address</dt><dd className="mt-2 font-mono text-sm">{detail.node.address}</dd></div>
            <div className="p-4"><dt className="text-xs text-muted-foreground">VNR</dt><dd className="mt-2 text-sm font-medium"><Link href={`/vnrs/${encodeURIComponent(detail.node.vnrName)}`} className="hover:underline">{detail.node.vnrName}</Link></dd></div>
            <div className="p-4"><dt className="text-xs text-muted-foreground">Generation</dt><dd className="mt-2 font-mono text-sm tabular-nums">{detail.node.generation}</dd></div>
            <div className="p-4"><dt className="text-xs text-muted-foreground">Updated</dt><dd className="mt-2 text-xs">{formatUtc(detail.node.updatedAt)}</dd></div>
          </dl>
        </section>
        <RuntimePanel detail={detail} />
      </div>

      <section className="border border-border bg-card" aria-labelledby="owned-routes-title">
        <header className="flex h-12 items-center justify-between border-b border-border px-3"><div className="flex items-center gap-2"><RouteIcon aria-hidden="true" className="size-4 text-primary" /><h3 id="owned-routes-title" className="text-sm font-semibold">Owned routes</h3><span className="font-mono text-[0.6875rem] text-muted-foreground">{detail.routes.length}</span></div><CreateRouteDialog node={detail.node} onChanged={detailPolling.refresh} /></header>
        <Table>
          <TableHeader><TableRow><TableHead>Prefix</TableHead><TableHead>Owner</TableHead><TableHead>Generation</TableHead><TableHead>Updated</TableHead><TableHead className="w-24"><span className="sr-only">Actions</span></TableHead></TableRow></TableHeader>
          <TableBody>
            {detail.routes.map((route) => <TableRow key={route.id}><TableCell className="font-mono text-xs">{route.prefix}</TableCell><TableCell>{route.nodeName}<div className="font-mono text-[0.625rem] text-muted-foreground">{shortId(route.nodeId)}</div></TableCell><TableCell className="font-mono text-xs">{route.generation}</TableCell><TableCell className="text-xs">{formatUtc(route.updatedAt)}</TableCell><TableCell><div className="flex justify-end"><EditRouteDialog route={route} nodes={nodes.items} onChanged={detailPolling.refresh} /><DeleteRouteDialog route={route} onChanged={detailPolling.refresh} /></div></TableCell></TableRow>)}
            {detail.routes.length === 0 ? <TableRow><TableCell colSpan={5} className="h-20 text-center text-muted-foreground">This Node owns no routed prefixes.</TableCell></TableRow> : null}
          </TableBody>
        </Table>
      </section>

      <section className="border border-border bg-card" aria-labelledby="checks-title">
        <header className="flex h-12 items-center justify-between border-b border-border px-3"><div className="flex items-center gap-2"><Activity aria-hidden="true" className="size-4 text-primary" /><h3 id="checks-title" className="text-sm font-semibold">Connectivity checks</h3></div><div className="flex items-center gap-2"><Badge tone={checksPolling.freshness === "fresh" ? "healthy" : "warning"}>{checksPolling.freshness === "fresh" ? "Fresh" : "Stale"}</Badge><Button variant="ghost" size="icon" aria-label="Refresh checks" onClick={checksPolling.refresh}><RefreshCw aria-hidden="true" className={checksPolling.phase === "polling" ? "animate-spin" : undefined} /></Button></div></header>
        {checksError === null ? null : <Alert tone="critical" className="m-3"><AlertCircle aria-hidden="true" /><AlertDescription>{checksError}</AlertDescription></Alert>}
        <Table>
          <TableHeader><TableRow><TableHead>Status</TableHead><TableHead>Created</TableHead><TableHead>Duration</TableHead><TableHead>Round trip</TableHead><TableHead>Failure</TableHead><TableHead>ID</TableHead></TableRow></TableHeader>
          <TableBody>
            {checks.map((check) => <TableRow key={check.id}><TableCell><Badge tone={connectivityTone(check.status)}>{readableState(check.status)}</Badge></TableCell><TableCell className="text-xs">{formatUtc(check.createdAt)}</TableCell><TableCell className="font-mono text-xs">{check.timeoutMilliseconds} ms</TableCell><TableCell className="font-mono text-xs">{check.roundTripMilliseconds === null ? "Not available" : `${check.roundTripMilliseconds.toFixed(1)} ms`}</TableCell><TableCell className="text-xs text-muted-foreground">{check.failureCode ?? "None"}</TableCell><TableCell className="font-mono text-[0.6875rem]" title={check.id}>{shortId(check.id)}</TableCell></TableRow>)}
            {checks.length === 0 ? <TableRow><TableCell colSpan={6} className="h-20 text-center text-muted-foreground">No connectivity checks have been recorded for this Node.</TableCell></TableRow> : null}
          </TableBody>
        </Table>
        <footer className="flex h-12 items-center justify-between border-t border-border px-3"><span className="text-xs text-muted-foreground">Active results refresh every 10 seconds.</span>{nextChecksCursor === null ? <span className="text-xs text-muted-foreground">End of check history</span> : <Button variant="outline" size="sm" disabled={loadingChecks} onClick={() => void loadOlderChecks()}>{loadingChecks ? "Loading" : "Load more"}</Button>}</footer>
      </section>
    </div>
  );
}
