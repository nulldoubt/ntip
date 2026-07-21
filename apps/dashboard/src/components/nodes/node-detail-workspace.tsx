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
import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useAuth } from "@/components/auth-context";
import { BootstrapDisclosure } from "@/components/nodes/bootstrap-disclosure";
import {
  fieldError,
  InlineFieldError,
  InventoryErrorSummary,
  inventoryFormErrorState,
  type InventoryFormErrorState,
} from "@/components/network/inventory-form-errors";
import { NodeAddressSelect, SegmentedCidrSelect } from "@/components/network/segmented-network-input";
import {
  fetchJson,
  fetchJsonWithEtag,
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
import { actionableApiError, BrowserApiError, readBrowserApiJson } from "@/lib/browser-api-error";
import {
  createCidrSelection,
  createEmptyCidrSelection,
  createNodeAddressAvailability,
  createNodeAddressSelection,
  type SegmentedCidrSelection,
} from "@/lib/network/segmented-network";
import { usePolledResource } from "@/lib/use-polled-resource";
import {
  bootstrapActionLabel,
  buildNodeInstallationCommand,
  parseEnrollmentBootstrapConfig,
  parseNodeBootstrapDisclosure,
  type EnrollmentBootstrapConfig,
  type NodeBootstrapDisclosure,
} from "@/lib/node-bootstrap";

type ConnectivityCheck = components["schemas"]["ConnectivityCheck"];
type ConnectivityCheckCreate = components["schemas"]["ConnectivityCheckCreate"];
type ConnectivityCheckPage = components["schemas"]["ConnectivityCheckPage"];
type DangerousConfirmation = components["schemas"]["DangerousConfirmation"];
type Node = components["schemas"]["Node"];
type NodeDetail = components["schemas"]["NodeDetail"];
type NodePage = components["schemas"]["NodePage"];
type NodeUpdate = components["schemas"]["NodeUpdate"];
type Route = components["schemas"]["Route"];
type RouteCreate = components["schemas"]["RouteCreate"];
type RouteUpdate = components["schemas"]["RouteUpdate"];
type Topology = components["schemas"]["Topology"];
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

function nodeOperationError(reason: unknown, resourceLabel: string, fallback: string): string {
  if (!(reason instanceof Error)) return fallback;
  return actionableApiError(reason, { resourceLabel, includeRequestId: true });
}

function isAbortError(reason: unknown): boolean {
  return reason instanceof DOMException && reason.name === "AbortError";
}

function Field({ label, htmlFor, children, hint, hintId }: Readonly<{
  label: string;
  htmlFor: string;
  children: ReactNode;
  hint?: string;
  hintId?: string;
}>) {
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {hint === undefined ? null : <p id={hintId} className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

function UpdateNodeDialog({ detail, vnrs, onChanged }: Readonly<{ detail: NodeDetail; vnrs: readonly Vnr[]; onChanged: () => void }>) {
  const { auth, can } = useAuth();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<InventoryFormErrorState | null>(null);
  const [topology, setTopology] = useState<Topology | null>(null);
  const [topologyPhase, setTopologyPhase] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [topologyError, setTopologyError] = useState<string | null>(null);
  const [vnrName, setVnrName] = useState(detail.node.vnrName);
  const [address, setAddress] = useState<string | null>(detail.node.address);
  const [unavailableAddress, setUnavailableAddress] = useState<string | null>(null);
  const [associationNotice, setAssociationNotice] = useState<string | null>(null);
  const [collisionNotice, setCollisionNotice] = useState<string | null>(null);
  const errorSummaryRef = useRef<HTMLDivElement>(null);
  const topologyRequest = useRef(0);

  useEffect(() => {
    if (error !== null) errorSummaryRef.current?.focus();
  }, [error]);

  const selectorTopology = useMemo((): Topology | null => {
    if (topology === null || unavailableAddress === null) return topology;
    return {
      ...topology,
      nodes: [...topology.nodes, {
        ...detail.node,
        id: "__concurrent_allocation__",
        address: unavailableAddress,
      }],
    };
  }, [detail.node, topology, unavailableAddress]);

  if (!can("inventory:write")) return null;

  async function refreshTopology(
    targetVnrName: string,
    preferredAddress: string | null,
    knownUnavailableAddress: string | null = null,
  ): Promise<string | null | undefined> {
    const request = ++topologyRequest.current;
    setTopologyPhase("loading");
    setTopologyError(null);
    try {
      const fresh = await fetchJson<Topology>("/api/v1/topology");
      if (request !== topologyRequest.current) return undefined;
      const targetVnr = fresh.vnrs.find((vnr) => vnr.name === targetVnrName) ?? fresh.vnrs[0];
      if (targetVnr === undefined) {
        setTopology(fresh);
        setVnrName("");
        setAddress(null);
        setTopologyPhase("ready");
        return null;
      }
      const availabilityTopology: Topology = knownUnavailableAddress === null
        ? fresh
        : {
            ...fresh,
            nodes: [...fresh.nodes, {
              ...detail.node,
              id: "__concurrent_allocation__",
              address: knownUnavailableAddress,
            }],
          };
      const availability = createNodeAddressAvailability({
        topology: availabilityTopology,
        vnrName: targetVnr.name,
        currentNodeId: detail.node.id,
      });
      const selected = createNodeAddressSelection(availability, preferredAddress).value;
      setTopology(fresh);
      setVnrName(targetVnr.name);
      setAddress(selected);
      setTopologyPhase("ready");
      return selected;
    } catch (reason) {
      if (request !== topologyRequest.current) return undefined;
      setTopology(null);
      setAddress(null);
      setTopologyPhase("error");
      setTopologyError(actionableApiError(reason));
      return undefined;
    }
  }

  function changeOpen(next: boolean) {
    if (pending) return;
    setOpen(next);
    setError(null);
    setAssociationNotice(null);
    setCollisionNotice(null);
    setUnavailableAddress(null);
    if (next) {
      setVnrName(detail.node.vnrName);
      setAddress(detail.node.address);
      void refreshTopology(detail.node.vnrName, detail.node.address);
    } else {
      topologyRequest.current += 1;
      setTopology(null);
      setTopologyPhase("idle");
      setTopologyError(null);
    }
  }

  function changeVnr(nextVnrName: string) {
    if (
      topology === null ||
      nextVnrName.length === 0 ||
      !topology.vnrs.some((vnr) => vnr.name === nextVnrName)
    ) return;
    setVnrName(nextVnrName);
    setError(null);
    setCollisionNotice(null);
    setUnavailableAddress(null);
    const availability = createNodeAddressAvailability({
      topology,
      vnrName: nextVnrName,
      currentNodeId: detail.node.id,
    });
    const nextAddress = createNodeAddressSelection(availability).value;
    setAddress(nextAddress);
    setAssociationNotice(nextVnrName === detail.node.vnrName
      ? null
      : nextAddress === null
        ? `Moving this Node to ${nextVnrName} would retire its current association, but the destination VNR has no free address.`
        : `Moving this Node to ${nextVnrName} retires its current association. Address ${nextAddress} is selected as the destination VNR’s lowest free host.`);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (address === null || topologyPhase !== "ready") return;
    setPending(true);
    setError(null);
    setCollisionNotice(null);
    const data = new FormData(event.currentTarget);
    const body: NodeUpdate = {
      name: String(data.get("name") ?? "").trim(),
      address,
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
      setError(inventoryFormErrorState(reason, "Node"));
      const collision = reason instanceof BrowserApiError &&
        reason.violations.some((violation) => violation.code === "address_in_use");
      if (collision) {
        setUnavailableAddress(address);
        const replacement = await refreshTopology(vnrName, null, address);
        if (replacement !== undefined) {
          setCollisionNotice(replacement === null
            ? `Address ${address} was allocated concurrently, and this VNR now has no free Node address.`
            : `Address ${address} was allocated concurrently. The selection moved to ${replacement}; review it and submit again.`);
        }
      }
    } finally {
      setPending(false);
    }
  }

  const nameViolation = fieldError(error, "name");
  const addressViolation = collisionNotice === null ? fieldError(error, "address") : null;
  const availableVnrs = topology?.vnrs ?? vnrs;

  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogTrigger asChild><Button variant="outline"><Pencil aria-hidden="true" />Edit Node</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Edit {detail.node.name}</DialogTitle><DialogDescription>A fresh topology snapshot limits address choices; a current read supplies the update precondition.</DialogDescription></DialogHeader>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <InventoryErrorSummary ref={errorSummaryRef} error={error} title="Node was not updated" />
          <Field label="Name" htmlFor="edit-node-name">
            <Input
              id="edit-node-name"
              name="name"
              required
              defaultValue={detail.node.name}
              autoComplete="off"
              disabled={pending}
              aria-invalid={nameViolation !== null || undefined}
              aria-describedby={nameViolation === null ? undefined : "edit-node-name-error"}
            />
            <InlineFieldError id="edit-node-name-error" violation={nameViolation} />
          </Field>
          <Field label="VNR" htmlFor="edit-node-vnr">
            <Select value={vnrName} onValueChange={changeVnr} disabled={pending || topologyPhase !== "ready"}>
              <SelectTrigger id="edit-node-vnr"><SelectValue /></SelectTrigger>
              <SelectContent>{availableVnrs.map((vnr) => <SelectItem key={vnr.name} value={vnr.name}>{vnr.name} · {vnr.cidr}</SelectItem>)}</SelectContent>
            </Select>
          </Field>
          <Field label="Address" htmlFor="edit-node-address">
            {selectorTopology === null || vnrName.length === 0 ? (
              <div id="edit-node-address" role="status" aria-live="polite" className="border border-dashed border-border px-3 py-2 text-sm text-muted-foreground">
                {topologyPhase === "loading" ? "Loading current address availability…" : "Address choices are unavailable."}
              </div>
            ) : (
              <NodeAddressSelect
                id="edit-node-address"
                ariaLabel="Node IPv4 address"
                ariaDescribedBy={`edit-node-address-help${addressViolation === null ? "" : " edit-node-address-error"}`}
                currentNodeId={detail.node.id}
                topology={selectorTopology}
                vnrName={vnrName}
                value={address}
                onValueChange={setAddress}
                invalid={addressViolation !== null}
                disabled={pending}
                required
              />
            )}
            <p id="edit-node-address-help" className="text-xs text-muted-foreground">
              Network, Master, broadcast, and allocated addresses are unavailable.
            </p>
            <InlineFieldError id="edit-node-address-error" violation={addressViolation} />
          </Field>
          {topologyError === null ? null : <Alert tone="warning"><AlertCircle aria-hidden="true" /><AlertDescription>{topologyError}</AlertDescription></Alert>}
          {address === null && topologyPhase === "ready" ? <Alert tone="warning"><AlertCircle aria-hidden="true" /><AlertDescription>The selected VNR has no free Node address.</AlertDescription></Alert> : null}
          {associationNotice === null ? null : <Alert tone="info" aria-live="polite"><Unplug aria-hidden="true" /><AlertDescription>{associationNotice}</AlertDescription></Alert>}
          {collisionNotice === null ? null : <Alert role="alert" tone="warning"><RefreshCw aria-hidden="true" /><AlertDescription>{collisionNotice}</AlertDescription></Alert>}
          <DialogFooter><Button type="button" variant="ghost" disabled={pending} onClick={() => changeOpen(false)}>Cancel</Button><Button type="submit" disabled={pending || topologyPhase !== "ready" || address === null}>{pending ? "Saving" : "Save changes"}</Button></DialogFooter>
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
      setError(nodeOperationError(reason, "connectivity check", "Connectivity check could not be started"));
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

function EnrollmentBootstrapDialog({ node, onChanged }: Readonly<{ node: Node; onChanged: () => void }>) {
  const { auth, can } = useAuth();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [operation, setOperation] = useState<Readonly<{
    enrollmentState: Node["enrollmentState"];
    generation: number;
    label: string;
    nodeId: string;
    nodeName: string;
    resetsEnrollment: boolean;
  }> | null>(null);
  const [config, setConfig] = useState<EnrollmentBootstrapConfig | null>(null);
  const [configPending, setConfigPending] = useState(false);
  const [disclosure, setDisclosure] = useState<NodeBootstrapDisclosure | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [discardPending, setDiscardPending] = useState(false);
  const [discardError, setDiscardError] = useState<string | null>(null);
  const configAbortRef = useRef<AbortController | null>(null);

  useEffect(() => () => {
    configAbortRef.current?.abort();
    configAbortRef.current = null;
  }, []);

  if (!can("enrollment:manage")) return null;

  const actionLabel = operation?.label ?? bootstrapActionLabel(node);
  const resetsEnrollment = operation?.resetsEnrollment ?? node.enrollmentState === "enrolled";
  const confirmationName = operation?.nodeName ?? node.name;
  const command = disclosure === null || config === null
    ? null
    : buildNodeInstallationCommand(config, disclosure.bootstrap.bootstrapId);

  function clearSecretState(): void {
    configAbortRef.current?.abort();
    configAbortRef.current = null;
    setPassword("");
    setConfirmation("");
    setOperation(null);
    setDisclosure(null);
    setConfig(null);
    setConfigPending(false);
    setDiscardError(null);
  }

  async function loadConfig(): Promise<void> {
    configAbortRef.current?.abort();
    const controller = new AbortController();
    configAbortRef.current = controller;
    setConfigPending(true);
    setError(null);
    try {
      const loaded = parseEnrollmentBootstrapConfig(
        await fetchJson<unknown>("/api/v1/enrollment/bootstrap-config", controller.signal),
      );
      if (controller.signal.aborted || configAbortRef.current !== controller) return;
      setConfig(loaded);
    } catch (reason) {
      if (isAbortError(reason) || configAbortRef.current !== controller) return;
      setConfig(null);
      setError(nodeOperationError(reason, "Node installer configuration", "Installer configuration could not be loaded"));
    } finally {
      if (configAbortRef.current === controller) {
        configAbortRef.current = null;
        setConfigPending(false);
      }
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const intent = operation;
    if (config === null || intent === null || confirmation !== intent.nodeName) return;
    setPending(true);
    setError(null);
    const currentPassword = password;
    setPassword("");
    let invitationDispatched = false;
    try {
      await reauthenticate(auth.csrfToken, currentPassword);
      const current = await fetchJsonWithEtag<NodeDetail>(`/api/v1/nodes/${intent.nodeId}`);
      if (
        current.data.node.id !== intent.nodeId ||
        current.data.node.name !== intent.nodeName ||
        current.data.node.enrollmentState !== intent.enrollmentState ||
        current.data.node.generation !== intent.generation
      ) {
        setError("The Node changed while this confirmation was open. Review the refreshed enrollment state and try again.");
        onChanged();
        return;
      }
      const body: DangerousConfirmation = { confirmation: intent.nodeName };
      const attempt = createMutationAttempt({
        method: "POST",
        url: intent.resetsEnrollment
          ? `/api/v1/nodes/${intent.nodeId}/actions/reset-enrollment`
          : `/api/v1/nodes/${intent.nodeId}/enrollment-bootstrap`,
        csrfToken: auth.csrfToken,
        ifMatch: current.etag,
        requiresIfMatch: true,
        responseKind: "one-time",
        body,
      });
      const request = attempt.buildRequest();
      invitationDispatched = true;
      const response = await fetch(request);
      const created = parseNodeBootstrapDisclosure(await readBrowserApiJson<unknown>(response));
      setDisclosure(created);
      onChanged();
    } catch (reason) {
      const message = nodeOperationError(reason, "Node setup invitation", "Setup invitation could not be generated");
      setError(invitationDispatched
        ? `${message} The one-time request was not retried. If the Node now shows a pending credential, generate a replacement.`
        : message);
      if (invitationDispatched) onChanged();
    } finally {
      setPending(false);
    }
  }

  function complete(): void {
    clearSecretState();
    setOpen(false);
    onChanged();
  }

  async function discard(): Promise<void> {
    if (disclosure === null || discardPending) return;
    setDiscardPending(true);
    setDiscardError(null);
    try {
      const current = await fetchJsonWithEtag<NodeDetail>(`/api/v1/nodes/${node.id}`);
      const attempt = createMutationAttempt({
        method: "DELETE",
        url: `/api/v1/nodes/${node.id}/enrollment-bootstrap`,
        csrfToken: auth.csrfToken,
        ifMatch: current.etag,
        requiresIfMatch: true,
        body: { confirmation: node.name },
      });
      const response = await fetch(attempt.buildRequest());
      await readBrowserApiJson<Node>(response);
      clearSecretState();
      setOpen(false);
      onChanged();
    } catch (reason) {
      setDiscardError(nodeOperationError(reason, "setup invitation", "The setup invitation could not be revoked"));
    } finally {
      setDiscardPending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => {
      if (pending || disclosure !== null || discardPending) return;
      setOpen(next);
      clearSecretState();
      setError(null);
      if (next) {
        setOperation({
          enrollmentState: node.enrollmentState,
          generation: node.generation,
          label: bootstrapActionLabel(node),
          nodeId: node.id,
          nodeName: node.name,
          resetsEnrollment: node.enrollmentState === "enrolled",
        });
        void loadConfig();
      } else {
        setOperation(null);
      }
    }}>
      <DialogTrigger asChild>
        <Button variant={resetsEnrollment ? "outline" : "default"}><KeyRound aria-hidden="true" />{actionLabel}</Button>
      </DialogTrigger>
      <DialogContent
        className={disclosure === null ? undefined : "max-h-[calc(100vh-2rem)] w-[min(46rem,calc(100vw-2rem))] overflow-y-auto [&>button:last-child]:hidden"}
        onEscapeKeyDown={(event) => { if (disclosure !== null) event.preventDefault(); }}
        onPointerDownOutside={(event) => { if (disclosure !== null) event.preventDefault(); }}
        onInteractOutside={(event) => { if (disclosure !== null) event.preventDefault(); }}
      >
        <DialogHeader>
          <DialogTitle>{actionLabel}</DialogTitle>
          <DialogDescription>{resetsEnrollment
            ? "Retire the enrolled identity, then disclose a new short-lived setup invitation once."
            : "Generate a short-lived setup invitation. Any unused predecessor is revoked atomically."}</DialogDescription>
        </DialogHeader>
        {disclosure !== null && command !== null ? (
          <BootstrapDisclosure
            command={command}
            disclosure={disclosure}
            discardError={discardError}
            discardPending={discardPending}
            onComplete={complete}
            onDiscard={() => void discard()}
          />
        ) : (
          <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
            <FormError>{error}</FormError>
            <Alert tone="warning"><ShieldAlert aria-hidden="true" /><AlertDescription>Reauthentication and a fresh resource ETag are required. Type the exact Node name to continue.</AlertDescription></Alert>
            <Field label="Current password" htmlFor="bootstrap-password"><Input id="bootstrap-password" type="password" minLength={14} maxLength={256} autoComplete="current-password" required value={password} disabled={pending} onChange={(event) => setPassword(event.target.value)} /></Field>
            <Field label={`Type “${confirmationName}”`} htmlFor="bootstrap-confirmation"><Input id="bootstrap-confirmation" autoComplete="off" required value={confirmation} disabled={pending} onChange={(event) => setConfirmation(event.target.value)} /></Field>
            <DialogFooter><Button type="button" variant="ghost" disabled={pending} onClick={() => { setOpen(false); clearSecretState(); }}>Cancel</Button><Button type="submit" variant={resetsEnrollment ? "destructive" : "default"} disabled={pending || configPending || config === null || password.length < 14 || confirmation !== confirmationName}>{pending ? "Authorizing" : actionLabel}</Button></DialogFooter>
          </form>
        )}
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
      setError(nodeOperationError(reason, "Node", "Node deletion failed"));
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
  const [prefix, setPrefix] = useState<SegmentedCidrSelection>(() => createEmptyCidrSelection("route"));
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<InventoryFormErrorState | null>(null);
  const errorSummaryRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (error !== null) errorSummaryRef.current?.focus();
  }, [error]);

  if (!can("inventory:write")) return null;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (prefix.value === null) return;
    setPending(true);
    setError(null);
    const body: RouteCreate = { nodeId: node.id, prefix: prefix.value };
    try {
      const attempt = createMutationAttempt({ method: "POST", url: "/api/v1/routes", csrfToken: auth.csrfToken, body });
      const response = await fetch(attempt.buildRequest());
      if (!response.ok) throw await responseError(response);
      setOpen(false);
      onChanged();
    } catch (reason) {
      setError(inventoryFormErrorState(reason, "route"));
    } finally {
      setPending(false);
    }
  }

  const prefixViolation = fieldError(error, "prefix");

  return (
    <Dialog open={open} onOpenChange={(next) => {
      if (pending) return;
      setOpen(next);
      setError(null);
      setPrefix(createEmptyCidrSelection("route"));
    }}>
      <DialogTrigger asChild><Button size="sm"><Plus aria-hidden="true" />Add route</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Add route</DialogTitle><DialogDescription>The prefix will be owned by {node.name}. Overlap and reserved-address invariants are checked transactionally.</DialogDescription></DialogHeader>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <InventoryErrorSummary ref={errorSummaryRef} error={error} title="Route was not created" />
          <Field label="IPv4 prefix" htmlFor="create-route-prefix" hintId="create-route-prefix-help" hint="Select four octets and an explicit /1–/32 prefix. Host bits must be zero for the selected prefix.">
            <SegmentedCidrSelect
              id="create-route-prefix"
              ariaLabel="Route IPv4 prefix"
              ariaDescribedBy={`create-route-prefix-help${prefixViolation === null ? "" : " create-route-prefix-error"}`}
              invalid={prefixViolation !== null}
              disabled={pending}
              required
              selection={prefix}
              onSelectionChange={setPrefix}
            />
            <InlineFieldError id="create-route-prefix-error" violation={prefixViolation} />
          </Field>
          <DialogFooter><Button type="button" variant="ghost" disabled={pending} onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" disabled={pending || prefix.value === null}>{pending ? "Adding" : "Add route"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function EditRouteDialog({ route, nodes, onChanged }: Readonly<{ route: Route; nodes: readonly Node[]; onChanged: () => void }>) {
  const { auth, can } = useAuth();
  const [open, setOpen] = useState(false);
  const [ownerId, setOwnerId] = useState(route.nodeId);
  const [prefix, setPrefix] = useState<SegmentedCidrSelection>(() => createCidrSelection(route.prefix, "route"));
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<InventoryFormErrorState | null>(null);
  const errorSummaryRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (error !== null) errorSummaryRef.current?.focus();
  }, [error]);

  if (!can("inventory:write")) return null;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (prefix.value === null) return;
    setPending(true);
    setError(null);
    const body: RouteUpdate = { prefix: prefix.value, nodeId: ownerId };
    try {
      const current = await fetchJsonWithEtag<Route>(`/api/v1/routes/${route.id}`);
      const attempt = createMutationAttempt({ method: "PATCH", url: `/api/v1/routes/${route.id}`, csrfToken: auth.csrfToken, ifMatch: current.etag, requiresIfMatch: true, body });
      const response = await fetch(attempt.buildRequest());
      if (!response.ok) throw await responseError(response);
      setOpen(false);
      onChanged();
    } catch (reason) {
      setError(inventoryFormErrorState(reason, "route"));
    } finally {
      setPending(false);
    }
  }

  const prefixViolation = fieldError(error, "prefix");

  return (
    <Dialog open={open} onOpenChange={(next) => {
      if (pending) return;
      setOpen(next);
      setError(null);
      setOwnerId(route.nodeId);
      setPrefix(createCidrSelection(route.prefix, "route"));
    }}>
      <DialogTrigger asChild><Button size="icon" variant="ghost" aria-label={`Edit route ${route.prefix}`}><Pencil aria-hidden="true" /></Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Edit route</DialogTitle><DialogDescription>A current route read supplies the ETag before the update commits.</DialogDescription></DialogHeader>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <InventoryErrorSummary ref={errorSummaryRef} error={error} title="Route was not updated" />
          <Field label="IPv4 prefix" htmlFor={`edit-route-prefix-${route.id}`} hintId={`edit-route-prefix-help-${route.id}`} hint="Changing the prefix keeps the selected octets visible and blocks a noncanonical boundary.">
            <SegmentedCidrSelect
              id={`edit-route-prefix-${route.id}`}
              ariaLabel={`Route ${route.prefix} IPv4 prefix`}
              ariaDescribedBy={`edit-route-prefix-help-${route.id}${prefixViolation === null ? "" : ` edit-route-prefix-error-${route.id}`}`}
              invalid={prefixViolation !== null}
              disabled={pending}
              required
              selection={prefix}
              onSelectionChange={setPrefix}
            />
            <InlineFieldError id={`edit-route-prefix-error-${route.id}`} violation={prefixViolation} />
          </Field>
          <Field label="Owner" htmlFor={`edit-route-owner-${route.id}`}>
            <Select value={ownerId} onValueChange={setOwnerId} disabled={pending}><SelectTrigger id={`edit-route-owner-${route.id}`}><SelectValue /></SelectTrigger><SelectContent>{nodes.map((node) => <SelectItem key={node.id} value={node.id}>{node.name} · {node.address}</SelectItem>)}</SelectContent></Select>
          </Field>
          <DialogFooter><Button type="button" variant="ghost" disabled={pending} onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" disabled={pending || prefix.value === null || (prefix.value === route.prefix && ownerId === route.nodeId)}>{pending ? "Saving" : "Save route"}</Button></DialogFooter>
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
      setError(nodeOperationError(reason, "route", "Route deletion failed"));
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
      setChecksError(nodeOperationError(reason, "connectivity checks", "Could not load older checks"));
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
          <EnrollmentBootstrapDialog node={detail.node} onChanged={detailPolling.refresh} />
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
