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
import { AlertCircle, ArrowRight, KeyRound, Plus, RefreshCw, Search, Server } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useAuth } from "@/components/auth-context";
import { BootstrapDisclosure } from "@/components/nodes/bootstrap-disclosure";
import {
  fieldError,
  InlineFieldError,
  inventoryFormErrorState,
  InventoryErrorSummary,
  type InventoryFormErrorState,
} from "@/components/network/inventory-form-errors";
import { NodeAddressSelect } from "@/components/network/segmented-network-input";
import { createMutationAttempt } from "@/lib/behavior/mutation";
import { fetchJson, fetchJsonWithEtag, reauthenticate } from "@/components/nodes/browser-api";
import {
  enrollmentTone,
  formatUtc,
  livenessTone,
  readableState,
  shortId,
} from "@/components/nodes/node-presenters";
import { useOperationalPolling, type OperationalPolling } from "@/components/nodes/use-operational-polling";
import {
  actionableApiError,
  BrowserApiError,
  readBrowserApiJson,
} from "@/lib/browser-api-error";
import {
  createNodeAddressAvailability,
  createNodeAddressSelection,
  selectNodeAddressOctet,
  type NodeAddressAvailability,
  type SegmentedIpv4Selection,
} from "@/lib/network/segmented-network";
import {
  buildNodeInstallationCommand,
  parseEnrollmentBootstrapConfig,
  parseNodeBootstrapDisclosure,
  shouldRecoverLostBootstrapResponse,
  type EnrollmentBootstrapConfig,
  type NodeBootstrapDisclosure,
} from "@/lib/node-bootstrap";

type Node = components["schemas"]["Node"];
type NodeBootstrapCreate = components["schemas"]["NodeBootstrapCreate"];
type NodeCreate = components["schemas"]["NodeCreate"];
type NodeDetail = components["schemas"]["NodeDetail"];
type NodePage = components["schemas"]["NodePage"];
type NodeRuntime = components["schemas"]["NodeRuntime"];
type NodeRuntimePage = components["schemas"]["NodeRuntimePage"];
type Topology = components["schemas"]["Topology"];
type Vnr = components["schemas"]["Vnr"];

type TopologyPhase = "idle" | "loading" | "ready" | "unavailable";

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

function isAbortError(reason: unknown): boolean {
  return reason instanceof DOMException && reason.name === "AbortError";
}

function addressSelection(
  topology: Topology,
  vnrName: string,
  preferredAddress: string | null = null,
): Readonly<{
  availability: NodeAddressAvailability;
  selection: SegmentedIpv4Selection;
}> {
  const availability = createNodeAddressAvailability({ topology, vnrName });
  return {
    availability,
    selection: createNodeAddressSelection(availability, preferredAddress),
  };
}

function nextAddressAfterConflict(topology: Topology, vnrName: string, rejectedAddress: string): string | null {
  const { availability, selection } = addressSelection(topology, vnrName, rejectedAddress);
  if (selection.value !== rejectedAddress) return selection.value;

  const lowest = createNodeAddressSelection(availability, null);
  if (lowest.value !== rejectedAddress) return lowest.value;

  // A just-refreshed projection should contain the winning allocation. If it
  // is briefly behind, skip the rejected address locally instead of offering
  // the same value again.
  for (let index = 3; index >= 0; index -= 1) {
    const octetIndex = index as 0 | 1 | 2 | 3;
    const currentOctet = selection.octets[octetIndex];
    if (currentOctet === null) continue;
    const nextOption = selection.octetOptions[octetIndex]
      .find((option) => option.status === "available" && option.value > currentOctet);
    if (nextOption !== undefined) {
      return selectNodeAddressOctet(availability, selection, octetIndex, nextOption.value).value;
    }
  }
  return null;
}

function CreateNodeDialog({ vnrs }: Readonly<{ vnrs: readonly Vnr[] }>) {
  const { auth, can } = useAuth();
  const router = useRouter();
  const canBootstrap = can("enrollment:manage");
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [name, setName] = useState("");
  const [vnrName, setVnrName] = useState("");
  const [address, setAddress] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [topology, setTopology] = useState<Topology | null>(null);
  const [topologyPhase, setTopologyPhase] = useState<TopologyPhase>("idle");
  const [topologyError, setTopologyError] = useState<string | null>(null);
  const [bootstrapConfig, setBootstrapConfig] = useState<EnrollmentBootstrapConfig | null>(null);
  const [bootstrapConfigPhase, setBootstrapConfigPhase] = useState<TopologyPhase>("idle");
  const [bootstrapConfigError, setBootstrapConfigError] = useState<string | null>(null);
  const [disclosure, setDisclosure] = useState<NodeBootstrapDisclosure | null>(null);
  const [lostNode, setLostNode] = useState<Node | null>(null);
  const [discardPending, setDiscardPending] = useState(false);
  const [discardError, setDiscardError] = useState<string | null>(null);
  const [formError, setFormError] = useState<InventoryFormErrorState | null>(null);
  const [announcement, setAnnouncement] = useState("");
  const [collisionNotice, setCollisionNotice] = useState<string | null>(null);
  const topologyAbortRef = useRef<AbortController | null>(null);
  const bootstrapConfigAbortRef = useRef<AbortController | null>(null);
  const errorSummaryRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (formError !== null) errorSummaryRef.current?.focus();
  }, [formError]);

  useEffect(() => () => {
    topologyAbortRef.current?.abort();
    topologyAbortRef.current = null;
    bootstrapConfigAbortRef.current?.abort();
    bootstrapConfigAbortRef.current = null;
  }, []);

  if (!can("inventory:write")) return null;

  function reset() {
    topologyAbortRef.current?.abort();
    topologyAbortRef.current = null;
    bootstrapConfigAbortRef.current?.abort();
    bootstrapConfigAbortRef.current = null;
    setName("");
    setVnrName("");
    setAddress(null);
    setPassword("");
    setConfirmation("");
    setTopology(null);
    setTopologyPhase("idle");
    setTopologyError(null);
    setBootstrapConfig(null);
    setBootstrapConfigPhase("idle");
    setBootstrapConfigError(null);
    setDisclosure(null);
    setLostNode(null);
    setDiscardPending(false);
    setDiscardError(null);
    setFormError(null);
    setAnnouncement("");
    setCollisionNotice(null);
  }

  async function refreshBootstrapConfig(): Promise<void> {
    if (!canBootstrap) return;
    bootstrapConfigAbortRef.current?.abort();
    const controller = new AbortController();
    bootstrapConfigAbortRef.current = controller;
    setBootstrapConfig(null);
    setBootstrapConfigError(null);
    setBootstrapConfigPhase("loading");
    try {
      const config = parseEnrollmentBootstrapConfig(
        await fetchJson<unknown>("/api/v1/enrollment/bootstrap-config", controller.signal),
      );
      if (controller.signal.aborted || bootstrapConfigAbortRef.current !== controller) return;
      setBootstrapConfig(config);
      setBootstrapConfigPhase("ready");
    } catch (reason) {
      if (isAbortError(reason) || bootstrapConfigAbortRef.current !== controller) return;
      setBootstrapConfig(null);
      setBootstrapConfigPhase("unavailable");
      setBootstrapConfigError(actionableApiError(reason, {
        resourceLabel: "Node installer configuration",
        includeRequestId: true,
      }));
    } finally {
      if (bootstrapConfigAbortRef.current === controller) bootstrapConfigAbortRef.current = null;
    }
  }

  async function refreshTopology(options: Readonly<{
    vnrName?: string;
    rejectedAddress?: string;
  }> = {}) {
    topologyAbortRef.current?.abort();
    const controller = new AbortController();
    topologyAbortRef.current = controller;
    setTopologyPhase("loading");
    setTopologyError(null);
    setTopology(null);
    setAddress(null);
    if (options.rejectedAddress === undefined) setCollisionNotice(null);
    setAnnouncement(options.rejectedAddress === undefined
      ? "Loading current VNRs and available Node addresses."
      : "The address was claimed by another Node. Refreshing available addresses.");

    try {
      const freshTopology = await fetchJson<Topology>("/api/v1/topology", controller.signal);
      if (controller.signal.aborted) return;

      const selectedVnrName = options.vnrName !== undefined && freshTopology.vnrs.some((vnr) => vnr.name === options.vnrName)
        ? options.vnrName
        : (freshTopology.vnrs[0]?.name ?? "");
      const selectedAddress = selectedVnrName.length === 0
        ? null
        : options.rejectedAddress === undefined
          ? addressSelection(freshTopology, selectedVnrName).selection.value
          : nextAddressAfterConflict(freshTopology, selectedVnrName, options.rejectedAddress);

      setTopology(freshTopology);
      setTopologyPhase("ready");
      setVnrName(selectedVnrName);
      setAddress(selectedAddress);

      if (selectedVnrName.length === 0) {
        setAnnouncement("No VNR is available. Create a VNR before adding a Node.");
      } else if (selectedAddress === null) {
        setAnnouncement(`${selectedVnrName} has no available Node addresses.`);
      } else if (options.rejectedAddress !== undefined) {
        const notice = `Address ${options.rejectedAddress} was allocated concurrently. The selection moved to ${selectedAddress}; review it and submit again.`;
        setCollisionNotice(notice);
        setAnnouncement(notice);
      } else {
        setAnnouncement(`Address ${selectedAddress} is selected as the lowest available address in ${selectedVnrName}.`);
      }
    } catch (reason) {
      if (isAbortError(reason)) return;
      setTopology(null);
      setTopologyPhase("unavailable");
      setVnrName("");
      setAddress(null);
      setTopologyError(actionableApiError(reason, {
        resourceLabel: "topology",
        includeRequestId: true,
      }));
      setAnnouncement("Current topology is unavailable. Node address selection is disabled.");
    } finally {
      if (topologyAbortRef.current === controller) topologyAbortRef.current = null;
    }
  }

  async function findNodeByExactName(requestedName: string): Promise<Node | null> {
    const seen = new Set<string>();
    let cursor: string | null = null;
    do {
      const suffix: string = cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`;
      const page: NodePage = await fetchJson<NodePage>(`/api/v1/nodes?limit=200${suffix}`);
      const existing = page.items.find((node) => node.name === requestedName);
      if (existing !== undefined) return existing;
      cursor = page.nextCursor;
      if (cursor !== null) {
        if (seen.has(cursor)) throw new Error("The Node cursor did not advance");
        seen.add(cursor);
      }
    } while (cursor !== null);
    return null;
  }

  function changeVnr(nextVnrName: string) {
    if (
      topology === null ||
      nextVnrName.length === 0 ||
      !topology.vnrs.some((vnr) => vnr.name === nextVnrName)
    ) return;
    try {
      const nextAddress = addressSelection(topology, nextVnrName).selection.value;
      setVnrName(nextVnrName);
      setAddress(nextAddress);
      setFormError(null);
      setCollisionNotice(null);
      setAnnouncement(nextAddress === null
        ? `${nextVnrName} has no available Node addresses.`
        : `Address ${nextAddress} is selected as the lowest available address in ${nextVnrName}.`);
    } catch (reason) {
      setTopology(null);
      setTopologyPhase("unavailable");
      setVnrName("");
      setAddress(null);
      setTopologyError(actionableApiError(reason, { resourceLabel: "topology" }));
      setAnnouncement("Current topology is unavailable. Node address selection is disabled.");
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (topologyPhase !== "ready" || topology === null || vnrName.length === 0 || address === null) return;
    const requestedName = name.trim();
    if (canBootstrap && (
      bootstrapConfig === null ||
      bootstrapConfigPhase !== "ready" ||
      confirmation !== requestedName
    )) return;
    setPending(true);
    setFormError(null);
    setCollisionNotice(null);
    setLostNode(null);
    setAnnouncement(canBootstrap ? "Confirming your password and creating the Node setup invitation." : "Creating Node inventory.");
    const body: NodeCreate = {
      name: requestedName,
      address,
      vnrName,
    };
    let provisioningDispatched = false;
    try {
      if (canBootstrap) {
        const currentPassword = password;
        setPassword("");
        await reauthenticate(auth.csrfToken, currentPassword);
      }
      const attempt = createMutationAttempt({
        method: "POST",
        url: canBootstrap ? "/api/v1/nodes/actions/bootstrap" : "/api/v1/nodes",
        csrfToken: auth.csrfToken,
        body: canBootstrap
          ? ({ ...body, confirmation: requestedName } satisfies NodeBootstrapCreate)
          : body,
        responseKind: canBootstrap ? "one-time" : "json",
      });
      const request = attempt.buildRequest();
      if (canBootstrap) provisioningDispatched = true;
      const response = await fetch(request);
      if (canBootstrap) {
        const created = parseNodeBootstrapDisclosure(await readBrowserApiJson<unknown>(response));
        setDisclosure(created);
        setAnnouncement("Node created. Save the installation command and one-time setup code.");
      } else {
        const node = await readBrowserApiJson<Node>(response);
        setOpen(false);
        router.push(`/nodes/${node.id}`);
        router.refresh();
      }
    } catch (reason) {
      if (canBootstrap && shouldRecoverLostBootstrapResponse(reason, provisioningDispatched)) {
        try {
          const existing = await findNodeByExactName(requestedName);
          if (existing !== null) {
            setLostNode(existing);
            setFormError(null);
            setAnnouncement("The Node exists, but its setup code was not received. Generate a replacement from the Node detail page.");
            return;
          }
        } catch {
          // Preserve the original failure when the recovery read is unavailable.
        }
      }
      setFormError(inventoryFormErrorState(reason, "Node"));
      setAnnouncement("Node was not created. Review the error summary and the marked fields.");
      const addressWasClaimed = reason instanceof BrowserApiError && (
        reason.code === "address_in_use" ||
        reason.violations.some((violation) => violation.field === "address" && violation.code === "address_in_use")
      );
      if (addressWasClaimed) {
        await refreshTopology({ vnrName: body.vnrName, rejectedAddress: body.address });
      }
    } finally {
      setPending(false);
    }
  }

  const nameViolation = fieldError(formError, "name");
  const vnrViolation = fieldError(formError, "vnrName") ?? fieldError(formError, "vnr");
  const addressViolation = collisionNotice === null ? fieldError(formError, "address") : null;
  const topologyReady = topologyPhase === "ready" && topology !== null;
  const exhausted = topologyReady && vnrName.length > 0 && address === null;
  const requestedName = name.trim();
  const bootstrapReady = !canBootstrap || (bootstrapConfigPhase === "ready" && bootstrapConfig !== null);
  const command = disclosure === null || bootstrapConfig === null
    ? null
    : buildNodeInstallationCommand(bootstrapConfig, disclosure.bootstrap.bootstrapId);

  function completeDisclosure(): void {
    if (disclosure === null) return;
    const nodeId = disclosure.node.id;
    setDisclosure(null);
    setBootstrapConfig(null);
    setOpen(false);
    router.push(`/nodes/${nodeId}`);
    router.refresh();
  }

  async function discardDisclosure(): Promise<void> {
    if (disclosure === null || discardPending) return;
    setDiscardPending(true);
    setDiscardError(null);
    try {
      const current = await fetchJsonWithEtag<NodeDetail>(`/api/v1/nodes/${disclosure.node.id}`);
      const attempt = createMutationAttempt({
        method: "DELETE",
        url: `/api/v1/nodes/${disclosure.node.id}/enrollment-bootstrap`,
        csrfToken: auth.csrfToken,
        ifMatch: current.etag,
        requiresIfMatch: true,
        body: { confirmation: disclosure.node.name },
      });
      const response = await fetch(attempt.buildRequest());
      await readBrowserApiJson<Node>(response);
      const nodeId = disclosure.node.id;
      setDisclosure(null);
      setBootstrapConfig(null);
      setOpen(false);
      router.push(`/nodes/${nodeId}`);
      router.refresh();
    } catch (reason) {
      setDiscardError(actionableApiError(reason, {
        resourceLabel: "setup invitation",
        includeRequestId: true,
      }));
    } finally {
      setDiscardPending(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (pending || disclosure !== null || discardPending) return;
        setOpen(nextOpen);
        if (nextOpen) {
          reset();
          void refreshTopology();
          void refreshBootstrapConfig();
        } else {
          reset();
        }
      }}
    >
      <DialogTrigger asChild>
        <Button disabled={vnrs.length === 0}><Plus aria-hidden="true" />Add Node</Button>
      </DialogTrigger>
      <DialogContent
        className={disclosure === null ? undefined : "max-h-[calc(100vh-2rem)] w-[min(46rem,calc(100vw-2rem))] overflow-y-auto [&>button:last-child]:hidden"}
        onEscapeKeyDown={(event) => { if (disclosure !== null) event.preventDefault(); }}
        onPointerDownOutside={(event) => { if (disclosure !== null) event.preventDefault(); }}
        onInteractOutside={(event) => { if (disclosure !== null) event.preventDefault(); }}
      >
        <DialogHeader>
          <DialogTitle>Create Node</DialogTitle>
          <DialogDescription>{canBootstrap
            ? "Create the inventory record and a short-lived setup invitation in one audited operation."
            : "Create the inventory record. A superuser must generate its setup invitation afterward."}</DialogDescription>
        </DialogHeader>
        {disclosure !== null && command !== null ? (
          <BootstrapDisclosure
            command={command}
            disclosure={disclosure}
            discardError={discardError}
            discardPending={discardPending}
            onComplete={completeDisclosure}
            onDiscard={() => void discardDisclosure()}
          />
        ) : lostNode !== null ? (
          <div className="grid gap-4">
            <Alert tone="warning" role="alert">
              <AlertCircle aria-hidden="true" />
              <AlertDescription>
                <strong>{lostNode.name}</strong> exists at <span className="font-mono">{lostNode.address}</span>, but the one-time setup response did not reach this browser. No duplicate was created. Open the Node and explicitly generate a replacement code.
              </AlertDescription>
            </Alert>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => { setOpen(false); reset(); }}>Close</Button>
              <Button type="button" onClick={() => { const nodeId = lostNode.id; setOpen(false); reset(); router.push(`/nodes/${nodeId}`); router.refresh(); }}>
                Open Node <ArrowRight aria-hidden="true" />
              </Button>
            </DialogFooter>
          </div>
        ) : (
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <InventoryErrorSummary ref={errorSummaryRef} error={formError} title="Node was not created" />
          <div className="grid gap-1.5">
            <Label htmlFor="node-name">Name</Label>
            <Input
              id="node-name"
              name="name"
              required
              maxLength={63}
              autoComplete="off"
              autoFocus
              placeholder="edge-berlin-01"
              value={name}
              disabled={pending}
              aria-invalid={nameViolation !== null || undefined}
              aria-describedby={nameViolation === null ? undefined : "node-name-error"}
              onChange={(event) => setName(event.target.value)}
            />
            <InlineFieldError id="node-name-error" violation={nameViolation} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="node-vnr">VNR</Label>
            <Select
              value={vnrName}
              onValueChange={changeVnr}
              disabled={!topologyReady || pending || topology.vnrs.length === 0}
              required
            >
              <SelectTrigger
                id="node-vnr"
                aria-invalid={vnrViolation !== null || undefined}
                aria-describedby={vnrViolation === null ? "node-vnr-help" : "node-vnr-help node-vnr-error"}
              >
                <SelectValue placeholder={topologyPhase === "loading" ? "Loading VNRs" : "Select a VNR"} />
              </SelectTrigger>
              <SelectContent>
                {topology?.vnrs.map((vnr) => <SelectItem key={vnr.name} value={vnr.name}>{vnr.name} · {vnr.cidr}</SelectItem>)}
              </SelectContent>
            </Select>
            <p id="node-vnr-help" className="text-xs text-muted-foreground">
              Address availability comes from a fresh topology snapshot each time this dialog opens.
            </p>
            <InlineFieldError id="node-vnr-error" violation={vnrViolation} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="node-address">Address</Label>
            {topologyPhase === "loading" ? (
              <div className="min-h-9 rounded-md border border-border bg-muted px-3 py-2 text-sm text-muted-foreground" role="status">
                Loading available addresses…
              </div>
            ) : topologyPhase === "unavailable" ? (
              <div className="min-h-9 rounded-md border border-warning-border bg-warning-muted px-3 py-2 text-sm text-muted-foreground" role="status">
                Address selection is unavailable until the topology can be loaded.
              </div>
            ) : !topologyReady || vnrName.length === 0 ? (
              <div className="min-h-9 rounded-md border border-border bg-muted px-3 py-2 text-sm text-muted-foreground" role="status">
                Select a VNR to choose an address.
              </div>
            ) : (
              <NodeAddressSelect
                id="node-address"
                ariaLabel="Node IPv4 address"
                ariaDescribedBy={addressViolation === null ? "node-address-help" : "node-address-help node-address-error"}
                topology={topology}
                vnrName={vnrName}
                value={address}
                onValueChange={setAddress}
                disabled={pending}
                invalid={addressViolation !== null}
                required
              />
            )}
            <p id="node-address-help" className="text-xs text-muted-foreground">
              {exhausted
                ? `${vnrName} has no free host address after reserving the network, Master, broadcast, and current Node allocations.`
                : address === null
                  ? "The lowest free host address is selected after a VNR is available."
                  : `${address} is the current lowest compatible free address.`}
            </p>
            <InlineFieldError id="node-address-error" violation={addressViolation} />
          </div>
          {canBootstrap ? (
            <>
              <div className="grid gap-1.5">
                <Label htmlFor="node-bootstrap-password">Current password</Label>
                <Input
                  id="node-bootstrap-password"
                  type="password"
                  autoComplete="current-password"
                  minLength={14}
                  maxLength={256}
                  required
                  value={password}
                  disabled={pending}
                  onChange={(event) => setPassword(event.target.value)}
                />
                <p className="text-xs text-muted-foreground">The password is sent only to reauthentication and is cleared before Node provisioning.</p>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="node-bootstrap-confirmation">Type “{requestedName || "the Node name"}”</Label>
                <Input
                  id="node-bootstrap-confirmation"
                  autoComplete="off"
                  required
                  value={confirmation}
                  disabled={pending || requestedName.length === 0}
                  onChange={(event) => setConfirmation(event.target.value)}
                  aria-describedby="node-bootstrap-confirmation-help"
                />
                <p id="node-bootstrap-confirmation-help" className="text-xs text-muted-foreground">Exact confirmation is required because the invitation is disclosed only once.</p>
              </div>
            </>
          ) : (
            <Alert tone="info">
              <KeyRound aria-hidden="true" />
              <AlertDescription>This creates inventory only. Ask a superuser to open the new Node and generate its setup code.</AlertDescription>
            </Alert>
          )}
          {topologyError === null ? null : (
            <Alert tone="warning">
              <AlertCircle aria-hidden="true" />
              <AlertDescription>{topologyError}</AlertDescription>
            </Alert>
          )}
          {collisionNotice === null ? null : (
            <Alert role="alert" tone="warning">
              <RefreshCw aria-hidden="true" />
              <AlertDescription>{collisionNotice}</AlertDescription>
            </Alert>
          )}
          {bootstrapConfigError === null ? null : (
            <Alert tone="warning">
              <AlertCircle aria-hidden="true" />
              <AlertDescription>{bootstrapConfigError} Setup invitation creation is disabled until it is available.</AlertDescription>
            </Alert>
          )}
          <p className="sr-only" aria-live="polite" aria-atomic="true">{collisionNotice === null ? announcement : ""}</p>
          <p className="sr-only" aria-live="assertive" aria-atomic="true">{collisionNotice ?? ""}</p>
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              disabled={pending}
              onClick={() => {
                setOpen(false);
                reset();
              }}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={pending || !topologyReady || !bootstrapReady || vnrName.length === 0 || address === null || (canBootstrap && (password.length < 14 || confirmation !== requestedName))}>
              {pending ? "Creating" : canBootstrap ? "Create Node and setup code" : "Create Node"}
            </Button>
          </DialogFooter>
        </form>
        )}
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
      setPageError(reason instanceof Error
        ? actionableApiError(reason, { resourceLabel: "Node list", includeRequestId: true })
        : "Could not load more Nodes");
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
