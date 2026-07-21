"use client";

import {
  Alert,
  AlertDescription,
  Badge,
  Button,
} from "@ntip/ui";
import { AlertCircle, Check, Copy, ShieldX, Terminal } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { formatUtc } from "@/components/nodes/node-presenters";
import type { NodeBootstrapDisclosure } from "@/lib/node-bootstrap";

type BootstrapDisclosureProps = Readonly<{
  command: string;
  disclosure: NodeBootstrapDisclosure;
  discardError: string | null;
  discardPending: boolean;
  onComplete: () => void;
  onDiscard: () => void;
}>;

function CopyValueButton({ label, value, onAnnounce }: Readonly<{
  label: string;
  value: string;
  onAnnounce: (message: string) => void;
}>) {
  const [copied, setCopied] = useState(false);

  async function copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      onAnnounce(`${label} copied.`);
      window.setTimeout(() => setCopied(false), 2_000);
    } catch {
      setCopied(false);
      onAnnounce(`Clipboard access was unavailable. Select the ${label.toLowerCase()} manually.`);
    }
  }

  return (
    <Button type="button" variant="outline" size="sm" onClick={() => void copy()}>
      {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
      {copied ? "Copied" : `Copy ${label.toLowerCase()}`}
    </Button>
  );
}

export function BootstrapDisclosure({
  command,
  disclosure,
  discardError,
  discardPending,
  onComplete,
  onDiscard,
}: BootstrapDisclosureProps) {
  const [saved, setSaved] = useState(false);
  const [announcement, setAnnouncement] = useState("");
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  return (
    <div className="grid gap-5">
      <div>
        <div className="flex items-center gap-2">
          <Badge tone="healthy">Node created</Badge>
          <span className="font-mono text-[0.6875rem] text-muted-foreground">expires {formatUtc(disclosure.bootstrap.expiresAt)}</span>
        </div>
        <h3 ref={headingRef} tabIndex={-1} className="mt-3 text-base font-semibold outline-none">
          Install {disclosure.node.name}
        </h3>
        <p className="mt-1 text-sm leading-6 text-muted-foreground">
          This setup code is shown only once. Keep this dialog open until you have saved both values.
        </p>
      </div>

      <dl className="grid grid-cols-3 divide-x divide-border border border-border bg-card">
        <div className="p-3"><dt className="text-xs text-muted-foreground">Node</dt><dd className="mt-1 text-sm font-medium">{disclosure.node.name}</dd></div>
        <div className="p-3"><dt className="text-xs text-muted-foreground">VNR</dt><dd className="mt-1 text-sm font-medium">{disclosure.node.vnrName}</dd></div>
        <div className="p-3"><dt className="text-xs text-muted-foreground">Address</dt><dd className="mt-1 font-mono text-sm">{disclosure.node.address}</dd></div>
      </dl>

      <section className="grid gap-2" aria-labelledby="bootstrap-command-title">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h4 id="bootstrap-command-title" className="text-sm font-semibold">Installation command</h4>
            <p className="text-xs text-muted-foreground">Run this on the fresh Linux Node as a user with sudo access.</p>
          </div>
          <CopyValueButton label="Command" value={command} onAnnounce={setAnnouncement} />
        </div>
        <textarea
          readOnly
          rows={4}
          spellCheck={false}
          value={command}
          className="max-h-36 w-full resize-none overflow-auto whitespace-pre-wrap break-all border border-border bg-muted p-3 font-mono text-xs leading-5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label="Installation command; select to copy manually"
          onClick={(event) => event.currentTarget.select()}
          onFocus={(event) => event.currentTarget.select()}
        />
      </section>

      <section className="grid gap-2" aria-labelledby="bootstrap-code-title">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h4 id="bootstrap-code-title" className="text-sm font-semibold">Secret setup code</h4>
            <p className="text-xs text-muted-foreground">Enter this only when the installer prompts on the Node terminal.</p>
          </div>
          <CopyValueButton label="Setup code" value={disclosure.bootstrap.secretCode} onAnnounce={setAnnouncement} />
        </div>
        <input
          readOnly
          type="text"
          autoComplete="off"
          spellCheck={false}
          value={disclosure.bootstrap.secretCode}
          className="w-full border border-primary/40 bg-primary/5 px-4 py-3 text-center font-mono text-xl font-semibold tracking-[0.18em] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label="Secret setup code; select to copy manually"
          onClick={(event) => event.currentTarget.select()}
          onFocus={(event) => event.currentTarget.select()}
        />
      </section>

      {discardError === null ? null : (
        <Alert tone="critical" role="alert">
          <AlertCircle aria-hidden="true" />
          <AlertDescription>{discardError} The dialog remains open and the invitation may still be valid.</AlertDescription>
        </Alert>
      )}

      <label className="flex items-start gap-3 border border-border bg-card p-3 text-sm">
        <input
          type="checkbox"
          className="mt-0.5 size-4 accent-[var(--color-primary)]"
          checked={saved}
          disabled={discardPending}
          onChange={(event) => setSaved(event.target.checked)}
        />
        <span><span className="font-medium">I saved it securely.</span><span className="mt-0.5 block text-xs text-muted-foreground">Closing clears the code from this dashboard view.</span></span>
      </label>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <Button type="button" variant="quietDanger" disabled={discardPending} onClick={onDiscard}>
          <ShieldX aria-hidden="true" />
          {discardPending ? "Revoking" : "Discard and revoke"}
        </Button>
        <Button type="button" disabled={!saved || discardPending} onClick={onComplete}>
          <Terminal aria-hidden="true" />Done</Button>
      </div>
      <p className="sr-only" aria-live="polite" aria-atomic="true">{announcement}</p>
    </div>
  );
}
