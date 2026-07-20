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
  Tabs,
  TabsList,
  TabsTrigger,
} from "@ntip/ui";
import { CircleAlert, CircleCheck, KeyRound, LoaderCircle, LogOut, RefreshCw, ShieldCheck } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { useAuth } from "@/components/auth-context";
import { usePolledResource } from "@/lib/use-polled-resource";
import { securityGet, securityMutation } from "./security-api";

type Session = components["schemas"]["Session"];
type SessionPage = components["schemas"]["SessionPage"];

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" }).format(new Date(value));
}

function errorMessage(reason: unknown): string {
  return reason instanceof Error ? reason.message : "The request failed";
}

function mergeSessions(primary: readonly Session[], older: readonly Session[]): Session[] {
  const seen = new Set<string>();
  return [...primary, ...older].filter((session) => {
    if (seen.has(session.id)) return false;
    seen.add(session.id);
    return true;
  });
}

export function SessionsWorkspace({ initialSessions, initialScope }: Readonly<{ initialSessions: SessionPage; initialScope: "own" | "all" }>) {
  const { auth, can } = useAuth();
  const [scope, setScope] = useState<"own" | "all">(initialScope);

  const scopedInitial = scope === initialScope
    ? initialSessions
    : { items: initialSessions.items.filter((session) => session.userId === auth.user.id), nextCursor: null };

  return <div className="mx-auto w-full max-w-[104rem] p-5 lg:p-6">
    <div className="mb-5 flex items-start justify-between gap-6">
      <div><p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.12em] text-primary-strong">Session control</p><h2 className="mt-1 text-xl font-semibold tracking-tight">Web sessions</h2><p className="mt-1 max-w-2xl text-sm leading-6 text-muted-foreground">Review active browser sessions, revoke access, and change your own management password.</p></div>
    </div>

    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <section aria-labelledby="session-list-heading">
        <div className="flex min-h-10 items-center border-b border-border">
          <div className="flex items-center gap-3"><h3 id="session-list-heading" className="text-sm font-semibold">Active sessions</h3>{can("sessions:manage-all") ? <Tabs value={scope} onValueChange={(value) => setScope(value as "own" | "all")}><TabsList className="border-0"><TabsTrigger value="own">Mine</TabsTrigger><TabsTrigger value="all">All users</TabsTrigger></TabsList></Tabs> : null}</div>
        </div>
        <SessionLedger key={scope} csrfToken={auth.csrfToken} initialSessions={scopedInitial} scope={scope} />
      </section>
      <ChangePassword csrfToken={auth.csrfToken} />
    </div>
  </div>;
}

function SessionLedger({ csrfToken, initialSessions, scope }: Readonly<{ csrfToken: string; initialSessions: SessionPage; scope: "own" | "all" }>) {
  const path = scope === "all" ? "/api/v1/sessions?scope=all&limit=50" as const : "/api/v1/sessions?scope=own&limit=50" as const;
  const polled = usePolledResource<SessionPage>(path, 30_000, initialSessions);
  const page = polled.data ?? initialSessions;
  const [older, setOlder] = useState<Session[]>([]);
  const [cursorOverride, setCursorOverride] = useState<string | null | undefined>(undefined);
  const [loadingMore, setLoadingMore] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const visibleSessions = useMemo(() => mergeSessions(page.items, older), [older, page.items]);
  const cursor = cursorOverride === undefined ? page.nextCursor : cursorOverride;

  async function loadMore() {
    if (cursor === null) return;
    setLoadingMore(true);
    setLoadError(null);
    try {
      const next = await securityGet<SessionPage>(`/api/v1/sessions?scope=${scope}&limit=50&cursor=${encodeURIComponent(cursor)}`);
      setOlder((current) => mergeSessions(current, next.items));
      setCursorOverride(next.nextCursor);
    } catch (reason) {
      setLoadError(errorMessage(reason));
    } finally {
      setLoadingMore(false);
    }
  }

  return <>
    <div className="flex min-h-9 items-center justify-end gap-3 border-b border-border text-xs text-muted-foreground" aria-live="polite"><span className={`size-1.5 rounded-full ${polled.error === null ? "bg-success" : "bg-warning"}`} />{polled.error ?? (polled.pauseReason === "offline" ? "Offline. Last known data." : "Poll 30s")}<Button type="button" size="sm" variant="ghost" onClick={() => polled.refresh()}><RefreshCw />Refresh</Button></div>
    {loadError !== null ? <Alert tone="critical" className="my-3"><CircleAlert /><AlertTitle>Older sessions not loaded</AlertTitle><AlertDescription>{loadError}</AlertDescription></Alert> : null}
    <div className="border-b border-border bg-card"><Table><TableHeader><TableRow><TableHead>User</TableHead><TableHead>Browser</TableHead><TableHead>Proxy peer</TableHead><TableHead>Last seen</TableHead><TableHead>Expires</TableHead><TableHead className="w-24"><span className="sr-only">Actions</span></TableHead></TableRow></TableHeader><TableBody>{visibleSessions.map((session) => <TableRow key={session.id}>
          <TableCell><div className="flex items-center gap-2"><span className="font-medium">{session.username}</span>{session.current ? <Badge tone="copper">current</Badge> : null}</div><div className="font-mono text-[0.6875rem] text-muted-foreground">{session.id}</div></TableCell>
          <TableCell className="max-w-64 truncate text-xs" title={session.userAgent ?? undefined}>{session.userAgent ?? "Not reported"}</TableCell>
          <TableCell className="font-mono text-xs text-muted-foreground">{session.proxyPeer ?? "loopback"}</TableCell>
          <TableCell className="whitespace-nowrap text-xs">{formatTimestamp(session.lastSeenAt)}</TableCell>
          <TableCell><div className="whitespace-nowrap text-xs">Idle {formatTimestamp(session.idleExpiresAt)}</div><div className="whitespace-nowrap text-[0.6875rem] text-muted-foreground">Absolute {formatTimestamp(session.absoluteExpiresAt)}</div></TableCell>
          <TableCell><RevokeSession session={session} csrfToken={csrfToken} onRevoked={() => polled.refresh()} /></TableCell>
        </TableRow>)}</TableBody></Table>{visibleSessions.length === 0 ? <div className="px-4 py-12 text-center text-sm text-muted-foreground">No sessions in this scope.</div> : null}</div>
    {cursor !== null ? <div className="flex justify-center pt-3"><Button variant="outline" size="sm" disabled={loadingMore} onClick={() => void loadMore()}>{loadingMore ? <LoaderCircle className="animate-spin" /> : null}Load more</Button></div> : null}
  </>;
}

function RevokeSession({ session, csrfToken, onRevoked }: Readonly<{ session: Session; csrfToken: string; onRevoked(): void }>) {
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function revoke() {
    setPending(true);
    setError(null);
    try {
      await securityMutation<void>({ csrfToken, ifMatch: session.etag, method: "DELETE", path: `/api/v1/sessions/${encodeURIComponent(session.id)}` });
      if (session.current) {
        window.location.assign("/login");
        return;
      }
      setOpen(false);
      onRevoked();
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setPending(false);
    }
  }

  return <Dialog open={open} onOpenChange={setOpen}><Button type="button" size="sm" variant={session.current ? "quietDanger" : "ghost"} onClick={() => setOpen(true)}><LogOut />Revoke</Button><DialogContent>
    <DialogHeader><DialogTitle>Revoke {session.current ? "current" : "web"} session</DialogTitle><DialogDescription>{session.current ? "You will be signed out immediately." : `This ends ${session.username}’s selected browser session.`} The latest session ETag is required.</DialogDescription></DialogHeader>
    {error !== null ? <Alert tone="critical"><CircleAlert /><AlertTitle>Session not revoked</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
    <DialogFooter><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="button" variant="destructive" disabled={pending} onClick={() => void revoke()}>{pending ? <LoaderCircle className="animate-spin" /> : <LogOut />}Revoke session</Button></DialogFooter>
  </DialogContent></Dialog>;
}

function ChangePassword({ csrfToken }: Readonly<{ csrfToken: string }>) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    setSuccess(false);
    try {
      await securityMutation<void, { currentPassword: string; newPassword: string }>({ body: { currentPassword, newPassword }, csrfToken, method: "POST", path: "/api/v1/auth/change-password" });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmation("");
      setSuccess(true);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setPending(false);
    }
  }

  return <section className="h-fit border border-border bg-card p-4" aria-labelledby="change-password-heading">
    <div className="mb-4 flex items-start gap-3"><span className="flex size-8 items-center justify-center bg-primary-muted text-primary-strong"><KeyRound className="size-4" /></span><div><h3 id="change-password-heading" className="text-sm font-semibold">Change password</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">Other web sessions are revoked after the change.</p></div></div>
    <form className="grid gap-3" onSubmit={(event) => void submit(event)}>
      <div className="grid gap-1.5"><Label htmlFor="current-password">Current password</Label><Input id="current-password" type="password" minLength={14} maxLength={256} autoComplete="current-password" required value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} /></div>
      <div className="grid gap-1.5"><Label htmlFor="new-password">New password</Label><Input id="new-password" type="password" minLength={14} maxLength={256} autoComplete="new-password" required value={newPassword} onChange={(event) => setNewPassword(event.target.value)} /><p className="text-[0.6875rem] text-muted-foreground">14 to 256 UTF-8 characters.</p></div>
      <div className="grid gap-1.5"><Label htmlFor="confirm-new-password">Confirm new password</Label><Input id="confirm-new-password" type="password" minLength={14} maxLength={256} autoComplete="new-password" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} aria-invalid={confirmation.length > 0 && confirmation !== newPassword} /></div>
      {error !== null ? <Alert tone="critical"><CircleAlert /><AlertTitle>Password not changed</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
      {success ? <Alert tone="info"><CircleCheck /><AlertTitle>Password changed</AlertTitle><AlertDescription>Other sessions were revoked.</AlertDescription></Alert> : null}
      <Button type="submit" disabled={pending || newPassword !== confirmation}>{pending ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}Update password</Button>
    </form>
  </section>;
}
