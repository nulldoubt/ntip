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
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
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
  CircleAlert,
  CircleCheck,
  Download,
  Ellipsis,
  KeyRound,
  LoaderCircle,
  RefreshCw,
  Shield,
  UserMinus,
  UserPlus,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { useAuth } from "@/components/auth-context";
import {
  downloadTemporaryPassword,
  getUserWithEtag,
  SecurityApiError,
  securityGet,
  securityMutation,
  securityReauthenticate,
} from "./security-api";

type User = components["schemas"]["User"];
type UserPage = components["schemas"]["UserPage"];
type UserProvisioningResult = components["schemas"]["UserProvisioningResult"];
type Role = components["schemas"]["Role"];

type UserAction = "reset" | "role" | "enable" | "disable" | "tombstone";

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function errorMessage(reason: unknown): string {
  if (reason instanceof SecurityApiError && reason.code === "precondition_failed") return "This user changed while you were reviewing it. Reloaded data is required before another attempt.";
  return reason instanceof Error ? reason.message : "The request failed";
}

function statusTone(status: User["status"]): "healthy" | "warning" | "neutral" {
  if (status === "active") return "healthy";
  if (status === "disabled") return "warning";
  return "neutral";
}

function mergeUsers(primary: readonly User[], older: readonly User[]): User[] {
  const seen = new Set<string>();
  return [...primary, ...older].filter((user) => {
    if (seen.has(user.id)) return false;
    seen.add(user.id);
    return true;
  });
}

export function UsersWorkspace({ initialUsers }: Readonly<{ initialUsers: UserPage }>) {
  const { auth } = useAuth();
  const [page, setPage] = useState(initialUsers);
  const [olderUsers, setOlderUsers] = useState<User[]>([]);
  const [cursor, setCursor] = useState(initialUsers.nextCursor);
  const [refreshing, setRefreshing] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [lastSuccessAt, setLastSuccessAt] = useState<number | null>(null);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    setLoadError(null);
    try {
      const next = await securityGet<UserPage>("/api/v1/users?limit=50");
      setPage(next);
      setOlderUsers([]);
      setCursor(next.nextCursor);
      setLastSuccessAt(Date.now());
    } catch (reason) {
      setLoadError(errorMessage(reason));
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    const onFocus = () => void refresh();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [refresh]);

  const users = useMemo(() => mergeUsers(page.items, olderUsers), [olderUsers, page.items]);

  async function loadMore() {
    if (cursor === null) return;
    setRefreshing(true);
    setLoadError(null);
    try {
      const next = await securityGet<UserPage>(`/api/v1/users?limit=50&cursor=${encodeURIComponent(cursor)}`);
      setOlderUsers((current) => mergeUsers(current, next.items));
      setCursor(next.nextCursor);
      setLastSuccessAt(Date.now());
    } catch (reason) {
      setLoadError(errorMessage(reason));
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <div className="mx-auto w-full max-w-[104rem] p-5 lg:p-6">
      <div className="mb-5 flex items-start justify-between gap-6">
        <div>
          <p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.12em] text-primary-strong">Access control</p>
          <h2 className="mt-1 text-xl font-semibold tracking-tight">Management users</h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-muted-foreground">Provision accounts, enforce role boundaries, and revoke access without erasing actor history.</p>
        </div>
        <div className="flex items-center gap-2">
          <Button type="button" size="sm" variant="outline" disabled={refreshing} onClick={() => void refresh()}><RefreshCw className={refreshing ? "animate-spin" : undefined} />Refresh</Button>
          <CreateUser csrfToken={auth.csrfToken} onCreated={() => void refresh()} />
        </div>
      </div>

      <div className="mb-3 flex min-h-8 items-center gap-2 text-xs text-muted-foreground" aria-live="polite">
        <span className={`size-1.5 rounded-full ${loadError === null ? "bg-success" : "bg-warning"}`} />
        {loadError ?? (lastSuccessAt === null ? "Initial server snapshot. Refreshes on window focus and after mutations." : `Updated ${formatTimestamp(new Date(lastSuccessAt).toISOString())}`)}
      </div>

      {loadError !== null ? <Alert tone="critical" className="mb-4"><CircleAlert /><AlertTitle>User list is stale</AlertTitle><AlertDescription>{loadError}</AlertDescription></Alert> : null}
      <div className="border-y border-border bg-card">
        <Table>
          <TableHeader><TableRow><TableHead>Username</TableHead><TableHead>Role</TableHead><TableHead>Status</TableHead><TableHead>Password state</TableHead><TableHead>Updated</TableHead><TableHead className="w-16"><span className="sr-only">Actions</span></TableHead></TableRow></TableHeader>
          <TableBody>{users.map((user) => (
            <TableRow key={user.id}>
              <TableCell><div className="font-medium">{user.username}</div><div className="font-mono text-[0.6875rem] text-muted-foreground">{user.id}</div></TableCell>
              <TableCell><Badge tone={user.role === "superuser" ? "copper" : user.role === "operator" ? "info" : "neutral"}>{user.role}</Badge></TableCell>
              <TableCell><Badge tone={statusTone(user.status)}>{user.status}</Badge></TableCell>
              <TableCell>{user.mustChangePassword ? <span className="inline-flex items-center gap-1.5 text-xs text-warning"><KeyRound className="size-3.5" />Change required</span> : <span className="text-xs text-muted-foreground">Established</span>}</TableCell>
              <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{formatTimestamp(user.updatedAt)}</TableCell>
              <TableCell>{user.status !== "tombstoned" ? <ManageUser user={user} csrfToken={auth.csrfToken} onChanged={() => void refresh()} /> : null}</TableCell>
            </TableRow>
          ))}</TableBody>
        </Table>
        {users.length === 0 ? <div className="px-4 py-12 text-center text-sm text-muted-foreground">No management users found.</div> : null}
      </div>
      {cursor !== null ? <div className="flex justify-center pt-3"><Button variant="outline" size="sm" disabled={refreshing} onClick={() => void loadMore()}>{refreshing ? <LoaderCircle className="animate-spin" /> : null}Load more</Button></div> : null}
    </div>
  );
}

function CreateUser({ csrfToken, onCreated }: Readonly<{ csrfToken: string; onCreated(): void }>) {
  const [open, setOpen] = useState(false);
  const [username, setUsername] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<UserProvisioningResult | null>(null);

  function close() {
    setOpen(false);
    setSecret(null);
    setUsername("");
    setRole("viewer");
    setError(null);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      const result = await securityMutation<UserProvisioningResult, { username: string; role: Role }>({
        body: { username, role },
        csrfToken,
        method: "POST",
        path: "/api/v1/users",
        responseKind: "one-time",
      });
      setSecret(result);
      onCreated();
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setPending(false);
    }
  }

  return <Dialog open={open} onOpenChange={(next) => { if (!next) close(); else setOpen(true); }}>
    <Button type="button" size="sm" onClick={() => setOpen(true)}><UserPlus />Add user</Button>
    <DialogContent>
      {secret === null ? <>
        <DialogHeader><DialogTitle>Provision management user</DialogTitle><DialogDescription>A temporary password is generated once. The user must change it at first sign-in.</DialogDescription></DialogHeader>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <div className="grid gap-2"><Label htmlFor="new-username">Username</Label><Input id="new-username" autoComplete="off" required minLength={1} maxLength={63} pattern="[a-z0-9][a-z0-9._-]*" value={username} onChange={(event) => setUsername(event.target.value.toLowerCase())} /><p className="text-xs text-muted-foreground">Lowercase ASCII. Tombstoned names cannot be reused.</p></div>
          <div className="grid gap-2"><Label htmlFor="new-role">Role</Label><Select value={role} onValueChange={(value) => setRole(value as Role)}><SelectTrigger id="new-role"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="viewer">Viewer</SelectItem><SelectItem value="operator">Operator</SelectItem><SelectItem value="superuser">Superuser</SelectItem></SelectContent></Select></div>
          {error !== null ? <Alert tone="critical"><CircleAlert /><AlertTitle>User not created</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
          <DialogFooter><Button type="button" variant="ghost" onClick={close}>Cancel</Button><Button type="submit" disabled={pending}>{pending ? <LoaderCircle className="animate-spin" /> : <UserPlus />}Create user</Button></DialogFooter>
        </form>
      </> : <TemporaryPassword secret={secret} onDone={close} />}
    </DialogContent>
  </Dialog>;
}

function ManageUser({ user, csrfToken, onChanged }: Readonly<{ user: User; csrfToken: string; onChanged(): void }>) {
  const [action, setAction] = useState<UserAction | null>(null);
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [role, setRole] = useState<Role>(user.role);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<UserProvisioningResult | null>(null);

  function close() {
    setAction(null);
    setPassword("");
    setConfirmation("");
    setRole(user.role);
    setError(null);
    setSecret(null);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (action === null) return;
    setPending(true);
    setError(null);
    try {
      await securityReauthenticate(csrfToken, password);
      const fresh = await getUserWithEtag(user.id);
      if (action === "reset") {
        const result = await securityMutation<UserProvisioningResult, { confirmation: string }>({ body: { confirmation: user.username }, csrfToken, ifMatch: fresh.etag, method: "POST", path: `/api/v1/users/${encodeURIComponent(user.id)}/password-reset`, responseKind: "one-time" });
        setSecret(result);
      } else if (action === "role") {
        await securityMutation<User, { role: Role; confirmation: string }>({ body: { role, confirmation: user.username }, csrfToken, ifMatch: fresh.etag, method: "PATCH", path: `/api/v1/users/${encodeURIComponent(user.id)}` });
        close();
      } else if (action === "enable" || action === "disable") {
        await securityMutation<User, { enabled: boolean; confirmation: string }>({ body: { enabled: action === "enable", confirmation: user.username }, csrfToken, ifMatch: fresh.etag, method: "PATCH", path: `/api/v1/users/${encodeURIComponent(user.id)}` });
        close();
      } else {
        await securityMutation<void, { confirmation: string }>({ body: { confirmation: user.username }, csrfToken, ifMatch: fresh.etag, method: "DELETE", path: `/api/v1/users/${encodeURIComponent(user.id)}` });
        close();
      }
      onChanged();
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setPending(false);
    }
  }

  const actionLabel = action === "reset" ? "Reset password" : action === "role" ? "Change role" : action === "enable" ? "Enable user" : action === "disable" ? "Disable user" : "Tombstone user";
  const destructive = action === "disable" || action === "tombstone";

  return <>
    <DropdownMenu><DropdownMenuTrigger asChild><Button type="button" size="icon" variant="ghost" aria-label={`Manage ${user.username}`}><Ellipsis /></Button></DropdownMenuTrigger><DropdownMenuContent align="end">
      <DropdownMenuItem onSelect={() => setAction("reset")}><KeyRound />Reset password</DropdownMenuItem>
      <DropdownMenuItem onSelect={() => setAction("role")}><Shield />Change role</DropdownMenuItem>
      <DropdownMenuSeparator />
      {user.status === "disabled" ? <DropdownMenuItem onSelect={() => setAction("enable")}><CircleCheck />Enable user</DropdownMenuItem> : <DropdownMenuItem onSelect={() => setAction("disable")}><UserMinus />Disable user</DropdownMenuItem>}
      <DropdownMenuItem className="text-destructive" onSelect={() => setAction("tombstone")}><UserMinus />Tombstone user</DropdownMenuItem>
    </DropdownMenuContent></DropdownMenu>
    <Dialog open={action !== null} onOpenChange={(open) => { if (!open) close(); }}><DialogContent>
      {secret !== null ? <TemporaryPassword secret={secret} onDone={close} /> : <>
        <DialogHeader><DialogTitle>{actionLabel}</DialogTitle><DialogDescription>{destructive ? "This change revokes the user’s web sessions. Tombstoning permanently reserves the username." : "This security-sensitive change requires a fresh password check and the current user ETag."}</DialogDescription></DialogHeader>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          {action === "role" ? <div className="grid gap-2"><Label htmlFor={`role-${user.id}`}>New role</Label><Select value={role} onValueChange={(value) => setRole(value as Role)}><SelectTrigger id={`role-${user.id}`}><SelectValue /></SelectTrigger><SelectContent><SelectItem value="viewer">Viewer</SelectItem><SelectItem value="operator">Operator</SelectItem><SelectItem value="superuser">Superuser</SelectItem></SelectContent></Select></div> : null}
          <div className="grid gap-2"><Label htmlFor={`password-${user.id}`}>Confirm your password</Label><Input id={`password-${user.id}`} type="password" minLength={14} maxLength={256} autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></div>
          <div className="grid gap-2"><Label htmlFor={`confirm-${user.id}`}>Type <span className="font-mono">{user.username}</span></Label><Input id={`confirm-${user.id}`} required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></div>
          {error !== null ? <Alert tone="critical"><CircleAlert /><AlertTitle>Change not committed</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
          <DialogFooter><Button type="button" variant="ghost" onClick={close}>Cancel</Button><Button type="submit" variant={destructive ? "destructive" : "default"} disabled={pending || confirmation !== user.username}>{pending ? <LoaderCircle className="animate-spin" /> : null}{actionLabel}</Button></DialogFooter>
        </form>
      </>}
    </DialogContent></Dialog>
  </>;
}

function TemporaryPassword({ secret, onDone }: Readonly<{ secret: UserProvisioningResult; onDone(): void }>) {
  return <>
    <DialogHeader><DialogTitle>Temporary password generated</DialogTitle><DialogDescription>This value is displayed once and is not recoverable. Download it now, then deliver it through a protected channel.</DialogDescription></DialogHeader>
    <Alert tone="warning"><KeyRound /><AlertTitle>One-time credential</AlertTitle><AlertDescription>Closing this dialog permanently removes the password from dashboard memory.</AlertDescription></Alert>
    <div className="grid gap-2"><Label htmlFor="temporary-password">{secret.user.username}</Label><Input id="temporary-password" readOnly value={secret.temporaryPassword} className="font-mono" /></div>
    <DialogFooter><Button type="button" variant="outline" onClick={() => downloadTemporaryPassword(secret.user.username, secret.temporaryPassword)}><Download />Download</Button><Button type="button" onClick={onDone}>I stored it securely</Button></DialogFooter>
  </>;
}
