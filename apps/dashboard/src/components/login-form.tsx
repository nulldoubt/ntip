"use client";

import { Button, Input, Label } from "@ntip/ui";
import type { components } from "@ntip/contracts";
import { ArrowRight, KeyRound, LoaderCircle, LockKeyhole } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

type AuthContext = components["schemas"]["AuthContext"];
type ErrorResponse = components["schemas"]["ErrorResponse"];

function errorMessage(payload: unknown, fallback: string): string {
  if (
    typeof payload === "object" &&
    payload !== null &&
    "error" in payload &&
    typeof payload.error === "object" &&
    payload.error !== null &&
    "code" in payload.error
  ) {
    const code = (payload as ErrorResponse).error.code;
    if (code === "invalid_credentials") return "The username or password is incorrect.";
    if (code === "rate_limited") return "Too many attempts. Wait before trying again.";
    if (code === "service_unavailable") return "The management service is unavailable.";
    if (code === "validation_failed") return "Check the entered values and try again.";
  }
  return fallback;
}

export function LoginForm({ redirectedForPasswordChange }: Readonly<{ redirectedForPasswordChange: boolean }>) {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [auth, setAuth] = useState<AuthContext | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const passwordChangeRequired = auth?.user.mustChangePassword === true;

  async function submitLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      const response = await fetch("/api/v1/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": crypto.randomUUID(),
        },
        body: JSON.stringify({ username, password }),
      });
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        setError(errorMessage(payload, "Sign in failed. Try again."));
        return;
      }
      const nextAuth = payload as AuthContext;
      if (nextAuth.user.mustChangePassword) {
        setAuth(nextAuth);
        setError(null);
        return;
      }
      router.replace("/overview");
      router.refresh();
    } catch {
      setError("The management service could not be reached.");
    } finally {
      setPending(false);
    }
  }

  async function submitPasswordChange(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (auth === null) return;
    const characterCount = Array.from(newPassword).length;
    if (characterCount < 14 || characterCount > 256) {
      setError("Use a password between 14 and 256 characters.");
      return;
    }
    if (newPassword !== confirmation) {
      setError("The new passwords do not match.");
      return;
    }

    setPending(true);
    setError(null);
    try {
      const response = await fetch("/api/v1/auth/change-password", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": crypto.randomUUID(),
          "X-CSRF-Token": auth.csrfToken,
        },
        body: JSON.stringify({ currentPassword: password, newPassword }),
      });
      if (!response.ok) {
        const payload: unknown = await response.json().catch(() => null);
        setError(errorMessage(payload, "Password change failed. Try again."));
        return;
      }
      setPassword("");
      setNewPassword("");
      setConfirmation("");
      router.replace("/overview");
      router.refresh();
    } catch {
      setError("The management service could not be reached.");
    } finally {
      setPending(false);
    }
  }

  if (passwordChangeRequired) {
    return (
      <form onSubmit={(event) => void submitPasswordChange(event)} noValidate>
        <div className="mb-7 flex size-10 items-center justify-center border border-primary-border bg-primary-muted text-primary-strong">
          <KeyRound aria-hidden="true" className="size-5" />
        </div>
        <h1 className="text-xl font-semibold tracking-tight">Choose a permanent password</h1>
        <p className="mt-2 text-sm leading-6 text-muted-foreground">
          The temporary password worked. Replace it before entering the management plane.
        </p>

        <div className="mt-7 space-y-5">
          <div className="space-y-2">
            <Label htmlFor="new-password">New password</Label>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              minLength={14}
              maxLength={256}
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
              disabled={pending}
              required
            />
            <p className="text-xs text-muted-foreground">14 to 256 characters</p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="confirm-password">Confirm new password</Label>
            <Input
              id="confirm-password"
              type="password"
              autoComplete="new-password"
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
              disabled={pending}
              required
            />
          </div>
        </div>

        <p className="mt-4 min-h-5 text-sm text-destructive" role="alert">
          {error}
        </p>
        <Button type="submit" className="mt-2 w-full" disabled={pending}>
          {pending ? <LoaderCircle aria-hidden="true" className="animate-spin" /> : <LockKeyhole aria-hidden="true" />}
          Save password and continue
        </Button>
      </form>
    );
  }

  return (
    <form onSubmit={(event) => void submitLogin(event)} noValidate>
      <h1 className="text-2xl font-semibold tracking-[-0.025em]">Sign in</h1>
      <p className="mt-2 text-sm leading-6 text-muted-foreground">
        Use your NTIP operator account to continue.
      </p>
      {redirectedForPasswordChange ? (
        <p className="mt-4 border border-warning-border bg-warning-muted px-3 py-2 text-xs leading-5 text-warning">
          Sign in with the temporary password to finish changing it.
        </p>
      ) : null}

      <div className="mt-8 space-y-5">
        <div className="space-y-2">
          <Label htmlFor="username">Username</Label>
          <Input
            id="username"
            name="username"
            type="text"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            disabled={pending}
            required
            autoFocus
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="password">Password</Label>
          <Input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            disabled={pending}
            required
          />
        </div>
      </div>

      <p className="mt-4 min-h-5 text-sm text-destructive" role="alert">
        {error}
      </p>
      <Button type="submit" className="mt-2 w-full" disabled={pending || username === "" || password === ""}>
        {pending ? <LoaderCircle aria-hidden="true" className="animate-spin" /> : null}
        Sign in
        {!pending ? <ArrowRight aria-hidden="true" /> : null}
      </Button>
    </form>
  );
}
