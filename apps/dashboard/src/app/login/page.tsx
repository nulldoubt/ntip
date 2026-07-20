import type { Metadata } from "next";
import { LoginForm } from "@/components/login-form";

export const metadata: Metadata = { title: "Sign in" };

export default async function LoginPage({
  searchParams,
}: Readonly<{ searchParams: Promise<{ reason?: string }> }>) {
  const reason = (await searchParams).reason;
  return (
    <main className="grid min-h-screen grid-cols-[minmax(0,1fr)_25rem] bg-background">
      <section className="grid place-items-center px-10 py-16">
        <div className="w-full max-w-sm">
          <div className="mb-10 flex items-baseline gap-3">
            <span className="font-mono text-xl font-semibold tracking-[0.13em] text-primary-strong">NTIP</span>
            <span className="text-xs font-semibold uppercase tracking-[0.1em] text-muted-foreground">
              Management
            </span>
          </div>
          <LoginForm redirectedForPasswordChange={reason === "password-change"} />
        </div>
      </section>

      <aside className="flex flex-col justify-between border-l border-border bg-card p-8" aria-label="Security context">
        <div>
          <p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.12em] text-primary-strong">
            Operator access
          </p>
          <h1 className="mt-4 text-2xl font-semibold leading-tight tracking-[-0.025em]">
            A precise view of the NTIP control plane.
          </h1>
          <p className="mt-4 text-sm leading-6 text-muted-foreground">
            Review private network inventory, runtime state, diagnostics, and audited changes from one
            focused workstation interface.
          </p>
        </div>

        <div className="space-y-4 border-t border-border pt-6 text-xs text-muted-foreground">
          <div className="flex items-center justify-between gap-4">
            <span>Session idle limit</span>
            <span className="font-mono text-foreground">30 minutes</span>
          </div>
          <div className="flex items-center justify-between gap-4">
            <span>Absolute limit</span>
            <span className="font-mono text-foreground">12 hours</span>
          </div>
          <p className="border-t border-border pt-4 leading-5">
            Access is recorded in the immutable audit trail. Use only your assigned account.
          </p>
        </div>
      </aside>
    </main>
  );
}
