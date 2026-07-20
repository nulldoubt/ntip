"use client";

import { Button } from "@ntip/ui";
import { TriangleAlert } from "lucide-react";

export default function ProtectedError({
  reset,
}: Readonly<{ error: Error & { digest?: string }; reset: () => void }>) {
  return (
    <div className="grid min-h-full place-items-center p-8">
      <section className="w-full max-w-lg border border-border bg-card p-6" aria-labelledby="error-title">
        <div className="mb-5 flex size-10 items-center justify-center border border-warning-border bg-warning-muted text-warning">
          <TriangleAlert aria-hidden="true" className="size-5" />
        </div>
        <p className="font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.1em] text-warning">
          Management data unavailable
        </p>
        <h2 id="error-title" className="mt-2 text-lg font-semibold tracking-tight">
          NTIP could not load this view
        </h2>
        <p className="mt-2 text-sm leading-6 text-muted-foreground">
          The management API may be restarting or temporarily unreachable. Existing network sessions
          are not represented by this dashboard state.
        </p>
        <Button className="mt-5" onClick={reset}>
          Try again
        </Button>
      </section>
    </div>
  );
}
