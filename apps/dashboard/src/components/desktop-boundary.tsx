import { Monitor } from "lucide-react";
import type { ReactNode } from "react";

export function DesktopBoundary({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <>
      <div className="desktop-guard" role="status" aria-live="polite">
        <section className="desktop-guard__panel" aria-labelledby="desktop-required-title">
          <div className="mb-5 flex size-10 items-center justify-center border border-primary-border bg-primary-muted text-primary-strong">
            <Monitor aria-hidden="true" className="size-5" />
          </div>
          <p className="mb-2 font-mono text-[0.6875rem] font-semibold uppercase tracking-[0.12em] text-primary-strong">
            NTIP Management
          </p>
          <h1 id="desktop-required-title" className="text-xl font-semibold tracking-tight">
            A desktop-sized window is required
          </h1>
          <p className="mt-3 max-w-md text-sm leading-6 text-muted-foreground">
            This operations interface is designed for precise network administration at widths of
            1024 pixels and above. Widen this window or open NTIP on a desktop display.
          </p>
        </section>
      </div>
      <div className="desktop-content">{children}</div>
    </>
  );
}
