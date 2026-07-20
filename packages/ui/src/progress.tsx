"use client";

import * as React from "react";
import { Progress as ProgressPrimitive } from "radix-ui";
import { cn } from "./cn";

export function Progress({ className, value = 0, ...props }: React.ComponentProps<typeof ProgressPrimitive.Root>) {
  const bounded = Math.min(100, Math.max(0, value ?? 0));
  return (
    <ProgressPrimitive.Root className={cn("relative h-1.5 w-full overflow-hidden rounded-full bg-muted", className)} value={bounded} {...props}>
      <ProgressPrimitive.Indicator className="h-full bg-primary transition-transform duration-200 motion-reduce:transition-none" style={{ transform: `translateX(-${100 - bounded}%)` }} />
    </ProgressPrimitive.Root>
  );
}
