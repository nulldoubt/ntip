import * as React from "react";
import { Label as LabelPrimitive } from "radix-ui";
import { cn } from "./cn";

export function Label({ className, ...props }: React.ComponentProps<typeof LabelPrimitive.Root>) {
  return (
    <LabelPrimitive.Root
      className={cn("text-xs font-semibold text-foreground peer-disabled:opacity-50", className)}
      {...props}
    />
  );
}
