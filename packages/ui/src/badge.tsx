import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "./cn";

const badgeVariants = cva(
  "inline-flex min-h-5 items-center gap-1 rounded-full border px-2 py-0.5 text-[0.6875rem] font-semibold leading-none tracking-[0.015em]",
  {
    variants: {
      tone: {
        neutral: "border-border bg-muted text-muted-foreground",
        healthy: "border-success-border bg-success-muted text-success",
        warning: "border-warning-border bg-warning-muted text-warning",
        critical: "border-destructive-border bg-destructive-muted text-destructive",
        info: "border-info-border bg-info-muted text-info",
        copper: "border-primary-border bg-primary-muted text-primary-strong",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export type BadgeProps = HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>;

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
