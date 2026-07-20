import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "./cn";

const alertVariants = cva(
  "grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 rounded-md border px-3.5 py-3 text-sm [&>svg]:mt-0.5 [&>svg]:size-4",
  {
    variants: {
      tone: {
        neutral: "border-border bg-muted text-foreground [&>svg]:text-muted-foreground",
        info: "border-info-border bg-info-muted text-foreground [&>svg]:text-info",
        warning: "border-warning-border bg-warning-muted text-foreground [&>svg]:text-warning",
        critical: "border-destructive-border bg-destructive-muted text-foreground [&>svg]:text-destructive",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export type AlertProps = HTMLAttributes<HTMLDivElement> & VariantProps<typeof alertVariants>;

export function Alert({ className, tone, ...props }: AlertProps) {
  return <div role="status" className={cn(alertVariants({ tone }), className)} {...props} />;
}

export function AlertTitle({ className, ...props }: HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={cn("font-semibold leading-5", className)} {...props} />;
}

export function AlertDescription({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("col-start-2 leading-5 text-muted-foreground", className)} {...props} />;
}
