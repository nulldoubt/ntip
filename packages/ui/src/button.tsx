import * as React from "react";
import { Slot } from "radix-ui";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "./cn";

export const buttonVariants = cva(
  "inline-flex min-h-9 shrink-0 items-center justify-center gap-2 rounded-md px-3 text-sm font-medium transition-[color,background-color,border-color,box-shadow,transform] duration-150 ease-[cubic-bezier(.25,1,.5,1)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-45 active:translate-y-px [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground hover:bg-primary/90",
        secondary: "border border-border bg-secondary text-secondary-foreground hover:bg-accent",
        ghost: "text-muted-foreground hover:bg-accent hover:text-foreground",
        outline: "border border-border bg-background text-foreground hover:border-strong hover:bg-accent",
        destructive: "bg-destructive text-destructive-foreground hover:bg-destructive/90",
        quietDanger: "text-destructive hover:bg-destructive-muted",
      },
      size: {
        sm: "min-h-8 px-2.5 text-xs",
        md: "min-h-9 px-3",
        lg: "min-h-10 px-4",
        icon: "size-9 px-0",
      },
    },
    defaultVariants: { variant: "default", size: "md" },
  },
);

export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants> & { asChild?: boolean };

export function Button({ className, variant, size, asChild, ...props }: ButtonProps) {
  const Component = asChild === true ? Slot.Slot : "button";
  return <Component className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}
