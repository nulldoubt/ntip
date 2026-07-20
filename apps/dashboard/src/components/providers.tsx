"use client";

import { TooltipProvider } from "@ntip/ui";
import { ThemeProvider } from "next-themes";
import type { ReactNode } from "react";

export function Providers({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <ThemeProvider
      attribute="class"
      defaultTheme="system"
      enableSystem
      storageKey="ntip-theme"
      disableTransitionOnChange
    >
      <TooltipProvider delayDuration={350} skipDelayDuration={100}>
        {children}
      </TooltipProvider>
    </ThemeProvider>
  );
}
