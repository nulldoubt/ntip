"use client";

import type { components } from "@ntip/contracts";
import { createContext, useContext, useMemo, type ReactNode } from "react";
import { capabilitiesForRole, type Capability } from "@/lib/capabilities";

export type DashboardAuthContext = components["schemas"]["AuthContext"];

type AuthValue = Readonly<{
  auth: DashboardAuthContext;
  capabilities: ReadonlySet<Capability>;
  can: (capability: Capability) => boolean;
}>;

const AuthContext = createContext<AuthValue | null>(null);

export function AuthContextProvider({
  auth,
  children,
}: Readonly<{ auth: DashboardAuthContext; children: ReactNode }>) {
  const value = useMemo<AuthValue>(() => {
    const capabilities = capabilitiesForRole(auth.user.role);
    return {
      auth,
      capabilities,
      can: (capability) => capabilities.has(capability),
    };
  }, [auth]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const context = useContext(AuthContext);
  if (context === null) throw new Error("useAuth must be used inside AuthContextProvider");
  return context;
}
