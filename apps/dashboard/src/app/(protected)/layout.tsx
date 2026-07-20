import type { ReactNode } from "react";
import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { getAuthContext, type AuthContext } from "@/lib/auth";
import { isApiErrorStatus } from "@/lib/server-api";

export default async function ProtectedLayout({ children }: Readonly<{ children: ReactNode }>) {
  let auth: AuthContext;
  try {
    auth = await getAuthContext();
  } catch (error) {
    if (isApiErrorStatus(error, 401)) redirect("/login");
    throw error;
  }

  if (auth.user.mustChangePassword) redirect("/login?reason=password-change");

  return <AppShell auth={auth}>{children}</AppShell>;
}
