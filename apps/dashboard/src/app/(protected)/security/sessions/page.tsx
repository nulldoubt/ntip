import type { Metadata } from "next";
import type { components } from "@ntip/contracts";
import { SessionsWorkspace } from "@/components/security/sessions-workspace";
import { getAuthContext } from "@/lib/auth";
import { apiGet } from "@/lib/server-api";

export const metadata: Metadata = {
  title: "Sessions | NTIP",
};

type SessionPage = components["schemas"]["SessionPage"];

export default async function SessionsPage() {
  const auth = await getAuthContext();
  const scope = auth.user.role === "superuser" ? "all" : "own";
  const sessions = await apiGet<SessionPage>(`/sessions?scope=${scope}&limit=50`);
  return <SessionsWorkspace initialSessions={sessions} initialScope={scope} />;
}
