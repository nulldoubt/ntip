import type { Metadata } from "next";
import type { components } from "@ntip/contracts";
import { ActivityWorkspace } from "@/components/activity/activity-workspace";
import { apiGet, apiGetResult } from "@/lib/server-api";

export const metadata: Metadata = {
  title: "Activity | NTIP",
};

type EventPage = components["schemas"]["EventPage"];
type ConnectivityCheckPage = components["schemas"]["ConnectivityCheckPage"];
type AuditPage = components["schemas"]["AuditPage"];
type NodePage = components["schemas"]["NodePage"];

export default async function ActivityPage() {
  const [events, checks, audit, nodes] = await Promise.all([
    apiGet<EventPage>("/events?limit=50"),
    apiGet<ConnectivityCheckPage>("/connectivity-checks?limit=50"),
    apiGetResult<AuditPage>("/audit?limit=50"),
    apiGet<NodePage>("/nodes?limit=200"),
  ]);

  return (
    <ActivityWorkspace
      initialAudit={audit.data}
      initialAuditEtag={audit.etag}
      initialChecks={checks}
      initialEvents={events}
      nodes={nodes.items}
    />
  );
}
