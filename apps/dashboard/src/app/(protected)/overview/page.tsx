import type { Metadata } from "next";
import type { components } from "@ntip/contracts";
import { OverviewLive } from "@/components/overview/overview-live";
import { apiGet } from "@/lib/server-api";

type Overview = components["schemas"]["Overview"];
type Topology = components["schemas"]["Topology"];
type EventPage = components["schemas"]["EventPage"];

export const metadata: Metadata = { title: "Overview" };

function settledValue<T>(result: PromiseSettledResult<T>): T | null {
  return result.status === "fulfilled" ? result.value : null;
}

export default async function OverviewPage() {
  const overview = await apiGet<Overview>("/overview");
  const [topologyResult, eventResult] = await Promise.allSettled([
    apiGet<Topology>("/topology"),
    apiGet<EventPage>("/events?limit=6"),
  ]);

  return (
    <OverviewLive
      initialOverview={overview}
      initialTopology={settledValue(topologyResult)}
      initialEvents={settledValue(eventResult)}
    />
  );
}
