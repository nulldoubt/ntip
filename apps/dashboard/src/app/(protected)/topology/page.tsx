import type { Metadata } from "next";
import type { components } from "@ntip/contracts";
import { TopologyWorkspace } from "@/components/topology/topology-workspace";
import { apiGet } from "@/lib/server-api";

type Topology = components["schemas"]["Topology"];

export const metadata: Metadata = { title: "Topology" };

export default async function TopologyPage() {
  const topology = await apiGet<Topology>("/topology");
  return <TopologyWorkspace initialTopology={topology} />;
}
