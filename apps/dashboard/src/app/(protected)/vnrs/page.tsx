import type { Metadata } from "next";
import type { Topology, VnrListData, VnrPage } from "@/components/vnrs/vnr-types";
import { VnrListClient } from "@/components/vnrs/vnr-list-client";
import { apiGet } from "@/lib/server-api";

export const metadata: Metadata = { title: "VNRs" };

export default async function VnrsPage() {
  const pagePromise = apiGet<VnrPage>("/vnrs?limit=50");
  const topologyPromise = apiGet<Topology>("/topology");
  const [page, topologyResult] = await Promise.all([
    pagePromise,
    topologyPromise.then(
      (topology) => ({ topology, topologyError: null }),
      () => ({ topology: null, topologyError: "Topology context is temporarily unavailable." }),
    ),
  ]);

  const initialData: VnrListData = {
    page,
    topology: topologyResult.topology,
    topologyError: topologyResult.topologyError,
  };

  return <VnrListClient initialData={initialData} />;
}
