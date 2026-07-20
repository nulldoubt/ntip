import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { VnrDetailClient } from "@/components/vnrs/vnr-detail-client";
import type { Topology, Vnr, VnrDetailData } from "@/components/vnrs/vnr-types";
import { apiGet, apiGetResult, isApiErrorStatus } from "@/lib/server-api";

export const metadata: Metadata = { title: "VNR details" };

export default async function VnrDetailPage({ params }: Readonly<{ params: Promise<{ name: string }> }>) {
  const { name } = await params;
  const detailPath = `/vnrs/${encodeURIComponent(name)}` as const;

  const [detailResult, topologyResult] = await Promise.all([
    apiGetResult<Vnr>(detailPath).catch((error: unknown) => {
      if (isApiErrorStatus(error, 404)) notFound();
      throw error;
    }),
    apiGet<Topology>("/topology").then(
      (topology) => ({ topology, topologyError: null }),
      () => ({ topology: null, topologyError: "Topology context is temporarily unavailable." }),
    ),
  ]);

  const initialData: VnrDetailData = {
    vnr: detailResult.data,
    etag: detailResult.etag,
    topology: topologyResult.topology,
    topologyError: topologyResult.topologyError,
  };

  return <VnrDetailClient key={detailResult.etag ?? detailResult.data.generation} initialData={initialData} />;
}
