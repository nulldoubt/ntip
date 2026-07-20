import type { Metadata } from "next";
import type { components } from "@ntip/contracts";
import { notFound } from "next/navigation";
import { NodeDetailWorkspace } from "@/components/nodes/node-detail-workspace";
import { apiGet, isApiErrorStatus } from "@/lib/server-api";

type ConnectivityCheckPage = components["schemas"]["ConnectivityCheckPage"];
type NodeDetail = components["schemas"]["NodeDetail"];
type NodePage = components["schemas"]["NodePage"];
type VnrPage = components["schemas"]["VnrPage"];

type PageProps = Readonly<{ params: Promise<{ id: string }> }>;

export const metadata: Metadata = { title: "Node detail" };

async function loadNodeOwners(): Promise<NodePage> {
  const items: NodePage["items"][number][] = [];
  const seenCursors = new Set<string>();
  let cursor: string | null = null;
  // The dashboard is scoped to small infrastructure teams, but follows the
  // canonical cursor rather than silently omitting eligible route owners.
  do {
    const suffix: string = cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`;
    const page: NodePage = await apiGet<NodePage>(`/nodes?limit=200${suffix}`);
    items.push(...page.items);
    cursor = page.nextCursor;
    if (cursor !== null) {
      if (seenCursors.has(cursor)) throw new Error("The Node cursor did not advance");
      seenCursors.add(cursor);
    }
  } while (cursor !== null);
  return { items, nextCursor: null };
}

async function loadVnrRegister(): Promise<VnrPage> {
  const items: VnrPage["items"][number][] = [];
  const seenCursors = new Set<string>();
  let cursor: string | null = null;
  do {
    const suffix: string = cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`;
    const page: VnrPage = await apiGet<VnrPage>(`/vnrs?limit=200${suffix}`);
    items.push(...page.items);
    cursor = page.nextCursor;
    if (cursor !== null) {
      if (seenCursors.has(cursor)) throw new Error("The VNR cursor did not advance");
      seenCursors.add(cursor);
    }
  } while (cursor !== null);
  return { items, nextCursor: null };
}

export default async function NodeDetailPage({ params }: PageProps) {
  const { id } = await params;
  const encodedId = encodeURIComponent(id);
  let detail: NodeDetail;
  let checks: ConnectivityCheckPage;
  let nodes: NodePage;
  let vnrs: VnrPage;
  try {
    [detail, checks, nodes, vnrs] = await Promise.all([
      apiGet<NodeDetail>(`/nodes/${encodedId}`),
      apiGet<ConnectivityCheckPage>(`/connectivity-checks?limit=20&nodeId=${encodedId}`),
      loadNodeOwners(),
      loadVnrRegister(),
    ]);
  } catch (error) {
    if (isApiErrorStatus(error, 404)) notFound();
    throw error;
  }

  return <NodeDetailWorkspace initialDetail={detail} initialChecks={checks} nodes={nodes} vnrs={vnrs.items} />;
}
