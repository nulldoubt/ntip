import type { Metadata } from "next";
import type { components } from "@ntip/contracts";
import { apiGet } from "@/lib/server-api";
import { NodesWorkspace } from "@/components/nodes/nodes-workspace";

type NodePage = components["schemas"]["NodePage"];
type NodeRuntimePage = components["schemas"]["NodeRuntimePage"];
type VnrPage = components["schemas"]["VnrPage"];

export const metadata: Metadata = { title: "Nodes" };

async function loadRuntimeRegister(): Promise<NodeRuntimePage> {
  const items: NodeRuntimePage["items"][number][] = [];
  const seenCursors = new Set<string>();
  let cursor: string | null = null;
  let observedAt = new Date(0).toISOString();
  do {
    const suffix: string = cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`;
    const page: NodeRuntimePage = await apiGet<NodeRuntimePage>(`/runtime/nodes?limit=200${suffix}`);
    items.push(...page.items);
    observedAt = page.observedAt;
    cursor = page.nextCursor;
    if (cursor !== null) {
      if (seenCursors.has(cursor)) throw new Error("The runtime cursor did not advance");
      seenCursors.add(cursor);
    }
  } while (cursor !== null);
  return { items, nextCursor: null, observedAt };
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

export default async function NodesPage() {
  const [nodes, runtime, vnrs] = await Promise.all([
    apiGet<NodePage>("/nodes?limit=50"),
    loadRuntimeRegister(),
    loadVnrRegister(),
  ]);

  return <NodesWorkspace initialNodes={nodes} initialRuntime={runtime} vnrs={vnrs.items} />;
}
