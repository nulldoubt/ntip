import type { components } from "@ntip/contracts";

export type Vnr = components["schemas"]["Vnr"];
export type VnrPage = components["schemas"]["VnrPage"];
export type Topology = components["schemas"]["Topology"];
export type Node = components["schemas"]["Node"];
export type NodeRuntime = components["schemas"]["NodeRuntime"];
export type EntityTag = components["schemas"]["EntityTag"];

export interface VnrListData {
  readonly page: VnrPage;
  readonly topology: Topology | null;
  readonly topologyError: string | null;
}

export interface VnrDetailData {
  readonly etag: EntityTag | null;
  readonly topology: Topology | null;
  readonly topologyError: string | null;
  readonly vnr: Vnr;
}
