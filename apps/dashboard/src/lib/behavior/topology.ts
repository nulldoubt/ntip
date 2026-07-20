import type { components } from "@ntip/contracts";

type Topology = components["schemas"]["Topology"];
type Node = components["schemas"]["Node"];
type NodeRuntime = components["schemas"]["NodeRuntime"];
type Route = components["schemas"]["Route"];
type Vnr = components["schemas"]["Vnr"];

export type TopologyEntityKind = "master" | "vnr" | "node" | "route";
export type TopologyEdgeKind = "contains" | "owns";

export interface TopologyLayoutEntity {
  readonly entityId: string;
  readonly key: string;
  readonly kind: TopologyEntityKind;
  readonly label: string;
  readonly parentKey: string | null;
  readonly x: number;
  readonly y: number;
}

export interface TopologyLayoutEdge {
  readonly key: string;
  readonly kind: TopologyEdgeKind;
  readonly sourceKey: string;
  readonly targetKey: string;
}

export interface TopologyNodeModel {
  readonly node: Node;
  readonly routes: readonly Route[];
  readonly runtime: NodeRuntime | null;
}

export interface TopologyVnrModel {
  readonly nodes: readonly TopologyNodeModel[];
  readonly vnr: Vnr;
}

export interface TopologyModel {
  readonly edges: readonly TopologyLayoutEdge[];
  readonly entities: readonly TopologyLayoutEntity[];
  readonly generation: number;
  readonly observedAt: string;
  readonly orphanNodeIds: readonly string[];
  readonly orphanRouteIds: readonly string[];
  readonly vnrs: readonly TopologyVnrModel[];
}

const COLUMN_X = Object.freeze({ master: 48, vnr: 304, node: 592, route: 880 });
const ROW_GAP = 72;

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareVnr(left: Vnr, right: Vnr): number {
  return compareText(left.name, right.name) || compareText(left.cidr, right.cidr);
}

function compareNode(left: Node, right: Node): number {
  return compareText(left.name, right.name) || compareText(left.id, right.id);
}

function compareRoute(left: Route, right: Route): number {
  return compareText(left.prefix, right.prefix) || compareText(left.id, right.id);
}

function runtimeTieBreaker(runtime: NodeRuntime): string {
  return [
    runtime.observedAt,
    runtime.liveness,
    runtime.sessionState,
    runtime.trafficState,
    runtime.observedEndpoint ?? "",
    runtime.authenticatedRxAt ?? "",
    runtime.authenticatedTxAt ?? "",
  ].join("\u0000");
}

function latestRuntimeByNode(runtimeEntries: readonly NodeRuntime[]): ReadonlyMap<string, NodeRuntime> {
  const result = new Map<string, NodeRuntime>();
  for (const runtime of runtimeEntries) {
    const existing = result.get(runtime.nodeId);
    if (existing === undefined || compareText(runtimeTieBreaker(existing), runtimeTieBreaker(runtime)) < 0) {
      result.set(runtime.nodeId, runtime);
    }
  }
  return result;
}

function center(rows: readonly number[]): number {
  if (rows.length === 0) return 0;
  return (rows[0]! + rows[rows.length - 1]!) / 2;
}

export function createTopologyModel(topology: Topology): TopologyModel {
  const vnrs = [...topology.vnrs].sort(compareVnr);
  const nodes = [...topology.nodes].sort(compareNode);
  const routes = [...topology.routes].sort(compareRoute);
  const runtimeByNode = latestRuntimeByNode(topology.runtime);
  const vnrNames = new Set(vnrs.map((vnr) => vnr.name));
  const nodeIds = new Set(nodes.map((node) => node.id));
  const orphanNodes = nodes.filter((node) => !vnrNames.has(node.vnrName));
  const orphanRoutes = routes.filter((route) => !nodeIds.has(route.nodeId));

  const vnrModels: TopologyVnrModel[] = vnrs.map((vnr) => ({
    vnr,
    nodes: nodes
      .filter((node) => node.vnrName === vnr.name)
      .map((node) => ({
        node,
        routes: routes.filter((route) => route.nodeId === node.id),
        runtime: runtimeByNode.get(node.id) ?? null,
      })),
  }));

  const entities: TopologyLayoutEntity[] = [];
  const edges: TopologyLayoutEdge[] = [];
  const vnrRows: number[] = [];
  let row = 0;

  for (const vnrModel of vnrModels) {
    const vnrKey = `vnr:${vnrModel.vnr.name}`;
    const nodeRows: number[] = [];

    if (vnrModel.nodes.length === 0) {
      nodeRows.push(row * ROW_GAP);
      row += 1;
    }

    for (const nodeModel of vnrModel.nodes) {
      const nodeKey = `node:${nodeModel.node.id}`;
      const routeRows: number[] = [];
      if (nodeModel.routes.length === 0) {
        routeRows.push(row * ROW_GAP);
        row += 1;
      } else {
        for (const route of nodeModel.routes) {
          const routeY = row * ROW_GAP;
          routeRows.push(routeY);
          const routeKey = `route:${route.id}`;
          entities.push({
            entityId: route.id,
            key: routeKey,
            kind: "route",
            label: route.prefix,
            parentKey: nodeKey,
            x: COLUMN_X.route,
            y: routeY,
          });
          edges.push({ key: `${nodeKey}->${routeKey}`, kind: "owns", sourceKey: nodeKey, targetKey: routeKey });
          row += 1;
        }
      }

      const nodeY = center(routeRows);
      nodeRows.push(nodeY);
      entities.push({
        entityId: nodeModel.node.id,
        key: nodeKey,
        kind: "node",
        label: nodeModel.node.name,
        parentKey: vnrKey,
        x: COLUMN_X.node,
        y: nodeY,
      });
      edges.push({ key: `${vnrKey}->${nodeKey}`, kind: "contains", sourceKey: vnrKey, targetKey: nodeKey });
    }

    const vnrY = center(nodeRows);
    vnrRows.push(vnrY);
    entities.push({
      entityId: vnrModel.vnr.name,
      key: vnrKey,
      kind: "vnr",
      label: vnrModel.vnr.name,
      parentKey: "master",
      x: COLUMN_X.vnr,
      y: vnrY,
    });
    edges.push({ key: `master->${vnrKey}`, kind: "contains", sourceKey: "master", targetKey: vnrKey });
  }

  for (const node of orphanNodes) {
    const nodeKey = `node:${node.id}`;
    const nodeRoutes = routes.filter((route) => route.nodeId === node.id);
    const routeRows: number[] = [];
    if (nodeRoutes.length === 0) {
      routeRows.push(row * ROW_GAP);
      row += 1;
    } else {
      for (const route of nodeRoutes) {
        const routeY = row * ROW_GAP;
        routeRows.push(routeY);
        const routeKey = `route:${route.id}`;
        entities.push({
          entityId: route.id,
          key: routeKey,
          kind: "route",
          label: route.prefix,
          parentKey: nodeKey,
          x: COLUMN_X.route,
          y: routeY,
        });
        edges.push({ key: `${nodeKey}->${routeKey}`, kind: "owns", sourceKey: nodeKey, targetKey: routeKey });
        row += 1;
      }
    }
    entities.push({
      entityId: node.id,
      key: nodeKey,
      kind: "node",
      label: node.name,
      parentKey: null,
      x: COLUMN_X.node,
      y: center(routeRows),
    });
  }

  for (const route of orphanRoutes) {
    entities.push({
      entityId: route.id,
      key: `route:${route.id}`,
      kind: "route",
      label: route.prefix,
      parentKey: null,
      x: COLUMN_X.route,
      y: row * ROW_GAP,
    });
    row += 1;
  }

  entities.push({
    entityId: "master",
    key: "master",
    kind: "master",
    label: "Master",
    parentKey: null,
    x: COLUMN_X.master,
    y: center(vnrRows),
  });

  return {
    edges: edges.sort((left, right) => compareText(left.key, right.key)),
    entities: entities.sort((left, right) => compareText(left.key, right.key)),
    generation: topology.generation,
    observedAt: topology.observedAt,
    orphanNodeIds: orphanNodes.map((node) => node.id).sort(compareText),
    orphanRouteIds: orphanRoutes.map((route) => route.id).sort(compareText),
    vnrs: vnrModels,
  };
}
