import { describe, expect, test } from "bun:test";
import type { components } from "@ntip/contracts";

import { createTopologyModel } from "../../src/lib/behavior/topology";

type Topology = components["schemas"]["Topology"];

const topology: Topology = {
  generation: 41,
  observedAt: "2026-07-20T12:00:00Z",
  vnrs: [
    {
      name: "west",
      cidr: "10.20.0.0/24",
      masterAddress: "10.20.0.1",
      publicRangeWarning: false,
      generation: 41,
      createdAt: "2026-07-20T10:00:00Z",
      updatedAt: "2026-07-20T10:00:00Z",
    },
    {
      name: "east",
      cidr: "10.10.0.0/24",
      masterAddress: "10.10.0.1",
      publicRangeWarning: false,
      generation: 41,
      createdAt: "2026-07-20T10:00:00Z",
      updatedAt: "2026-07-20T10:00:00Z",
    },
  ],
  nodes: [
    {
      id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      name: "west-edge",
      address: "10.20.0.2",
      vnrName: "west",
      enrollmentState: "enrolled",
      generation: 41,
      createdAt: "2026-07-20T10:00:00Z",
      updatedAt: "2026-07-20T10:00:00Z",
    },
    {
      id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      name: "east-core",
      address: "10.10.0.2",
      vnrName: "east",
      enrollmentState: "enrolled",
      generation: 41,
      createdAt: "2026-07-20T10:00:00Z",
      updatedAt: "2026-07-20T10:00:00Z",
    },
  ],
  routes: [
    {
      id: "dddddddddddddddddddddddddddddddd",
      nodeId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      nodeName: "east-core",
      prefix: "172.16.2.0/24",
      generation: 41,
      createdAt: "2026-07-20T10:00:00Z",
      updatedAt: "2026-07-20T10:00:00Z",
    },
    {
      id: "cccccccccccccccccccccccccccccccc",
      nodeId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      nodeName: "east-core",
      prefix: "172.16.1.0/24",
      generation: 41,
      createdAt: "2026-07-20T10:00:00Z",
      updatedAt: "2026-07-20T10:00:00Z",
    },
  ],
  runtime: [
    {
      nodeId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      liveness: "online",
      sessionState: "established",
      trafficState: "warm",
      observedEndpoint: "198.51.100.10:51900",
      authenticatedRxAt: "2026-07-20T11:59:58Z",
      authenticatedTxAt: "2026-07-20T11:59:59Z",
      observedAt: "2026-07-20T12:00:00Z",
    },
    {
      nodeId: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      liveness: "offline",
      sessionState: "disconnected",
      trafficState: "unknown",
      observedEndpoint: null,
      authenticatedRxAt: null,
      authenticatedTxAt: null,
      observedAt: "2026-07-20T12:00:00Z",
    },
  ],
};

describe("createTopologyModel", () => {
  test("is independent of API input order", () => {
    const reversed: Topology = {
      ...topology,
      vnrs: [...topology.vnrs].reverse(),
      nodes: [...topology.nodes].reverse(),
      routes: [...topology.routes].reverse(),
      runtime: [...topology.runtime].reverse(),
    };

    expect(createTopologyModel(reversed)).toEqual(createTopologyModel(topology));
  });

  test("sorts relationships and lays them out in stable hierarchy columns", () => {
    const model = createTopologyModel(topology);

    expect(model.vnrs.map(({ vnr }) => vnr.name)).toEqual(["east", "west"]);
    expect(model.vnrs[0]?.nodes[0]?.routes.map((route) => route.prefix)).toEqual([
      "172.16.1.0/24",
      "172.16.2.0/24",
    ]);
    expect(model.entities.find(({ key }) => key === "master")).toMatchObject({ kind: "master", x: 48 });
    expect(model.entities.find(({ key }) => key === "vnr:east")).toMatchObject({
      kind: "vnr",
      parentKey: "master",
      x: 304,
    });
    expect(model.entities.find(({ key }) => key === "node:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).toMatchObject({
      kind: "node",
      parentKey: "vnr:east",
      x: 592,
      y: 36,
    });
    expect(model.entities.find(({ key }) => key === "route:cccccccccccccccccccccccccccccccc")).toMatchObject({
      kind: "route",
      parentKey: "node:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      x: 880,
      y: 0,
    });
    expect(model.edges).toContainEqual({
      key: "master->vnr:east",
      kind: "contains",
      sourceKey: "master",
      targetKey: "vnr:east",
    });
    expect(model.orphanNodeIds).toEqual([]);
    expect(model.orphanRouteIds).toEqual([]);
  });

  test("reports inconsistent projections without inventing relationships", () => {
    const inconsistent: Topology = {
      ...topology,
      nodes: [{ ...topology.nodes[0]!, vnrName: "missing" }],
      routes: [
        { ...topology.routes[0]!, nodeId: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" },
        { ...topology.routes[1]!, nodeId: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
      ],
      runtime: [],
    };
    const model = createTopologyModel(inconsistent);

    expect(model.orphanNodeIds).toEqual(["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]);
    expect(model.orphanRouteIds).toEqual(["dddddddddddddddddddddddddddddddd"]);
    expect(model.entities.find(({ key }) => key === "node:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?.parentKey).toBeNull();
    expect(model.entities.find(({ key }) => key === "route:dddddddddddddddddddddddddddddddd")?.parentKey).toBeNull();
    expect(model.entities.find(({ key }) => key === "route:cccccccccccccccccccccccccccccccc")?.parentKey)
      .toBe("node:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  });
});
