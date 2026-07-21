import { describe, expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  NodeAddressSelect,
  SegmentedCidrSelect,
} from "../../src/components/network/segmented-network-input";
import {
  createCidrSelection,
  createEmptyCidrSelection,
  createNodeAddressAvailability,
  createNodeAddressSelection,
  selectCidrOctet,
  selectCidrPrefix,
  selectNodeAddressOctet,
  type NodeAddressTopology,
  type SegmentOption,
} from "../../src/lib/network/segmented-network";
import {
  IPV4_MAX,
  formatIpv4,
  octetPrefixInterval,
  parseIpv4,
  parseIpv4Cidr,
} from "../../src/lib/network/ipv4";

const NOW = "2026-07-21T00:00:00Z";

function topology(
  cidr: string,
  masterAddress: string,
  nodes: readonly Readonly<{ id: string; address: string }>[] = [],
): NodeAddressTopology {
  return {
    vnrs: [{
      name: "lab",
      cidr,
      masterAddress,
      publicRangeWarning: false,
      generation: 1,
      createdAt: NOW,
      updatedAt: NOW,
    }],
    nodes: nodes.map((node, index) => ({
      id: node.id,
      name: `node-${index}`,
      address: node.address,
      vnrName: "lab",
      enrollmentState: "unenrolled" as const,
      generation: 1,
      createdAt: NOW,
      updatedAt: NOW,
    })),
  };
}

function values(options: readonly SegmentOption[], status: SegmentOption["status"] = "available"): readonly number[] {
  return options.filter((option) => option.status === status).map((option) => option.value);
}

describe("BigInt-safe IPv4 arithmetic", () => {
  test("round-trips the full 32-bit space and rejects non-canonical decimal", () => {
    expect(parseIpv4("255.255.255.255")).toBe(IPV4_MAX);
    expect(formatIpv4(IPV4_MAX)).toBe("255.255.255.255");
    expect(() => parseIpv4("10.01.2.3")).toThrow();
    expect(() => parseIpv4("10.1.2.256")).toThrow();
    expect(() => parseIpv4("10.1.2")).toThrow();
  });

  test("calculates large CIDR and octet-prefix intervals without host enumeration", () => {
    const cidr = parseIpv4Cidr("128.0.0.0/1");
    expect(cidr.network).toBe(0x8000_0000n);
    expect(cidr.broadcast).toBe(IPV4_MAX);
    expect(octetPrefixInterval([10, 20, 30])).toEqual({
      first: parseIpv4("10.20.30.0"),
      last: parseIpv4("10.20.30.255"),
    });
  });
});

describe("prefix-aware CIDR selection", () => {
  test("starts VNR and route drafts with explicit blank selections", () => {
    const vnr = createEmptyCidrSelection("vnr");
    expect(vnr.octets).toEqual([null, null, null, null]);
    expect(vnr.prefixLength).toBe(24);
    expect(vnr.value).toBeNull();
    expect(vnr.validity).toBe("incomplete");

    const route = createEmptyCidrSelection("route");
    expect(route.octets).toEqual([null, null, null, null]);
    expect(route.prefixLength).toBeNull();
    expect(route.value).toBeNull();
  });

  test("enforces VNR /1-/30 and route /1-/32 bounds", () => {
    expect(createCidrSelection("0.0.0.0/1", "vnr").value).toBe("0.0.0.0/1");
    expect(createCidrSelection("192.0.2.0/30", "vnr").value).toBe("192.0.2.0/30");
    expect(() => createCidrSelection("192.0.2.0/31", "vnr")).toThrow();
    expect(createCidrSelection("192.0.2.7/32", "route").value).toBe("192.0.2.7/32");
    expect(() => createCidrSelection("0.0.0.0/0", "route")).toThrow();
  });

  test("supports partial network octets and resets downstream to the lowest completion", () => {
    const selection = createCidrSelection("10.20.16.0/20", "vnr");
    expect(values(selection.octetOptions[2])).toEqual([
      0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240,
    ]);
    expect(values(selection.octetOptions[3])).toEqual([0]);

    const changed = selectCidrOctet(selection, 1, 21);
    expect(changed.octets).toEqual([10, 21, 0, 0]);
    expect(changed.value).toBe("10.21.0.0/20");
  });

  test("preserves visible host bits across prefix changes until explicitly corrected", () => {
    const original = createCidrSelection("10.20.23.0/24", "vnr");
    const invalid = selectCidrPrefix(original, 20);
    expect(invalid.octets).toEqual([10, 20, 23, 0]);
    expect(invalid.value).toBeNull();
    expect(invalid.validity).toBe("host_bits_set");
    expect(values(invalid.octetOptions[2], "retained-invalid")).toEqual([23]);
    expect(() => selectCidrOctet(invalid, 2, 23)).toThrow();

    const corrected = selectCidrOctet(invalid, 2, 16);
    expect(corrected.octets).toEqual([10, 20, 16, 0]);
    expect(corrected.value).toBe("10.20.16.0/20");
    expect(corrected.validity).toBe("canonical");
  });
});

describe("Node address availability", () => {
  test("uses the lowest /24 hole while excluding endpoints, Master, and allocations", () => {
    const snapshot = topology("10.10.1.0/24", "10.10.1.1", [
      { id: "00000000000000000000000000000001", address: "10.10.1.2" },
      { id: "00000000000000000000000000000002", address: "10.10.1.4" },
    ]);
    const availability = createNodeAddressAvailability({ topology: snapshot, vnrName: "lab" });
    const selection = createNodeAddressSelection(availability);
    expect(selection.value).toBe("10.10.1.3");
    expect(selection.octetOptions.slice(0, 3).map((options) => options.length)).toEqual([1, 1, 1]);
    expect(values(selection.octetOptions[3])).not.toContain(0);
    expect(values(selection.octetOptions[3])).not.toContain(1);
    expect(values(selection.octetOptions[3])).not.toContain(2);
    expect(values(selection.octetOptions[3])).not.toContain(4);
    expect(values(selection.octetOptions[3])).not.toContain(255);
    expect(values(selection.octetOptions[3])).toContain(254);
  });

  test("preserves the current edit Node while retaining the next primary-like holes", () => {
    const currentNodeId = "00000000000000000000000000000001";
    const snapshot = topology("10.10.1.0/24", "10.10.1.1", [
      { id: currentNodeId, address: "10.10.1.2" },
      { id: "00000000000000000000000000000002", address: "10.10.1.3" },
    ]);
    const availability = createNodeAddressAvailability({ topology: snapshot, vnrName: "lab", currentNodeId });
    const selection = createNodeAddressSelection(availability, "10.10.1.2");
    expect(selection.value).toBe("10.10.1.2");
    expect(values(selection.octetOptions[3])).toContain(2);
    expect(values(selection.octetOptions[3])).not.toContain(3);
  });

  test("handles /16 address boundaries rather than treating each octet as a subnet", () => {
    const availability = createNodeAddressAvailability({
      topology: topology("10.20.0.0/16", "10.20.0.1"),
      vnrName: "lab",
    });
    expect(availability.isAvailable(parseIpv4("10.20.0.255"))).toBeTrue();
    expect(availability.isAvailable(parseIpv4("10.20.255.255"))).toBeFalse();
    expect(availability.octetOptions([10, 20, 0])).toContain(255);
    expect(availability.octetOptions([10, 20, 255])).toContain(254);
    expect(availability.octetOptions([10, 20, 255])).not.toContain(255);
  });

  test("handles partial /20 octets and chooses the lowest compatible completion", () => {
    const availability = createNodeAddressAvailability({
      topology: topology("10.30.16.0/20", "10.30.16.1", [
        { id: "00000000000000000000000000000001", address: "10.30.16.2" },
      ]),
      vnrName: "lab",
    });
    const selection = createNodeAddressSelection(availability);
    expect(selection.value).toBe("10.30.16.3");
    expect(availability.octetOptions([10, 30])).toEqual([
      16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ]);

    const next = selectNodeAddressOctet(availability, selection, 2, 17);
    expect(next.value).toBe("10.30.17.0");
  });

  test("reports /30 exhaustion but preserves its current edit Node", () => {
    const currentNodeId = "00000000000000000000000000000001";
    const snapshot = topology("10.40.0.0/30", "10.40.0.1", [
      { id: currentNodeId, address: "10.40.0.2" },
    ]);
    const createAvailability = createNodeAddressAvailability({ topology: snapshot, vnrName: "lab" });
    expect(createNodeAddressSelection(createAvailability).validity).toBe("exhausted");
    expect(createNodeAddressSelection(createAvailability).value).toBeNull();

    const editAvailability = createNodeAddressAvailability({ topology: snapshot, vnrName: "lab", currentNodeId });
    const editSelection = createNodeAddressSelection(editAvailability, "10.40.0.2");
    expect(editSelection.validity).toBe("available");
    expect(editSelection.value).toBe("10.40.0.2");
  });

  test("finds a default in a large VNR without enumerating its hosts", () => {
    const availability = createNodeAddressAvailability({
      topology: topology("10.0.0.0/8", "10.0.0.1"),
      vnrName: "lab",
    });
    expect(createNodeAddressSelection(availability).value).toBe("10.0.0.2");
  });
});

describe("segmented selection markup", () => {
  test("exposes four keyboard Select labels and an inline host-bit announcement", () => {
    const invalid = selectCidrPrefix(createCidrSelection("10.20.23.0/24", "vnr"), 20);
    const markup = renderToStaticMarkup(createElement(SegmentedCidrSelect, {
      id: "vnr-cidr",
      ariaLabel: "VNR IPv4 CIDR",
      selection: invalid,
      onSelectionChange: () => undefined,
    }));
    for (let index = 1; index <= 4; index += 1) {
      expect(markup).toContain(`aria-label="VNR IPv4 CIDR, octet ${index} of 4"`);
    }
    expect(markup).toContain('aria-label="VNR IPv4 CIDR, prefix length"');
    expect(markup).toContain('aria-invalid="true"');
    expect(markup).toContain("This prefix leaves host bits selected");
    expect(markup).not.toContain("<input");
  });

  test("does not synchronize a default Node address during render", () => {
    let changeCount = 0;
    const markup = renderToStaticMarkup(createElement(NodeAddressSelect, {
      id: "node-address",
      ariaLabel: "Node address",
      topology: topology("10.10.1.0/24", "10.10.1.1"),
      vnrName: "lab",
      value: null,
      onValueChange: () => { changeCount += 1; },
    }));

    expect(changeCount).toBe(0);
    const trigger = (index: number): string => markup.match(
      new RegExp(`<button[^>]*aria-label="Node address, octet ${index} of 4"[^>]*>`),
    )?.[0] ?? "";
    for (let index = 1; index <= 3; index += 1) expect(trigger(index)).toContain('disabled=""');
    expect(trigger(4)).not.toContain('disabled=""');
  });
});
