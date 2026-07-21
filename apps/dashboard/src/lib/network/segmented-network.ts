import type { components } from "@ntip/contracts";
import {
  containsIpv4,
  formatIpv4,
  formatIpv4Cidr,
  ipv4FromOctets,
  ipv4ToOctets,
  networkAddress,
  octetPrefixInterval,
  parseIpv4,
  parseIpv4Cidr,
  tryParseIpv4,
  type Ipv4Octets,
  type NullableIpv4Octets,
} from "./ipv4";

export type OctetIndex = 0 | 1 | 2 | 3;
export type CidrPurpose = "vnr" | "route";
export type SegmentOptionStatus = "available" | "retained-invalid";

export interface SegmentOption {
  readonly value: number;
  readonly status: SegmentOptionStatus;
}

export type OctetOptionMatrix = readonly [
  readonly SegmentOption[],
  readonly SegmentOption[],
  readonly SegmentOption[],
  readonly SegmentOption[],
];

export interface SegmentedIpv4Selection {
  readonly kind: "address";
  readonly value: string | null;
  readonly octets: NullableIpv4Octets;
  readonly octetOptions: OctetOptionMatrix;
  readonly validity: "available" | "exhausted";
}

export interface SegmentedCidrSelection {
  readonly kind: "cidr";
  readonly purpose: CidrPurpose;
  readonly value: string | null;
  readonly octets: NullableIpv4Octets;
  readonly prefixLength: number | null;
  readonly prefixOptions: readonly number[];
  readonly octetOptions: OctetOptionMatrix;
  readonly validity: "incomplete" | "canonical" | "host_bits_set";
}

type Topology = components["schemas"]["Topology"];
export type NodeAddressTopology = Readonly<Pick<Topology, "nodes" | "vnrs">>;

export interface CreateNodeAddressAvailabilityOptions {
  readonly topology: NodeAddressTopology;
  readonly vnrName: string;
  readonly currentNodeId?: string;
}

const octetIndices: readonly OctetIndex[] = [0, 1, 2, 3];
const allOctetValues: readonly number[] = Object.freeze(Array.from({ length: 256 }, (_, value) => value));
const emptyOctets = (): NullableIpv4Octets => [null, null, null, null];
const emptyOptionMatrix = (): OctetOptionMatrix => [[], [], [], []];

function requireOctet(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    throw new RangeError("IPv4 octet must be an integer from 0 to 255");
  }
}

function requireOctetIndex(index: number): asserts index is OctetIndex {
  if (!Number.isInteger(index) || index < 0 || index > 3) {
    throw new RangeError("IPv4 octet index must be from 0 to 3");
  }
}

function availableOptions(values: readonly number[]): readonly SegmentOption[] {
  return values.map((value) => ({ value, status: "available" as const }));
}

function prefixOptions(purpose: CidrPurpose): readonly number[] {
  const maximum = purpose === "vnr" ? 30 : 32;
  return Object.freeze(Array.from({ length: maximum }, (_, index) => index + 1));
}

function requirePurposePrefix(purpose: CidrPurpose, prefixLength: number): void {
  const maximum = purpose === "vnr" ? 30 : 32;
  if (!Number.isInteger(prefixLength) || prefixLength < 1 || prefixLength > maximum) {
    throw new RangeError(`${purpose === "vnr" ? "VNR" : "Route"} prefix length must be from 1 to ${maximum}`);
  }
}

function validCidrOctetValues(prefixLength: number | null, index: OctetIndex): readonly number[] {
  if (prefixLength === null) return allOctetValues;
  const significantBits = Math.max(0, Math.min(8, prefixLength - index * 8));
  if (significantBits === 0) return [0];
  if (significantBits === 8) return allOctetValues;
  const step = 2 ** (8 - significantBits);
  return Object.freeze(Array.from({ length: 2 ** significantBits }, (_, optionIndex) => optionIndex * step));
}

function withRetainedInvalid(
  values: readonly number[],
  current: number | null,
): readonly SegmentOption[] {
  const options = availableOptions(values);
  if (current === null || values.includes(current)) return options;
  return [...options, { value: current, status: "retained-invalid" as const }]
    .toSorted((left, right) => left.value - right.value);
}

function deriveCidrSelection(
  purpose: CidrPurpose,
  octets: NullableIpv4Octets,
  selectedPrefix: number | null,
): SegmentedCidrSelection {
  if (selectedPrefix !== null) requirePurposePrefix(purpose, selectedPrefix);
  for (const octet of octets) if (octet !== null) requireOctet(octet);

  const prefixChoices = prefixOptions(purpose);
  const options = octetIndices.map((index): readonly SegmentOption[] => {
    const upstreamComplete = octets.slice(0, index).every((octet) => octet !== null);
    if (!upstreamComplete) {
      const current = octets[index];
      return current === null ? [] : [{ value: current, status: "retained-invalid" }];
    }
    return withRetainedInvalid(validCidrOctetValues(selectedPrefix, index), octets[index]);
  }) as unknown as OctetOptionMatrix;

  if (selectedPrefix === null || octets.some((octet) => octet === null)) {
    return {
      kind: "cidr",
      purpose,
      value: null,
      octets,
      prefixLength: selectedPrefix,
      prefixOptions: prefixChoices,
      octetOptions: options,
      validity: "incomplete",
    };
  }

  const completeOctets = octets as Ipv4Octets;
  const address = ipv4FromOctets(completeOctets);
  const network = networkAddress(address, selectedPrefix);
  if (network !== address) {
    return {
      kind: "cidr",
      purpose,
      value: null,
      octets,
      prefixLength: selectedPrefix,
      prefixOptions: prefixChoices,
      octetOptions: options,
      validity: "host_bits_set",
    };
  }

  return {
    kind: "cidr",
    purpose,
    value: formatIpv4Cidr(address, selectedPrefix),
    octets,
    prefixLength: selectedPrefix,
    prefixOptions: prefixChoices,
    octetOptions: options,
    validity: "canonical",
  };
}

export function createEmptyCidrSelection(
  purpose: CidrPurpose,
  initialPrefixLength: number | null = purpose === "vnr" ? 24 : null,
): SegmentedCidrSelection {
  return deriveCidrSelection(purpose, emptyOctets(), initialPrefixLength);
}

export function createCidrSelection(value: string, purpose: CidrPurpose): SegmentedCidrSelection {
  const cidr = parseIpv4Cidr(value);
  requirePurposePrefix(purpose, cidr.prefixLength);
  return deriveCidrSelection(purpose, ipv4ToOctets(cidr.network), cidr.prefixLength);
}

export function createCidrSelectionFromDraft(
  purpose: CidrPurpose,
  octets: NullableIpv4Octets,
  selectedPrefix: number | null,
): SegmentedCidrSelection {
  return deriveCidrSelection(purpose, [...octets] as NullableIpv4Octets, selectedPrefix);
}

export function selectCidrOctet(
  selection: SegmentedCidrSelection,
  index: OctetIndex,
  value: number,
): SegmentedCidrSelection {
  requireOctetIndex(index);
  requireOctet(value);
  const validValues = validCidrOctetValues(selection.prefixLength, index);
  if (!validValues.includes(value)) throw new RangeError("Selected octet is not canonical for the current prefix length");
  if (selection.octets.slice(0, index).some((octet) => octet === null)) {
    throw new RangeError("Select upstream IPv4 octets first");
  }

  const next: [number | null, number | null, number | null, number | null] = [...selection.octets];
  next[index] = value;
  for (let downstream = index + 1; downstream < 4; downstream += 1) next[downstream] = 0;
  return deriveCidrSelection(selection.purpose, next, selection.prefixLength);
}

export function selectCidrPrefix(
  selection: SegmentedCidrSelection,
  prefixLength: number,
): SegmentedCidrSelection {
  requirePurposePrefix(selection.purpose, prefixLength);
  // Prefix changes deliberately preserve every visible octet. If host bits
  // become non-zero the result remains visible but cannot be submitted until
  // the operator explicitly chooses a canonical boundary.
  return deriveCidrSelection(selection.purpose, selection.octets, prefixLength);
}

export class NodeAddressAvailability {
  readonly vnrName: string;
  readonly cidr: string;
  readonly masterAddress: string;
  readonly network: bigint;
  readonly broadcast: bigint;
  readonly prefixLength: number;
  readonly #blocked: ReadonlySet<bigint>;

  constructor(
    vnrName: string,
    cidr: string,
    masterAddress: string,
    network: bigint,
    broadcast: bigint,
    prefixLength: number,
    blocked: ReadonlySet<bigint>,
  ) {
    this.vnrName = vnrName;
    this.cidr = cidr;
    this.masterAddress = masterAddress;
    this.network = network;
    this.broadcast = broadcast;
    this.prefixLength = prefixLength;
    this.#blocked = blocked;
  }

  isAvailable(address: bigint): boolean {
    return address > this.network && address < this.broadcast && !this.#blocked.has(address);
  }

  lowestMatching(octetPrefix: readonly number[]): bigint | null {
    const interval = octetPrefixInterval(octetPrefix);
    let candidate = interval.first > this.network ? interval.first : this.network;
    const last = interval.last < this.broadcast ? interval.last : this.broadcast;
    if (candidate > last) return null;

    // Only sparse, explicitly blocked addresses are stepped over. Runtime is
    // bounded by inventory size rather than the CIDR's host count.
    while (candidate <= last && this.#blocked.has(candidate)) candidate += 1n;
    return candidate <= last ? candidate : null;
  }

  octetOptions(octetPrefix: readonly number[]): readonly number[] {
    return allOctetValues.filter((octet) => this.lowestMatching([...octetPrefix, octet]) !== null);
  }
}

export function createNodeAddressAvailability({
  topology,
  vnrName,
  currentNodeId,
}: CreateNodeAddressAvailabilityOptions): NodeAddressAvailability {
  const vnr = topology.vnrs.find((candidate) => candidate.name === vnrName);
  if (vnr === undefined) throw new RangeError(`VNR ${vnrName} is absent from the topology snapshot`);

  const cidr = parseIpv4Cidr(vnr.cidr);
  requirePurposePrefix("vnr", cidr.prefixLength);
  const master = parseIpv4(vnr.masterAddress);
  if (!containsIpv4(cidr, master) || master === cidr.network || master === cidr.broadcast) {
    throw new TypeError("Topology contains an invalid VNR Master address");
  }

  const blocked = new Set<bigint>([cidr.network, master, cidr.broadcast]);
  for (const node of topology.nodes) {
    if (currentNodeId !== undefined && node.id === currentNodeId) continue;
    const address = parseIpv4(node.address);
    if (containsIpv4(cidr, address)) blocked.add(address);
  }

  return new NodeAddressAvailability(
    vnr.name,
    vnr.cidr,
    vnr.masterAddress,
    cidr.network,
    cidr.broadcast,
    cidr.prefixLength,
    blocked,
  );
}

function nodeSelectionForAddress(
  availability: NodeAddressAvailability,
  address: bigint | null,
): SegmentedIpv4Selection {
  if (address === null) {
    return {
      kind: "address",
      value: null,
      octets: emptyOctets(),
      octetOptions: emptyOptionMatrix(),
      validity: "exhausted",
    };
  }

  const octets = ipv4ToOctets(address);
  const optionMatrix = octetIndices.map((index) =>
    availableOptions(availability.octetOptions(octets.slice(0, index))),
  ) as unknown as OctetOptionMatrix;
  return {
    kind: "address",
    value: formatIpv4(address),
    octets,
    octetOptions: optionMatrix,
    validity: "available",
  };
}

export function createNodeAddressSelection(
  availability: NodeAddressAvailability,
  preferredAddress?: string | null,
): SegmentedIpv4Selection {
  const preferred = preferredAddress === undefined || preferredAddress === null
    ? null
    : tryParseIpv4(preferredAddress);
  const selected = preferred !== null && availability.isAvailable(preferred)
    ? preferred
    : availability.lowestMatching([]);
  return nodeSelectionForAddress(availability, selected);
}

export function selectNodeAddressOctet(
  availability: NodeAddressAvailability,
  selection: SegmentedIpv4Selection,
  index: OctetIndex,
  value: number,
): SegmentedIpv4Selection {
  requireOctetIndex(index);
  requireOctet(value);
  if (selection.validity === "exhausted") throw new RangeError("The selected VNR has no available Node addresses");
  const upstream = selection.octets.slice(0, index);
  if (upstream.some((octet) => octet === null)) throw new RangeError("Select upstream IPv4 octets first");
  const next = availability.lowestMatching([...(upstream as number[]), value]);
  if (next === null) throw new RangeError("Selected octet has no available address completion");
  return nodeSelectionForAddress(availability, next);
}
