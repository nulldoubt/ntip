export const IPV4_BIT_COUNT = 32;
export const IPV4_MAX = (1n << 32n) - 1n;

export type Ipv4Octets = readonly [number, number, number, number];
export type NullableIpv4Octets = readonly [number | null, number | null, number | null, number | null];

export interface Ipv4Cidr {
  readonly address: bigint;
  readonly network: bigint;
  readonly broadcast: bigint;
  readonly prefixLength: number;
}

const canonicalOctetPattern = /^(?:0|[1-9][0-9]{0,2})$/;
const canonicalPrefixPattern = /^(?:0|[1-9][0-9]{0,2})$/;

function requireIntegerInRange(value: number, minimum: number, maximum: number, label: string): void {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(`${label} must be an integer from ${minimum} to ${maximum}`);
  }
}

export function requirePrefixLength(prefixLength: number): void {
  requireIntegerInRange(prefixLength, 0, IPV4_BIT_COUNT, "IPv4 prefix length");
}

export function requireIpv4Value(value: bigint): void {
  if (value < 0n || value > IPV4_MAX) throw new RangeError("IPv4 value is outside the 32-bit address space");
}

export function ipv4FromOctets(octets: Ipv4Octets): bigint {
  let value = 0n;
  for (const [index, octet] of octets.entries()) {
    requireIntegerInRange(octet, 0, 255, `IPv4 octet ${index + 1}`);
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

export function ipv4ToOctets(value: bigint): Ipv4Octets {
  requireIpv4Value(value);
  return [
    Number((value >> 24n) & 0xffn),
    Number((value >> 16n) & 0xffn),
    Number((value >> 8n) & 0xffn),
    Number(value & 0xffn),
  ];
}

export function formatIpv4(value: bigint): string {
  return ipv4ToOctets(value).join(".");
}

export function parseIpv4(text: string): bigint {
  const parts = text.split(".");
  if (parts.length !== 4) throw new TypeError("IPv4 address must contain four decimal octets");

  const octets: number[] = [];
  for (const part of parts) {
    if (!canonicalOctetPattern.test(part)) throw new TypeError("IPv4 octets must use canonical decimal notation");
    const octet = Number(part);
    requireIntegerInRange(octet, 0, 255, "IPv4 octet");
    octets.push(octet);
  }
  return ipv4FromOctets(octets as unknown as Ipv4Octets);
}

export function tryParseIpv4(text: string): bigint | null {
  try {
    return parseIpv4(text);
  } catch {
    return null;
  }
}

export function prefixMask(prefixLength: number): bigint {
  requirePrefixLength(prefixLength);
  if (prefixLength === 0) return 0n;
  return (IPV4_MAX << BigInt(IPV4_BIT_COUNT - prefixLength)) & IPV4_MAX;
}

export function networkAddress(address: bigint, prefixLength: number): bigint {
  requireIpv4Value(address);
  return address & prefixMask(prefixLength);
}

export function broadcastAddress(address: bigint, prefixLength: number): bigint {
  return networkAddress(address, prefixLength) | (IPV4_MAX ^ prefixMask(prefixLength));
}

export function containsIpv4(cidr: Pick<Ipv4Cidr, "network" | "broadcast">, address: bigint): boolean {
  requireIpv4Value(address);
  return address >= cidr.network && address <= cidr.broadcast;
}

export function parseIpv4Cidr(text: string): Ipv4Cidr {
  const slash = text.indexOf("/");
  if (slash <= 0 || slash !== text.lastIndexOf("/") || slash === text.length - 1) {
    throw new TypeError("IPv4 CIDR must contain one address and one prefix length");
  }

  const address = parseIpv4(text.slice(0, slash));
  const prefixText = text.slice(slash + 1);
  if (!canonicalPrefixPattern.test(prefixText)) {
    throw new TypeError("IPv4 prefix length must use canonical decimal notation");
  }
  const prefixLength = Number(prefixText);
  requirePrefixLength(prefixLength);
  const network = networkAddress(address, prefixLength);
  if (network !== address) throw new TypeError("IPv4 CIDR contains non-zero host bits");
  return { address, network, broadcast: broadcastAddress(address, prefixLength), prefixLength };
}

export function formatIpv4Cidr(address: bigint, prefixLength: number): string {
  requirePrefixLength(prefixLength);
  const network = networkAddress(address, prefixLength);
  if (network !== address) throw new TypeError("IPv4 CIDR contains non-zero host bits");
  return `${formatIpv4(address)}/${prefixLength}`;
}

export function octetPrefixInterval(octets: readonly number[]): Readonly<{ first: bigint; last: bigint }> {
  if (octets.length > 4) throw new RangeError("An IPv4 octet prefix cannot contain more than four octets");

  let first = 0n;
  for (const [index, octet] of octets.entries()) {
    requireIntegerInRange(octet, 0, 255, `IPv4 octet ${index + 1}`);
    first |= BigInt(octet) << BigInt(24 - index * 8);
  }
  const remainingBits = BigInt((4 - octets.length) * 8);
  const suffix = remainingBits === 0n ? 0n : (1n << remainingBits) - 1n;
  return { first, last: first | suffix };
}
