"use client";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  cn,
} from "@ntip/ui";
import { useEffect, useMemo, type ReactNode } from "react";
import {
  createNodeAddressAvailability,
  createNodeAddressSelection,
  selectCidrOctet,
  selectCidrPrefix,
  selectNodeAddressOctet,
  type NodeAddressTopology,
  type OctetIndex,
  type OctetOptionMatrix,
  type SegmentedCidrSelection,
  type SegmentedIpv4Selection,
} from "@/lib/network/segmented-network";
import type { NullableIpv4Octets } from "@/lib/network/ipv4";

const octetIndices: readonly OctetIndex[] = [0, 1, 2, 3];

interface SharedSegmentedProps {
  readonly id: string;
  readonly ariaLabel: string;
  readonly ariaDescribedBy?: string | undefined;
  readonly className?: string | undefined;
  readonly disabled?: boolean | undefined;
  readonly invalid?: boolean | undefined;
  readonly required?: boolean | undefined;
}

interface OctetControlsProps extends SharedSegmentedProps {
  readonly octets: NullableIpv4Octets;
  readonly octetOptions: OctetOptionMatrix;
  readonly onOctetChange: (index: OctetIndex, value: number) => void;
  readonly suffix?: ReactNode | undefined;
}

function triggerId(id: string, index: OctetIndex): string {
  return index === 0 ? id : `${id}-octet-${index + 1}`;
}

function parseSelectedDecimal(value: string): number | null {
  if (value.length === 0) return null;
  if (!/^(?:0|[1-9][0-9]{0,2})$/.test(value)) throw new TypeError("Segmented IPv4 values must use canonical decimal notation");
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 255) throw new RangeError("IPv4 octet must be from 0 to 255");
  return parsed;
}

function OctetControls({
  id,
  ariaLabel,
  ariaDescribedBy,
  className,
  disabled = false,
  invalid = false,
  required = false,
  octets,
  octetOptions,
  onOctetChange,
  suffix,
}: OctetControlsProps) {
  return (
    <div
      role="group"
      aria-label={ariaLabel}
      aria-describedby={ariaDescribedBy}
      className={cn("flex flex-wrap items-center gap-1", className)}
    >
      {octetIndices.map((index) => {
        const options = octetOptions[index];
        const current = octets[index];
        const currentOption = current === null ? undefined : options.find((option) => option.value === current);
        const segmentInvalid = currentOption?.status === "retained-invalid";
        const availableCount = options.filter((option) => option.status === "available").length;
        const selectable = availableCount > 0;
        const fixed = availableCount === 1 && !segmentInvalid;
        return (
          <span key={index} className="contents">
            {index === 0 ? null : <span aria-hidden="true" className="font-mono text-sm text-muted-foreground">.</span>}
            <Select
              {...(current === null ? {} : { value: String(current) })}
              disabled={disabled || !selectable || fixed}
              required={required}
              onValueChange={(nextValue) => {
                const nextOctet = parseSelectedDecimal(nextValue);
                if (nextOctet === null || !options.some((option) => option.status === "available" && option.value === nextOctet)) return;
                onOctetChange(index, nextOctet);
              }}
            >
              <SelectTrigger
                id={triggerId(id, index)}
                aria-label={`${ariaLabel}, octet ${index + 1} of 4`}
                aria-describedby={ariaDescribedBy}
                aria-invalid={invalid || segmentInvalid || undefined}
                className="w-[4.5rem] font-mono tabular-nums"
              >
                <SelectValue placeholder="—">{current === null ? undefined : current}</SelectValue>
              </SelectTrigger>
              <SelectContent>
                {options.map((option) => (
                  <SelectItem
                    key={option.value}
                    value={String(option.value)}
                    disabled={option.status === "retained-invalid"}
                    className="font-mono tabular-nums"
                  >
                    {option.value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </span>
        );
      })}
      {suffix}
    </div>
  );
}

export interface SegmentedIpv4SelectProps extends SharedSegmentedProps {
  readonly selection: SegmentedIpv4Selection;
  readonly onOctetChange: (index: OctetIndex, value: number) => void;
}

export function SegmentedIpv4Select({ selection, onOctetChange, ...props }: SegmentedIpv4SelectProps) {
  return (
    <OctetControls
      {...props}
      invalid={props.invalid === true || selection.validity === "exhausted"}
      octets={selection.octets}
      octetOptions={selection.octetOptions}
      onOctetChange={onOctetChange}
    />
  );
}

export interface NodeAddressSelectProps extends SharedSegmentedProps {
  readonly topology: NodeAddressTopology;
  readonly vnrName: string;
  readonly currentNodeId?: string | undefined;
  readonly value: string | null;
  readonly onValueChange: (value: string | null) => void;
}

export function NodeAddressSelect({
  topology,
  vnrName,
  currentNodeId,
  value,
  onValueChange,
  ...props
}: NodeAddressSelectProps) {
  const availability = useMemo(
    () => createNodeAddressAvailability({
      topology,
      vnrName,
      ...(currentNodeId === undefined ? {} : { currentNodeId }),
    }),
    [currentNodeId, topology, vnrName],
  );
  const selection = useMemo(
    () => createNodeAddressSelection(availability, value),
    [availability, value],
  );

  useEffect(() => {
    if (selection.value !== value) onValueChange(selection.value);
  }, [onValueChange, selection.value, value]);

  return (
    <SegmentedIpv4Select
      {...props}
      selection={selection}
      onOctetChange={(index, octet) => {
        const next = selectNodeAddressOctet(availability, selection, index, octet);
        onValueChange(next.value);
      }}
    />
  );
}

export interface SegmentedCidrSelectProps extends SharedSegmentedProps {
  readonly selection: SegmentedCidrSelection;
  readonly onSelectionChange: (selection: SegmentedCidrSelection) => void;
}

export function SegmentedCidrSelect({
  selection,
  onSelectionChange,
  ...props
}: SegmentedCidrSelectProps) {
  const hostBitsMessageId = `${props.id}-host-bits`;
  const describedBy = [props.ariaDescribedBy, selection.validity === "host_bits_set" ? hostBitsMessageId : undefined]
    .filter((value): value is string => value !== undefined)
    .join(" ") || undefined;
  const prefixSelectable = !props.disabled && selection.prefixOptions.length > 0;
  const prefixControl = (
    <>
      <span aria-hidden="true" className="font-mono text-sm text-muted-foreground">/</span>
      <Select
        {...(selection.prefixLength === null ? {} : { value: String(selection.prefixLength) })}
        disabled={!prefixSelectable}
        required={props.required === true}
        onValueChange={(value) => {
          const prefixLength = parseSelectedDecimal(value);
          if (prefixLength === null || !selection.prefixOptions.includes(prefixLength)) return;
          onSelectionChange(selectCidrPrefix(selection, prefixLength));
        }}
      >
        <SelectTrigger
          id={`${props.id}-prefix`}
          aria-label={`${props.ariaLabel}, prefix length`}
          aria-describedby={describedBy}
          aria-invalid={props.invalid || selection.validity === "host_bits_set" || undefined}
          className="w-[5rem] font-mono tabular-nums"
        >
          <SelectValue placeholder="Prefix">
            {selection.prefixLength === null ? undefined : selection.prefixLength}
          </SelectValue>
        </SelectTrigger>
        <SelectContent>
          {selection.prefixOptions.map((prefixLength) => (
            <SelectItem key={prefixLength} value={String(prefixLength)} className="font-mono tabular-nums">
              {prefixLength}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </>
  );

  return (
    <div className="space-y-1.5">
      <OctetControls
        {...props}
        ariaDescribedBy={describedBy}
        invalid={props.invalid === true || selection.validity === "host_bits_set"}
        octets={selection.octets}
        octetOptions={selection.octetOptions}
        onOctetChange={(index, octet) => onSelectionChange(selectCidrOctet(selection, index, octet))}
        suffix={prefixControl}
      />
      {selection.validity === "host_bits_set" ? (
        <p id={hostBitsMessageId} role="status" aria-live="polite" className="text-xs text-warning">
          This prefix leaves host bits selected. Choose a canonical network boundary before submitting.
        </p>
      ) : null}
    </div>
  );
}
