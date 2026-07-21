"use client";

import { Alert, AlertDescription, AlertTitle } from "@ntip/ui";
import { CircleAlert } from "lucide-react";
import { forwardRef } from "react";
import {
  actionableApiError,
  BrowserApiError,
  type ApiFieldViolation,
} from "@/lib/browser-api-error";

export interface InventoryFormErrorState {
  readonly message: string;
  readonly requestId: string | null;
  readonly violations: readonly ApiFieldViolation[];
}

export function inventoryFormErrorState(
  reason: unknown,
  resourceLabel: string,
): InventoryFormErrorState {
  const violations = reason instanceof BrowserApiError ? reason.violations : [];
  return {
    message: violations[0]?.message ?? actionableApiError(reason, { resourceLabel }),
    requestId: reason instanceof BrowserApiError ? reason.requestId : null,
    violations,
  };
}

export const InventoryErrorSummary = forwardRef<
  HTMLDivElement,
  Readonly<{ error: InventoryFormErrorState | null; title: string }>
>(function InventoryErrorSummary({ error, title }, ref) {
  if (error === null) return null;
  return (
    <div ref={ref} tabIndex={-1} className="focus:outline-none">
      <Alert tone="critical">
        <CircleAlert aria-hidden="true" />
        <AlertTitle>{title}</AlertTitle>
        <AlertDescription>
          <p>{error.message}</p>
          {error.violations.length === 0 ? null : (
            <ul className="mt-2 list-disc space-y-1 ps-4">
              {error.violations.map((violation) => (
                <li key={`${violation.field}:${violation.code}`}>{violation.message}</li>
              ))}
            </ul>
          )}
          {error.requestId === null ? null : (
            <p className="mt-2 font-mono text-[0.6875rem] text-muted-foreground">
              Request ID: {error.requestId}
            </p>
          )}
        </AlertDescription>
      </Alert>
    </div>
  );
});

export function fieldError(
  error: InventoryFormErrorState | null,
  field: string,
): ApiFieldViolation | null {
  return error?.violations.find((violation) => violation.field === field) ?? null;
}

export function InlineFieldError({ id, violation }: Readonly<{
  id: string;
  violation: ApiFieldViolation | null;
}>) {
  if (violation === null) return null;
  return (
    <p id={id} role="status" aria-live="polite" className="text-xs text-destructive">
      {violation.message}
    </p>
  );
}
