import { describe, expect, test } from "bun:test";

import { responseError as nodeResponseError } from "../../src/components/nodes/browser-api";
import {
  actionableError as actionableVnrError,
  ClientApiError,
  errorFromResponse as vnrErrorFromResponse,
} from "../../src/components/vnrs/client-api";
import {
  actionableApiError,
  browserApiErrorFromResponse,
  BrowserApiError,
  readBrowserApiJson,
} from "../../src/lib/browser-api-error";

const requestId = "018f8d95b0f74d669f16a606fa9c87e2";

describe("browser API errors", () => {
  test("preserves the canonical status, code, request ID, and field violations", async () => {
    const response = Response.json(
      {
        error: {
          code: "invariant_violation",
          message: "The address is reserved for the Master.",
          requestId,
          violations: [
            {
              field: "address",
              code: "address_reserved_master",
              message: "Choose another address in the VNR.",
            },
          ],
        },
      },
      { status: 409, headers: { "x-request-id": requestId } },
    );

    const error = await browserApiErrorFromResponse(response);

    expect(error).toBeInstanceOf(BrowserApiError);
    expect(error).toMatchObject({
      status: 409,
      code: "invariant_violation",
      message: "The address is reserved for the Master.",
      requestId,
      violations: [
        {
          field: "address",
          code: "address_reserved_master",
          message: "Choose another address in the VNR.",
        },
      ],
    });
  });

  test("retains response evidence and provides an actionable malformed-body fallback", async () => {
    const response = new Response("not-json", {
      status: 503,
      headers: { "x-request-id": requestId, "content-type": "text/plain" },
    });

    const error = await browserApiErrorFromResponse(response);

    expect(error).toMatchObject({
      status: 503,
      code: "invalid_upstream_response",
      requestId,
      violations: [],
    });
    expect(actionableApiError(error, { includeRequestId: true })).toBe(
      `The management service is temporarily unavailable. Try again shortly. (request ${requestId})`,
    );
  });

  test("keeps additive unknown violation codes and top-level messages usable", async () => {
    const response = Response.json(
      {
        error: {
          code: "validation_failed",
          message: "Review the highlighted value.",
          requestId,
          violations: [
            { field: "prefix", code: "future_inventory_code", message: "A future constraint failed." },
          ],
        },
      },
      { status: 400 },
    );

    const error = await browserApiErrorFromResponse(response);

    expect(error.violations[0]?.code).toBe("future_inventory_code");
    expect(actionableApiError(error)).toBe("Review the highlighted value.");
  });

  test("reports invalid JSON from an otherwise successful response as a typed API error", async () => {
    const response = new Response("not-json", {
      status: 200,
      headers: { "x-request-id": requestId },
    });

    await expect(readBrowserApiJson(response)).rejects.toMatchObject({
      status: 502,
      code: "invalid_upstream_response",
      requestId,
    });
  });

  test("keeps VNR and Node compatibility exports on the shared implementation", async () => {
    const vnrError = await vnrErrorFromResponse(
      Response.json(
        { error: { code: "precondition_failed", message: "Stale.", requestId } },
        { status: 412 },
      ),
    );
    const nodeError = await nodeResponseError(
      Response.json(
        { error: { code: "conflict", message: "Already used.", requestId, violations: [] } },
        { status: 409 },
      ),
    );

    expect(vnrError).toBeInstanceOf(ClientApiError);
    expect(vnrError).toBeInstanceOf(BrowserApiError);
    expect(actionableVnrError(vnrError)).toBe(
      "This VNR changed after it was loaded. Review the current values and try again.",
    );
    expect(nodeError).toBeInstanceOf(BrowserApiError);
    expect(nodeError).toMatchObject({ status: 409, code: "conflict", requestId });
  });
});
