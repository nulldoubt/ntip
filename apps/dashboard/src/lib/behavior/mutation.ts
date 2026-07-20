import type { components } from "@ntip/contracts";

export type MutationMethod = "POST" | "PUT" | "PATCH" | "DELETE";
export type MutationResponseKind = "json" | "empty" | "one-time";

type CsrfToken = components["schemas"]["AuthContext"]["csrfToken"];
type EntityTag = components["schemas"]["EntityTag"];

export interface MutationAttemptOptions<TBody> {
  readonly body?: TBody;
  readonly csrfToken: CsrfToken;
  readonly headers?: HeadersInit;
  readonly idempotencyKeyFactory?: () => string;
  readonly ifMatch?: EntityTag;
  readonly method: MutationMethod;
  readonly requiresIfMatch?: boolean;
  readonly responseKind?: MutationResponseKind;
  readonly url: string | URL;
}

export interface MutationAttempt {
  readonly automaticTransportRetryAllowed: boolean;
  readonly idempotencyKey: string | null;
  readonly responseKind: MutationResponseKind;
  buildRequest(): Request;
}

function randomIdempotencyKey(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function requireNonEmpty(value: string, name: string): void {
  if (value.trim().length === 0) throw new TypeError(`${name} must not be empty`);
}

export function createMutationAttempt<TBody = never>(options: MutationAttemptOptions<TBody>): MutationAttempt {
  requireNonEmpty(options.csrfToken, "csrfToken");
  if (options.requiresIfMatch === true && options.ifMatch === undefined) {
    throw new TypeError("ifMatch is required for this mutation");
  }

  const responseKind = options.responseKind ?? "json";
  const idempotencyKey = options.method === "POST"
    ? (options.idempotencyKeyFactory ?? randomIdempotencyKey)()
    : null;
  if (idempotencyKey !== null) requireNonEmpty(idempotencyKey, "idempotencyKey");
  const serializedBody = options.body === undefined ? undefined : JSON.stringify(options.body);
  let oneTimeRequestBuilt = false;

  return Object.freeze({
    automaticTransportRetryAllowed: options.method === "POST" && responseKind !== "one-time",
    idempotencyKey,
    responseKind,
    buildRequest(): Request {
      if (responseKind === "one-time" && oneTimeRequestBuilt) {
        throw new Error("A one-time-response mutation request cannot be retried");
      }
      const headers = new Headers(options.headers);
      headers.set("Accept", "application/json");
      headers.set("X-CSRF-Token", options.csrfToken);
      if (serializedBody !== undefined) headers.set("Content-Type", "application/json");
      if (options.ifMatch !== undefined) headers.set("If-Match", options.ifMatch);
      if (idempotencyKey !== null) headers.set("Idempotency-Key", idempotencyKey);

      const requestInit: RequestInit = {
        method: options.method,
        headers,
        cache: "no-store",
        credentials: "same-origin",
        redirect: "error",
      };
      if (serializedBody !== undefined) requestInit.body = serializedBody;
      const request = new Request(options.url, requestInit);
      if (responseKind === "one-time") oneTimeRequestBuilt = true;
      return request;
    },
  });
}
