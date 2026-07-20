/**
 * This file is generated from openapi/ntip-v1.yaml.
 * Do not make direct changes to the file.
 */

import createClient from "openapi-fetch";
import type { Client, ClientOptions } from "openapi-fetch";
import type { paths } from "./schema";

export type NtipApiClient = Client<paths>;

export function createNtipApiClient(options: ClientOptions = {}): NtipApiClient {
  return createClient<paths>({
    baseUrl: "/api/v1",
    credentials: "same-origin",
    ...options,
  });
}
