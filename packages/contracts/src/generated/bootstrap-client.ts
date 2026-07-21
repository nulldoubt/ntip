/**
 * This file is generated from openapi/ntip-bootstrap-v1.yaml.
 * Do not make direct changes to the file.
 */

import createClient from "openapi-fetch";
import type { Client, ClientOptions } from "openapi-fetch";
import type { paths } from "./bootstrap-schema";

export type NtipBootstrapClient = Client<paths>;

export function createNtipBootstrapClient(options: ClientOptions = {}): NtipBootstrapClient {
  return createClient<paths>({
    baseUrl: "",
    credentials: "omit",
    redirect: "error",
    ...options,
  });
}
