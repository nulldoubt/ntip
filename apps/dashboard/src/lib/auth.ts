import "server-only";

import type { components } from "@ntip/contracts";
import { cache } from "react";
import { apiGet } from "@/lib/server-api";

export type AuthContext = components["schemas"]["AuthContext"];
export type Role = components["schemas"]["Role"];

export const getAuthContext = cache(async (): Promise<AuthContext> => {
  return apiGet<AuthContext>("/auth/me");
});
