import type { Page } from "@playwright/test";
import type { FixtureSnapshot } from "./fixture-api";

export const credentials = {
  operator: { username: "operator", password: "operator-password-2026" },
  superuser: { username: "superuser", password: "superuser-password-2026" },
  temporary: { username: "temporary", password: "temporary-password-2026" },
  viewer: { username: "viewer", password: "viewer-password-2026" },
} as const;

const controlOrigin = `http://127.0.0.1:${process.env.NTIP_E2E_CONTROL_PORT ?? "8790"}`;

async function control(path: string, init?: RequestInit): Promise<Response> {
  const response = await fetch(`${controlOrigin}${path}`, init);
  if (!response.ok) throw new Error(`fixture control ${path} failed (${response.status})`);
  return response;
}

export async function resetFixture(): Promise<void> {
  await control("/reset", { method: "POST" });
}

export async function resetMetrics(): Promise<void> {
  await control("/metrics/reset", { method: "POST" });
}

export async function clearFaults(): Promise<void> {
  await control("/faults", { method: "DELETE" });
}

export async function setFault(options: Readonly<{
  path: `/api/v1/${string}`;
  status?: number;
  delayMilliseconds?: number;
  remaining?: number;
}>): Promise<void> {
  await control("/fault", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(options),
  });
}

export async function fixtureSnapshot(): Promise<FixtureSnapshot> {
  return await (await control("/snapshot")).json() as FixtureSnapshot;
}

export async function loginAs(page: Page, principal: keyof typeof credentials): Promise<void> {
  const credential = credentials[principal];
  await page.goto("/login");
  await page.getByLabel("Username").fill(credential.username);
  await page.getByLabel("Password", { exact: true }).fill(credential.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  if (principal !== "temporary") await page.waitForURL("**/overview");
}

export async function useReducedMotion(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: "reduce" });
}
