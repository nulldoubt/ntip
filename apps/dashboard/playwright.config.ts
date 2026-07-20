import { defineConfig, devices } from "@playwright/test";
import { resolve } from "node:path";

const artifactRoot = resolve(import.meta.dirname, "../../output/playwright");
const httpsPort = Number(process.env.NTIP_E2E_HTTPS_PORT ?? "3443");
const controlPort = Number(process.env.NTIP_E2E_CONTROL_PORT ?? "8790");

export default defineConfig({
  testDir: "./test/e2e",
  outputDir: resolve(artifactRoot, "test-results"),
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  timeout: 45_000,
  expect: { timeout: 8_000 },
  reporter: [
    ["line"],
    ["html", { open: "never", outputFolder: resolve(artifactRoot, "html-report") }],
  ],
  use: {
    ...devices["Desktop Chrome"],
    baseURL: `https://127.0.0.1:${httpsPort}`,
    ignoreHTTPSErrors: true,
    locale: "en-US",
    timezoneId: "UTC",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    viewport: { width: 1440, height: 900 },
  },
  webServer: {
    command: "bun run build && bun run scripts/test-harness.ts",
    cwd: import.meta.dirname,
    env: {
      ...process.env,
      NEXT_TELEMETRY_DISABLED: "1",
      NTIP_E2E_HTTPS_PORT: String(httpsPort),
      NTIP_E2E_CONTROL_PORT: String(controlPort),
      TZ: "UTC",
    },
    url: `http://127.0.0.1:${controlPort}/ready`,
    reuseExistingServer: false,
    timeout: 240_000,
    stdout: "pipe",
    stderr: "pipe",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
