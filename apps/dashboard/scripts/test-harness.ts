import { startDashboardHarness } from "./harness-runtime";

const harness = await startDashboardHarness();
let stopping = false;

async function stop(): Promise<void> {
  if (stopping) return;
  stopping = true;
  const exitCode = await harness.close();
  process.exit(exitCode === 0 || exitCode === 143 ? 0 : 1);
}

process.once("SIGINT", () => void stop());
process.once("SIGTERM", () => void stop());
