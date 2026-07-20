import { describe, expect, test } from "bun:test";

import {
  BoundedPollingScheduler,
  PollingController,
  failureBackoffMilliseconds,
  globalPollingScheduler,
  jitteredIntervalMilliseconds,
  type PollingClock,
  type PollingGate,
} from "../../src/lib/behavior/polling";

async function flushPromises(): Promise<void> {
  for (let index = 0; index < 12; index += 1) await Promise.resolve();
}

class FakeClock implements PollingClock {
  #nextId = 1;
  #now = 0;
  readonly #timers = new Map<number, { readonly at: number; readonly callback: () => void }>();

  now(): number {
    return this.#now;
  }

  setTimeout(callback: () => void, delayMilliseconds: number): unknown {
    const id = this.#nextId;
    this.#nextId += 1;
    this.#timers.set(id, { at: this.#now + delayMilliseconds, callback });
    return id;
  }

  clearTimeout(handle: unknown): void {
    if (typeof handle === "number") this.#timers.delete(handle);
  }

  async advanceBy(delayMilliseconds: number): Promise<void> {
    const target = this.#now + delayMilliseconds;
    while (true) {
      const due = [...this.#timers.entries()]
        .filter(([, timer]) => timer.at <= target)
        .sort((left, right) => left[1].at - right[1].at || left[0] - right[0])[0];
      if (due === undefined) break;
      this.#now = due[1].at;
      this.#timers.delete(due[0]);
      due[1].callback();
      await flushPromises();
    }
    this.#now = target;
    await flushPromises();
  }
}

class MutableGate implements PollingGate {
  #online = true;
  #visible = true;
  readonly #listeners = new Set<() => void>();

  isOnline(): boolean {
    return this.#online;
  }

  isVisible(): boolean {
    return this.#visible;
  }

  subscribe(listener: () => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  setOnline(online: boolean): void {
    this.#online = online;
    for (const listener of this.#listeners) listener();
  }

  setVisible(visible: boolean): void {
    this.#visible = visible;
    for (const listener of this.#listeners) listener();
  }
}

describe("BoundedPollingScheduler", () => {
  test("the shared scheduler admits at most two background requests", async () => {
    expect(globalPollingScheduler.maximumConcurrent).toBe(2);

    const scheduler = new BoundedPollingScheduler(2);
    const releases: Array<() => void> = [];
    let active = 0;
    let maximumObserved = 0;

    const tasks = Array.from({ length: 5 }, (_, index) => scheduler.schedule(async () => {
      active += 1;
      maximumObserved = Math.max(maximumObserved, active);
      await new Promise<void>((resolve) => releases.push(resolve));
      active -= 1;
      return index;
    }));

    expect(active).toBe(2);
    expect(scheduler.activeCount).toBe(2);
    expect(scheduler.queuedCount).toBe(3);

    while (releases.length > 0 || scheduler.queuedCount > 0 || scheduler.activeCount > 0) {
      const release = releases.shift();
      if (release !== undefined) release();
      await flushPromises();
    }

    expect(await Promise.all(tasks)).toEqual([0, 1, 2, 3, 4]);
    expect(maximumObserved).toBe(2);
  });

  test("an aborted queued request never consumes an admission slot", async () => {
    const scheduler = new BoundedPollingScheduler(1);
    let releaseFirst: (() => void) | undefined;
    const first = scheduler.schedule(() => new Promise<void>((resolve) => {
      releaseFirst = resolve;
    }));
    const abortController = new AbortController();
    let secondRan = false;
    const second = scheduler.schedule(async () => {
      secondRan = true;
    }, abortController.signal);

    abortController.abort();
    await expect(second).rejects.toHaveProperty("name", "AbortError");
    releaseFirst?.();
    await first;
    await flushPromises();

    expect(secondRan).toBeFalse();
    expect(scheduler.activeCount).toBe(0);
  });
});

describe("PollingController", () => {
  test("retains last-known-good data and uses the 20/40/60 second failure backoff", async () => {
    const clock = new FakeClock();
    const gate = new MutableGate();
    const scheduler = new BoundedPollingScheduler(2);
    let attempts = 0;
    const controller = new PollingController({
      clock,
      gate,
      scheduler,
      intervalMilliseconds: 10_000,
      random: () => 0.5,
      fetch: async () => {
        attempts += 1;
        if (attempts === 1) return { generation: 7 };
        throw new Error(`failure-${attempts}`);
      },
    });

    controller.start();
    await clock.advanceBy(0);
    expect(controller.getSnapshot()).toMatchObject({
      data: { generation: 7 },
      freshness: "fresh",
      failedAttempts: 0,
      nextAttemptAt: 10_000,
    });

    await clock.advanceBy(10_000);
    expect(controller.getSnapshot()).toMatchObject({
      data: { generation: 7 },
      error: "failure-2",
      freshness: "stale",
      failedAttempts: 1,
      nextAttemptAt: 30_000,
    });

    await clock.advanceBy(20_000);
    expect(controller.getSnapshot().nextAttemptAt).toBe(70_000);
    expect(controller.getSnapshot().failedAttempts).toBe(2);

    await clock.advanceBy(40_000);
    expect(controller.getSnapshot().nextAttemptAt).toBe(130_000);
    expect(controller.getSnapshot().failedAttempts).toBe(3);
    expect(controller.getSnapshot().data).toEqual({ generation: 7 });

    await clock.advanceBy(60_000);
    expect(controller.getSnapshot().nextAttemptAt).toBe(190_000);
    expect(controller.getSnapshot().failedAttempts).toBe(4);
    controller.stop();
  });

  test("pauses while offline or hidden and resumes immediately", async () => {
    const clock = new FakeClock();
    const gate = new MutableGate();
    const controller = new PollingController({
      clock,
      gate,
      scheduler: new BoundedPollingScheduler(2),
      intervalMilliseconds: 10_000,
      random: () => 0.5,
      fetch: async () => "current",
    });

    gate.setOnline(false);
    controller.start();
    await clock.advanceBy(100_000);
    expect(controller.getSnapshot()).toMatchObject({
      data: null,
      phase: "paused",
      pauseReason: "offline",
      nextAttemptAt: null,
    });

    gate.setOnline(true);
    await clock.advanceBy(0);
    expect(controller.getSnapshot()).toMatchObject({ data: "current", freshness: "fresh" });

    gate.setVisible(false);
    expect(controller.getSnapshot()).toMatchObject({
      data: "current",
      freshness: "stale",
      phase: "paused",
      pauseReason: "hidden",
      nextAttemptAt: null,
    });
    await clock.advanceBy(100_000);
    gate.setVisible(true);
    await clock.advanceBy(0);
    expect(controller.getSnapshot()).toMatchObject({
      data: "current",
      freshness: "fresh",
      failedAttempts: 0,
    });
    controller.stop();
  });

  test("an explicit refresh replaces an active poll without stalling", async () => {
    const clock = new FakeClock();
    let attempts = 0;
    const controller = new PollingController({
      clock,
      gate: new MutableGate(),
      scheduler: new BoundedPollingScheduler(2),
      intervalMilliseconds: 10_000,
      random: () => 0.5,
      fetch: (signal) => {
        attempts += 1;
        if (attempts === 2) return Promise.resolve("replacement");
        return new Promise<string>((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
        });
      },
    });

    controller.start();
    await clock.advanceBy(0);
    expect(controller.getSnapshot().phase).toBe("polling");
    controller.refresh();
    await clock.advanceBy(0);

    expect(attempts).toBe(2);
    expect(controller.getSnapshot()).toMatchObject({ data: "replacement", freshness: "fresh" });
    controller.stop();
  });

  test("jitter and failure schedules are bounded and deterministic", () => {
    expect(jitteredIntervalMilliseconds(10_000, 0)).toBe(9_000);
    expect(jitteredIntervalMilliseconds(10_000, 0.5)).toBe(10_000);
    expect(jitteredIntervalMilliseconds(10_000, 1)).toBe(11_000);
    expect(failureBackoffMilliseconds(1)).toBe(20_000);
    expect(failureBackoffMilliseconds(2)).toBe(40_000);
    expect(failureBackoffMilliseconds(3)).toBe(60_000);
    expect(failureBackoffMilliseconds(30)).toBe(60_000);
  });
});
