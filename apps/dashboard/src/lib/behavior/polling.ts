export interface PollingClock {
  now(): number;
  setTimeout(callback: () => void, delayMilliseconds: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface PollingGate {
  isOnline(): boolean;
  isVisible(): boolean;
  subscribe(listener: () => void): () => void;
}

export type PollingPauseReason = "hidden" | "offline";
export type PollingFreshness = "empty" | "fresh" | "stale";
export type PollingPhase = "idle" | "waiting" | "polling" | "paused";

export interface PollingSnapshot<T> {
  readonly data: T | null;
  readonly error: string | null;
  readonly failedAttempts: number;
  readonly freshness: PollingFreshness;
  readonly lastAttemptAt: number | null;
  readonly lastSuccessAt: number | null;
  readonly nextAttemptAt: number | null;
  readonly pauseReason: PollingPauseReason | null;
  readonly phase: PollingPhase;
}

interface QueuedTask<T> {
  readonly run: () => Promise<T>;
  readonly signal: AbortSignal | undefined;
  readonly resolve: (value: T) => void;
  readonly reject: (reason: unknown) => void;
  removeAbortListener: (() => void) | null;
}

function abortError(): DOMException {
  return new DOMException("The polling task was aborted", "AbortError");
}

export class BoundedPollingScheduler {
  readonly #maximumConcurrent: number;
  #activeCount = 0;
  #queue: QueuedTask<unknown>[] = [];

  constructor(maximumConcurrent = 2) {
    if (!Number.isSafeInteger(maximumConcurrent) || maximumConcurrent < 1) {
      throw new RangeError("maximumConcurrent must be a positive safe integer");
    }
    this.#maximumConcurrent = maximumConcurrent;
  }

  get activeCount(): number {
    return this.#activeCount;
  }

  get maximumConcurrent(): number {
    return this.#maximumConcurrent;
  }

  get queuedCount(): number {
    return this.#queue.length;
  }

  schedule<T>(run: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    if (signal?.aborted === true) {
      return Promise.reject(abortError());
    }

    return new Promise<T>((resolve, reject) => {
      const task: QueuedTask<T> = {
        run,
        signal,
        resolve,
        reject,
        removeAbortListener: null,
      };

      if (signal !== undefined) {
        const onAbort = (): void => {
          const index = this.#queue.indexOf(task as QueuedTask<unknown>);
          if (index === -1) return;
          this.#queue.splice(index, 1);
          task.removeAbortListener?.();
          task.removeAbortListener = null;
          reject(abortError());
        };
        signal.addEventListener("abort", onAbort, { once: true });
        task.removeAbortListener = () => signal.removeEventListener("abort", onAbort);
      }

      this.#queue.push(task as QueuedTask<unknown>);
      this.#drain();
    });
  }

  #drain(): void {
    while (this.#activeCount < this.#maximumConcurrent) {
      const task = this.#queue.shift();
      if (task === undefined) return;

      task.removeAbortListener?.();
      task.removeAbortListener = null;
      if (task.signal?.aborted === true) {
        task.reject(abortError());
        continue;
      }

      this.#activeCount += 1;
      void task
        .run()
        .then(task.resolve, task.reject)
        .finally(() => {
          this.#activeCount -= 1;
          this.#drain();
        });
    }
  }
}

export const globalPollingScheduler = new BoundedPollingScheduler(2);

const systemClock: PollingClock = {
  now: () => Date.now(),
  setTimeout: (callback, delayMilliseconds) => globalThis.setTimeout(callback, delayMilliseconds),
  clearTimeout: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export function createBrowserPollingGate(): PollingGate {
  return {
    isOnline: () => (typeof navigator === "undefined" ? true : navigator.onLine),
    isVisible: () => (typeof document === "undefined" ? true : document.visibilityState === "visible"),
    subscribe(listener) {
      if (typeof window === "undefined" || typeof document === "undefined") return () => undefined;
      window.addEventListener("online", listener);
      window.addEventListener("offline", listener);
      document.addEventListener("visibilitychange", listener);
      return () => {
        window.removeEventListener("online", listener);
        window.removeEventListener("offline", listener);
        document.removeEventListener("visibilitychange", listener);
      };
    },
  };
}

export const FAILURE_BACKOFF_MILLISECONDS = [20_000, 40_000, 60_000] as const;

export function failureBackoffMilliseconds(failedAttempts: number): number {
  if (!Number.isFinite(failedAttempts) || failedAttempts <= 1) return FAILURE_BACKOFF_MILLISECONDS[0];
  if (failedAttempts === 2) return FAILURE_BACKOFF_MILLISECONDS[1];
  return FAILURE_BACKOFF_MILLISECONDS[2];
}

export function jitteredIntervalMilliseconds(intervalMilliseconds: number, randomValue: number): number {
  if (!Number.isFinite(intervalMilliseconds) || intervalMilliseconds < 0) {
    throw new RangeError("intervalMilliseconds must be a non-negative finite number");
  }
  const normalizedRandom = Math.min(1, Math.max(0, Number.isFinite(randomValue) ? randomValue : 0.5));
  return Math.round(intervalMilliseconds * (0.9 + normalizedRandom * 0.2));
}

export interface PollingControllerOptions<T> {
  readonly fetch: (signal: AbortSignal) => Promise<T>;
  readonly intervalMilliseconds: number;
  readonly clock?: PollingClock;
  readonly gate?: PollingGate;
  readonly initialData?: T;
  readonly random?: () => number;
  readonly scheduler?: BoundedPollingScheduler;
}

function errorMessage(reason: unknown): string {
  return reason instanceof Error ? reason.message : "Polling failed";
}

function pauseReason(gate: PollingGate): PollingPauseReason | null {
  if (!gate.isOnline()) return "offline";
  if (!gate.isVisible()) return "hidden";
  return null;
}

export class PollingController<T> {
  readonly #clock: PollingClock;
  readonly #fetch: (signal: AbortSignal) => Promise<T>;
  readonly #gate: PollingGate;
  readonly #intervalMilliseconds: number;
  readonly #listeners = new Set<() => void>();
  readonly #random: () => number;
  readonly #scheduler: BoundedPollingScheduler;
  #activeAbortController: AbortController | null = null;
  #gateUnsubscribe: (() => void) | null = null;
  #started = false;
  #timeoutHandle: unknown = null;
  #snapshot: PollingSnapshot<T>;

  constructor(options: PollingControllerOptions<T>) {
    if (!Number.isFinite(options.intervalMilliseconds) || options.intervalMilliseconds <= 0) {
      throw new RangeError("intervalMilliseconds must be a positive finite number");
    }

    this.#clock = options.clock ?? systemClock;
    this.#fetch = options.fetch;
    this.#gate = options.gate ?? createBrowserPollingGate();
    this.#intervalMilliseconds = options.intervalMilliseconds;
    this.#random = options.random ?? Math.random;
    this.#scheduler = options.scheduler ?? globalPollingScheduler;
    const hasInitialData = options.initialData !== undefined;
    this.#snapshot = {
      data: options.initialData ?? null,
      error: null,
      failedAttempts: 0,
      freshness: hasInitialData ? "stale" : "empty",
      lastAttemptAt: null,
      lastSuccessAt: null,
      nextAttemptAt: null,
      pauseReason: null,
      phase: "idle",
    };
  }

  getSnapshot = (): PollingSnapshot<T> => this.#snapshot;

  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  };

  start(): void {
    if (this.#started) return;
    this.#started = true;
    this.#gateUnsubscribe = this.#gate.subscribe(this.#handleGateChange);
    this.#handleGateChange();
  }

  stop(): void {
    if (!this.#started) return;
    this.#started = false;
    this.#gateUnsubscribe?.();
    this.#gateUnsubscribe = null;
    this.#clearTimer();
    this.#activeAbortController?.abort();
    this.#activeAbortController = null;
    this.#replaceSnapshot({
      ...this.#snapshot,
      nextAttemptAt: null,
      pauseReason: null,
      phase: "idle",
    });
  }

  refresh(): void {
    if (!this.#started) return;
    this.#activeAbortController?.abort();
    this.#activeAbortController = null;
    this.#clearTimer();
    this.#handleGateChange();
  }

  readonly #handleGateChange = (): void => {
    if (!this.#started) return;
    const reason = pauseReason(this.#gate);
    if (reason !== null) {
      this.#clearTimer();
      this.#activeAbortController?.abort();
      this.#activeAbortController = null;
      this.#replaceSnapshot({
        ...this.#snapshot,
        freshness: this.#snapshot.data === null ? "empty" : "stale",
        nextAttemptAt: null,
        pauseReason: reason,
        phase: "paused",
      });
      return;
    }

    if (this.#snapshot.phase === "polling" && this.#activeAbortController !== null) return;
    this.#arm(0);
  };

  #arm(delayMilliseconds: number): void {
    if (!this.#started) return;
    this.#clearTimer();
    const nextAttemptAt = this.#clock.now() + delayMilliseconds;
    this.#replaceSnapshot({
      ...this.#snapshot,
      nextAttemptAt,
      pauseReason: null,
      phase: "waiting",
    });
    this.#timeoutHandle = this.#clock.setTimeout(() => {
      this.#timeoutHandle = null;
      void this.#poll();
    }, delayMilliseconds);
  }

  #clearTimer(): void {
    if (this.#timeoutHandle === null) return;
    this.#clock.clearTimeout(this.#timeoutHandle);
    this.#timeoutHandle = null;
  }

  async #poll(): Promise<void> {
    if (!this.#started) return;
    const reason = pauseReason(this.#gate);
    if (reason !== null) {
      this.#handleGateChange();
      return;
    }

    const abortController = new AbortController();
    this.#activeAbortController = abortController;
    this.#replaceSnapshot({
      ...this.#snapshot,
      lastAttemptAt: this.#clock.now(),
      nextAttemptAt: null,
      pauseReason: null,
      phase: "polling",
    });

    try {
      const data = await this.#scheduler.schedule(() => this.#fetch(abortController.signal), abortController.signal);
      if (!this.#started || this.#activeAbortController !== abortController) return;
      this.#activeAbortController = null;
      this.#replaceSnapshot({
        data,
        error: null,
        failedAttempts: 0,
        freshness: "fresh",
        lastAttemptAt: this.#snapshot.lastAttemptAt,
        lastSuccessAt: this.#clock.now(),
        nextAttemptAt: null,
        pauseReason: null,
        phase: "waiting",
      });
      this.#arm(jitteredIntervalMilliseconds(this.#intervalMilliseconds, this.#random()));
    } catch (reason) {
      if (!this.#started || this.#activeAbortController !== abortController) return;
      this.#activeAbortController = null;
      if (abortController.signal.aborted) return;
      const failedAttempts = this.#snapshot.failedAttempts + 1;
      this.#replaceSnapshot({
        ...this.#snapshot,
        error: errorMessage(reason),
        failedAttempts,
        freshness: this.#snapshot.data === null ? "empty" : "stale",
        phase: "waiting",
      });
      this.#arm(failureBackoffMilliseconds(failedAttempts));
    }
  }

  #replaceSnapshot(snapshot: PollingSnapshot<T>): void {
    this.#snapshot = snapshot;
    for (const listener of this.#listeners) listener();
  }
}
