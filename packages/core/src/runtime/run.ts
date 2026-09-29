import { performance } from "node:perf_hooks";
import { Worker } from "node:worker_threads";
import { hashesEqual, sha256Hex } from "../hash.ts";
import { err, ok, type Result, type WasmImport } from "../types.ts";
import type { VerifiedModule } from "./verified.ts";

export type RunErrorCode =
  | "HASH_CHANGED"
  | "INVALID_ARGS"
  | "TIMEOUT"
  | "WORKER_FAILED"
  | "HOST_IMPORT_MISSING"
  | "EXPORT_NOT_FOUND"
  | "TRAP"
  | "INSTANTIATION_FAILED";

export interface RunError {
  readonly code: RunErrorCode;
  readonly message: string;
}

export interface RunOutput {
  /** Numeric return value of the exported function, or null if none. */
  readonly value: number | bigint | null;
  /** Numbers the module passed to env.log (capped). */
  readonly logs: readonly number[];
  readonly durationMs: number;
}

export interface RunCall {
  readonly exportName: string;
  readonly args?: readonly number[];
}

export interface RunLimits {
  /** Wall-clock limit, including startup. Default 1000, max 30000. */
  readonly timeoutMs?: number;
  /** JS heap limit for the worker in MB. Default 64, range 16-512. */
  readonly maxHeapMb?: number;
}

/** Messages between main thread and worker (see worker.ts). */
export interface WorkerInput {
  readonly bytes: Uint8Array;
  readonly exportName: string;
  readonly args: readonly number[];
  readonly imports: readonly WasmImport[];
}
export type WorkerMessage =
  | { readonly ok: true; readonly value: number | bigint | null; readonly logs: readonly number[] }
  | {
      readonly ok: false;
      readonly code: "HOST_IMPORT_MISSING" | "EXPORT_NOT_FOUND" | "TRAP" | "INSTANTIATION_FAILED";
      readonly message: string;
    };

const WORKER_URL = new URL("./worker.ts", import.meta.url);
const MAX_ARGS = 16;
const clamp = (n: number, min: number, max: number) => Math.min(max, Math.max(min, n));

function badArgs(message: string) {
  return err<RunError>({ code: "INVALID_ARGS", message });
}

function isWorkerMessage(value: unknown): value is WorkerMessage {
  if (typeof value !== "object" || value === null) return false;
  const m = value as Record<string, unknown>;
  return m.ok === true ? Array.isArray(m.logs) : m.ok === false && typeof m.code === "string";
}

/**
 * Run one exported function of a verified module in an isolated worker.
 *
 * Only a VerifiedModule (from authorize()) is accepted. The bytes are
 * re-hashed immediately before running, so a module altered in memory after
 * authorization is rejected.
 */
export function runModule(
  module: VerifiedModule,
  call: RunCall,
  limits: RunLimits = {},
): Promise<Result<RunOutput, RunError>> {
  const args = call.args ?? [];
  if (typeof call.exportName !== "string" || call.exportName === "" || call.exportName.length > 100) {
    return Promise.resolve(badArgs("exportName must be a non-empty string (max 100 chars)."));
  }
  if (args.length > MAX_ARGS || !args.every((a) => typeof a === "number" && Number.isFinite(a))) {
    return Promise.resolve(badArgs(`args must be at most ${MAX_ARGS} finite numbers.`));
  }

  if (!hashesEqual(sha256Hex(module.bytes), module.facts.sha256)) {
    return Promise.resolve(
      err<RunError>({
        code: "HASH_CHANGED",
        message: "Module bytes no longer match the verified hash.",
      }),
    );
  }

  const timeoutMs = clamp(limits.timeoutMs ?? 1000, 1, 30_000);
  const maxHeapMb = clamp(limits.maxHeapMb ?? 64, 16, 512);
  const started = performance.now();

  return new Promise((resolve) => {
    let settled = false;
    const workerData: WorkerInput = {
      bytes: module.bytes,
      exportName: call.exportName,
      args,
      imports: module.facts.imports,
    };
    const worker = new Worker(WORKER_URL, {
      workerData,
      env: {}, // the worker sees no environment variables
      argv: [],
      stdout: true,
      stderr: true,
      resourceLimits: {
        maxOldGenerationSizeMb: maxHeapMb,
        maxYoungGenerationSizeMb: 16,
        stackSizeMb: 4,
      },
    });

    const finish = (result: Result<RunOutput, RunError>) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void worker.terminate();
      resolve(result);
    };
    const fail = (code: RunErrorCode, message: string) => finish(err({ code, message }));

    const timer = setTimeout(
      () => fail("TIMEOUT", `Execution exceeded ${timeoutMs} ms and was stopped.`),
      timeoutMs,
    );

    worker.once("message", (msg: unknown) => {
      if (!isWorkerMessage(msg)) return fail("WORKER_FAILED", "Worker sent an invalid message.");
      if (msg.ok) {
        return finish(
          ok({ value: msg.value, logs: msg.logs, durationMs: performance.now() - started }),
        );
      }
      return fail(msg.code, msg.message);
    });
    worker.once("error", (e) => fail("WORKER_FAILED", e instanceof Error ? e.message : "Worker crashed."));
    worker.once("exit", (code) =>
      fail("WORKER_FAILED", `Worker exited (code ${code}) without a result.`),
    );
  });
}
