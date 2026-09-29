/**
 * Runs inside a worker thread. The WebAssembly code can only reach what is
 * handed to it through `importObject` below: nothing else.
 */
import { parentPort, workerData } from "node:worker_threads";
import type { WorkerInput, WorkerMessage } from "./run.ts";

const input = workerData as WorkerInput;
const MAX_LOGS = 1000;
const logs: number[] = [];

/** The ONLY host functions a module can ever be given. */
const HOST_FUNCTIONS = new Map<string, (...args: number[]) => void>([
  [
    "env.log",
    (value = 0) => {
      if (logs.length < MAX_LOGS) logs.push(value);
    },
  ],
]);

function execute(): WorkerMessage {
  const fail = (code: Extract<WorkerMessage, { ok: false }>["code"], message: string): WorkerMessage => ({
    ok: false,
    code,
    message,
  });

  // Null-prototype objects so names like "__proto__" are just names.
  const importObject: Record<string, Record<string, unknown>> = Object.create(null);
  for (const imp of input.imports) {
    const host =
      imp.kind === "function"
        ? HOST_FUNCTIONS.get(`${imp.module}.${imp.name}`)
        : undefined;
    if (!host) {
      return fail(
        "HOST_IMPORT_MISSING",
        `No host implementation for import ${imp.module}.${imp.name}.`,
      );
    }
    (importObject[imp.module] ??= Object.create(null) as Record<string, unknown>)[imp.name] = host;
  }

  try {
    const module = new WebAssembly.Module(input.bytes as BufferSource);
    const instance = new WebAssembly.Instance(module, importObject as WebAssembly.Imports);
    const fn = (instance.exports as Record<string, unknown>)[input.exportName];
    if (typeof fn !== "function") {
      return fail("EXPORT_NOT_FOUND", `Export "${input.exportName}" is not a function.`);
    }
    const result: unknown = fn(...input.args);
    return {
      ok: true,
      value: typeof result === "number" || typeof result === "bigint" ? result : null,
      logs,
    };
  } catch (cause) {
    if (cause instanceof WebAssembly.RuntimeError) {
      return fail("TRAP", cause.message);
    }
    return fail(
      "INSTANTIATION_FAILED",
      cause instanceof Error ? cause.message : "Module could not be instantiated.",
    );
  }
}

parentPort?.postMessage(execute());
