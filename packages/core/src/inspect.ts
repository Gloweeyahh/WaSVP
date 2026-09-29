import { sha256Hex } from "./hash.ts";
import {
  err,
  ok,
  type ExternalKind,
  type InspectError,
  type ModuleFacts,
  type Result,
} from "./types.ts";

/** Default cap: 10 MiB. Callers can override. */
export const DEFAULT_MAX_MODULE_BYTES = 10 * 1024 * 1024;

const WASM_MAGIC = [0x00, 0x61, 0x73, 0x6d] as const; // "\0asm"

const KINDS: ReadonlySet<string> = new Set([
  "function",
  "table",
  "memory",
  "global",
  "tag",
]);

function asKind(kind: string): ExternalKind {
  // Unknown future kinds are treated as an invalid module rather than guessed.
  if (!KINDS.has(kind)) throw new Error(`Unsupported extern kind: ${kind}`);
  return kind as ExternalKind;
}

function hasWasmMagic(bytes: Uint8Array): boolean {
  return WASM_MAGIC.every((b, i) => bytes[i] === b);
}

/**
 * Inspect a WebAssembly binary without executing any of its code.
 *
 * WebAssembly.Module() only compiles/validates; it does not run the start
 * function or instantiate anything, so this is safe for untrusted input.
 */
export function inspectModule(
  bytes: Uint8Array,
  opts: { maxBytes?: number } = {},
): Result<ModuleFacts, InspectError> {
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_MODULE_BYTES;

  if (bytes.byteLength === 0) {
    return err({ code: "EMPTY", message: "Module is empty." });
  }
  if (bytes.byteLength > maxBytes) {
    return err({
      code: "TOO_LARGE",
      message: `Module is ${bytes.byteLength} bytes; limit is ${maxBytes}.`,
    });
  }
  if (!hasWasmMagic(bytes)) {
    return err({
      code: "NOT_WASM",
      message: "File does not start with the WebAssembly magic bytes.",
    });
  }

  try {
    const module = new WebAssembly.Module(bytes as BufferSource);
    return ok({
      sha256: sha256Hex(bytes),
      sizeBytes: bytes.byteLength,
      imports: WebAssembly.Module.imports(module).map((i) => ({
        module: i.module,
        name: i.name,
        kind: asKind(i.kind),
      })),
      exports: WebAssembly.Module.exports(module).map((e) => ({
        name: e.name,
        kind: asKind(e.kind),
      })),
    });
  } catch (cause) {
    return err({
      code: "INVALID_MODULE",
      message:
        cause instanceof Error ? cause.message : "Module failed validation.",
    });
  }
}
