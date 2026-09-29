/**
 * Shared types for @wasvp/core.
 *
 * Design rule: core functions NEVER throw for expected failures.
 * They return a Result, so callers are forced to handle both cases.
 */

export type Ok<T> = { readonly ok: true; readonly value: T };
export type Err<E> = { readonly ok: false; readonly error: E };
export type Result<T, E> = Ok<T> | Err<E>;

export const ok = <T>(value: T): Ok<T> => ({ ok: true, value });
export const err = <E>(error: E): Err<E> => ({ ok: false, error });

/** Lowercase hex SHA-256 digest (64 chars). */
export type Sha256Hex = string & { readonly __brand: "Sha256Hex" };

export type ExternalKind = "function" | "table" | "memory" | "global" | "tag";

export interface WasmImport {
  readonly module: string;
  readonly name: string;
  readonly kind: ExternalKind;
}

export interface WasmExport {
  readonly name: string;
  readonly kind: ExternalKind;
}

/** Everything we can learn about a module WITHOUT running it. */
export interface ModuleFacts {
  readonly sha256: Sha256Hex;
  readonly sizeBytes: number;
  readonly imports: readonly WasmImport[];
  readonly exports: readonly WasmExport[];
}

export type InspectErrorCode =
  | "EMPTY"
  | "TOO_LARGE"
  | "NOT_WASM"
  | "INVALID_MODULE";

export interface InspectError {
  readonly code: InspectErrorCode;
  readonly message: string;
}
