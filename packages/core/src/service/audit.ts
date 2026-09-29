import { sha256Hex } from "../hash.ts";
import { err, ok, type Result } from "../types.ts";

/**
 * Tamper-evident audit log.
 *
 * Each entry contains the hash of the entry before it, so changing,
 * deleting or reordering any past entry breaks every hash after it.
 * verifyAuditChain() finds the first broken link.
 */

export type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [key: string]: Json };

export type AuditEventType =
  | "module.accepted"
  | "module.blocked"
  | "run.completed"
  | "run.failed"
  | "run.blocked"
  | "policy.changed"
  | "policy.rejected";

export interface AuditInput {
  readonly actor: string;
  readonly type: AuditEventType;
  /** Hash of the module involved, or null if not applicable. */
  readonly moduleSha256: string | null;
  readonly details: { readonly [key: string]: Json };
}

export interface AuditEntry extends AuditInput {
  readonly seq: number;
  readonly timestamp: string;
  readonly prevHash: string;
  readonly hash: string;
}

export const GENESIS_HASH = "0".repeat(64);

/** JSON with sorted keys, so the same data always hashes the same. */
export function canonicalJson(value: Json): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k] as Json)}`)
    .join(",")}}`;
}

function entryHash(e: Omit<AuditEntry, "hash">): string {
  const body: Json = {
    seq: e.seq,
    timestamp: e.timestamp,
    actor: e.actor,
    type: e.type,
    moduleSha256: e.moduleSha256,
    details: e.details as Json,
    prevHash: e.prevHash,
  };
  return sha256Hex(new TextEncoder().encode(canonicalJson(body)));
}

export function buildEntry(
  prev: AuditEntry | null,
  input: AuditInput,
  timestamp: string,
): AuditEntry {
  const partial = {
    seq: prev ? prev.seq + 1 : 0,
    timestamp,
    actor: input.actor,
    type: input.type,
    moduleSha256: input.moduleSha256,
    details: structuredClone(input.details) as AuditEntry["details"],
    prevHash: prev ? prev.hash : GENESIS_HASH,
  };
  return Object.freeze({ ...partial, hash: entryHash(partial) });
}

export interface ChainError {
  readonly seq: number;
  readonly code: "BAD_SEQ" | "BAD_PREV_HASH" | "BAD_HASH";
  readonly message: string;
}

/** Check every link in the chain; report the first problem found. */
export function verifyAuditChain(
  entries: readonly AuditEntry[],
): Result<{ length: number }, ChainError> {
  let prevHash = GENESIS_HASH;
  for (const [index, e] of entries.entries()) {
    if (e.seq !== index) {
      return err({ seq: e.seq, code: "BAD_SEQ", message: `Expected entry ${index}, found ${e.seq}.` });
    }
    if (e.prevHash !== prevHash) {
      return err({ seq: e.seq, code: "BAD_PREV_HASH", message: `Entry ${e.seq} does not link to the entry before it.` });
    }
    const { hash, ...rest } = e;
    if (entryHash(rest) !== hash) {
      return err({ seq: e.seq, code: "BAD_HASH", message: `Entry ${e.seq} has been modified.` });
    }
    prevHash = hash;
  }
  return ok({ length: entries.length });
}

/** Storage port: swap the in-memory version for PostgreSQL later. */
export interface AuditStore {
  last(): Promise<AuditEntry | null>;
  /** Append-only. There is deliberately no update or delete. */
  append(entry: AuditEntry): Promise<Result<void, { message: string }>>;
  list(): Promise<readonly AuditEntry[]>;
}

export class InMemoryAuditStore implements AuditStore {
  private readonly entries: AuditEntry[] = [];

  async last() {
    return this.entries[this.entries.length - 1] ?? null;
  }

  async append(entry: AuditEntry) {
    const prev = this.entries[this.entries.length - 1] ?? null;
    const expectedSeq = prev ? prev.seq + 1 : 0;
    const expectedPrev = prev ? prev.hash : GENESIS_HASH;
    if (entry.seq !== expectedSeq || entry.prevHash !== expectedPrev) {
      return err({ message: "Entry does not extend the current chain." });
    }
    this.entries.push(entry);
    return ok(undefined);
  }

  async list() {
    return [...this.entries];
  }
}

/** Serialises appends so concurrent events can never fork the chain. */
export class AuditLogger {
  private queue: Promise<unknown> = Promise.resolve();
  private readonly store: AuditStore;
  private readonly now: () => Date;

  constructor(store: AuditStore, now: () => Date = () => new Date()) {
    this.store = store;
    this.now = now;
  }

  /**
   * Record an event. If the log cannot be written this THROWS: callers
   * should treat "no audit record" as a failure and not carry on.
   */
  record(input: AuditInput): Promise<AuditEntry> {
    const run = this.queue.then(async () => {
      const entry = buildEntry(await this.store.last(), input, this.now().toISOString());
      const result = await this.store.append(entry);
      if (!result.ok) throw new Error(`Audit write failed: ${result.error.message}`);
      return entry;
    });
    this.queue = run.catch(() => undefined);
    return run;
  }

  list() {
    return this.store.list();
  }
}
