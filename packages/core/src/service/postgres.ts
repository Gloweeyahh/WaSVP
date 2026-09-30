import { err, ok } from "../types.ts";
import {
  canonicalJson,
  type AuditEntry,
  type AuditEventType,
  type AuditStore,
  type Json,
} from "./audit.ts";
import type { ModuleStore, StoredModule } from "./stores.ts";

/**
 * SQL-backed stores. They talk to the database through this tiny interface,
 * which node-postgres (`pg`) satisfies, so the adapters have no hard
 * dependency on any driver and can be tested against other SQL engines.
 * Placeholders are numbered ($1, $2, ...), the Postgres style.
 */
export interface SqlClient {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

function text(value: unknown, field: string): string {
  if (typeof value !== "string") throw new Error(`Unexpected value for ${field} in database row.`);
  return value;
}

function rowToEntry(row: Record<string, unknown>): AuditEntry {
  return Object.freeze({
    seq: Number(row.seq),
    timestamp: text(row.created_at, "created_at"),
    actor: text(row.actor, "actor"),
    type: text(row.event_type, "event_type") as AuditEventType,
    moduleSha256: row.module_sha256 === null ? null : text(row.module_sha256, "module_sha256"),
    details: JSON.parse(text(row.details_json, "details_json")) as AuditEntry["details"],
    prevHash: text(row.prev_hash, "prev_hash"),
    hash: text(row.hash, "hash"),
  });
}

const AUDIT_COLUMNS =
  "seq, created_at, actor, event_type, module_sha256, details_json, prev_hash, hash";

export class PostgresAuditStore implements AuditStore {
  private readonly db: SqlClient;

  constructor(db: SqlClient) {
    this.db = db;
  }

  async last() {
    const r = await this.db.query(
      `SELECT ${AUDIT_COLUMNS} FROM audit_entries ORDER BY seq DESC LIMIT 1`,
    );
    return r.rows[0] ? rowToEntry(r.rows[0]) : null;
  }

  async list() {
    const r = await this.db.query(`SELECT ${AUDIT_COLUMNS} FROM audit_entries ORDER BY seq ASC`);
    return r.rows.map(rowToEntry);
  }

  /**
   * Two guards stop the chain forking: this check, and the database's
   * PRIMARY KEY on seq plus UNIQUE on prev_hash (which win even if two
   * server instances append at the same moment; the loser gets an error).
   */
  async append(entry: AuditEntry) {
    try {
      const prev = await this.last();
      const expectedSeq = prev ? prev.seq + 1 : 0;
      const expectedPrev = prev ? prev.hash : "0".repeat(64);
      if (entry.seq !== expectedSeq || entry.prevHash !== expectedPrev) {
        return err({ message: "Entry does not extend the current chain." });
      }
      await this.db.query(
        `INSERT INTO audit_entries (${AUDIT_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          entry.seq,
          entry.timestamp,
          entry.actor,
          entry.type,
          entry.moduleSha256,
          canonicalJson(entry.details as Json),
          entry.prevHash,
          entry.hash,
        ],
      );
      return ok(undefined);
    } catch (cause) {
      return err({ message: cause instanceof Error ? cause.message : "Could not write audit entry." });
    }
  }
}

export class PostgresModuleStore implements ModuleStore {
  private readonly db: SqlClient;

  constructor(db: SqlClient) {
    this.db = db;
  }

  /** First upload of a hash wins; later ones are ignored (returns false). */
  async put(module: StoredModule) {
    const r = await this.db.query(
      `INSERT INTO modules (sha256, bytes, signature_json, uploaded_by, uploaded_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (sha256) DO NOTHING
       RETURNING sha256`,
      [
        module.sha256,
        Buffer.from(module.bytes),
        JSON.stringify(module.signature ?? null),
        module.uploadedBy,
        module.uploadedAt,
      ],
    );
    return r.rows.length === 1;
  }

  async get(sha256: string) {
    const r = await this.db.query(
      `SELECT sha256, bytes, signature_json, uploaded_by, uploaded_at FROM modules WHERE sha256 = $1`,
      [sha256],
    );
    const row = r.rows[0];
    if (!row) return null;
    if (!(row.bytes instanceof Uint8Array)) throw new Error("Unexpected bytes value in database row.");
    return {
      sha256: text(row.sha256, "sha256"),
      bytes: new Uint8Array(row.bytes),
      signature: JSON.parse(text(row.signature_json, "signature_json")) as unknown,
      uploadedBy: text(row.uploaded_by, "uploaded_by"),
      uploadedAt: text(row.uploaded_at, "uploaded_at"),
    };
  }
}
