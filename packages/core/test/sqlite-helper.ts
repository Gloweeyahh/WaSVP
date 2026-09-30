import { DatabaseSync } from "node:sqlite";
import type { SqlClient } from "../src/service/postgres.ts";

/**
 * A SQLite-backed SqlClient, used to test the SQL adapters' queries and row
 * mapping without needing a Postgres server. It does NOT test the Postgres
 * migration (types, triggers, RLS): the live test does that.
 */
const SCHEMA = `
CREATE TABLE modules (
  sha256 TEXT PRIMARY KEY, bytes BLOB NOT NULL, signature_json TEXT NOT NULL,
  uploaded_by TEXT NOT NULL, uploaded_at TEXT NOT NULL
);
CREATE TABLE audit_entries (
  seq INTEGER PRIMARY KEY, created_at TEXT NOT NULL, actor TEXT NOT NULL,
  event_type TEXT NOT NULL, module_sha256 TEXT, details_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL UNIQUE, hash TEXT NOT NULL UNIQUE
);
`;

export function openSqlite(): { db: DatabaseSync; client: SqlClient } {
  const db = new DatabaseSync(":memory:");
  db.exec(SCHEMA);
  const client: SqlClient = {
    async query(text, values = []) {
      const sql = text.replace(/\$(\d+)/g, "?$1"); // $1 -> ?1
      const rows = db.prepare(sql).all(...(values as never[]));
      return { rows: rows as Record<string, unknown>[] };
    },
  };
  return { db, client };
}
