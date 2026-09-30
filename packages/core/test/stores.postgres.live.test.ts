/**
 * Runs the store contract, plus checks on the migration's triggers, against a
 * REAL Postgres. Skipped unless DATABASE_URL is set:
 *
 *   DATABASE_URL='postgres://...' node --test test/stores.postgres.live.test.ts
 *
 * Each test gets its own throw-away schema, dropped afterwards, so it never
 * touches your real tables.
 */
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { PostgresAuditStore, PostgresModuleStore } from "../src/service/postgres.ts";
import { auditStoreContract, moduleStoreContract } from "./store-contract.ts";

const url = process.env.DATABASE_URL;
const MIGRATION = readFileSync(new URL("../migrations/001_init.sql", import.meta.url), "utf8");

describe("postgres (live)", { skip: url ? false : "DATABASE_URL is not set" }, () => {
  const cleanups: Array<() => Promise<void>> = [];

  async function freshClient() {
    const { default: pg } = await import("pg");
    const isLocal = /(localhost|127\.0\.0\.1)/.test(url!);
    const client = new pg.Client({
      connectionString: url!,
      ssl: isLocal ? false : { rejectUnauthorized: false },
    });
    await client.connect();
    const schema = `wasvp_test_${Math.random().toString(36).slice(2, 10)}`;
    await client.query(`CREATE SCHEMA ${schema}`);
    await client.query(`SET search_path TO ${schema}`);
    await client.query(MIGRATION);
    cleanups.push(async () => {
      await client.query(`DROP SCHEMA ${schema} CASCADE`);
      await client.end();
    });
    return client;
  }

  after(async () => {
    for (const fn of cleanups) await fn();
  });

  auditStoreContract("postgres", async () => new PostgresAuditStore(await freshClient()));
  moduleStoreContract("postgres", async () => new PostgresModuleStore(await freshClient()));

  test("postgres: the database itself refuses to edit, delete or truncate audit entries", async () => {
    const client = await freshClient();
    await client.query(
      `INSERT INTO audit_entries (seq, created_at, actor, event_type, module_sha256, details_json, prev_hash, hash)
       VALUES (0, '2026-01-01T00:00:00.000Z', 'a', 'module.accepted', NULL, '{}', $1, $2)`,
      ["0".repeat(64), "1".repeat(64)],
    );
    await assert.rejects(client.query("UPDATE audit_entries SET actor = 'mallory'"), /append-only/);
    await assert.rejects(client.query("DELETE FROM audit_entries"), /append-only/);
    await assert.rejects(client.query("TRUNCATE audit_entries"), /append-only/);
  });

  test("postgres: stored modules cannot be edited", async () => {
    const client = await freshClient();
    await client.query(
      `INSERT INTO modules (sha256, bytes, signature_json, uploaded_by, uploaded_at)
       VALUES ($1, $2, '{}', 'a', 'x')`,
      ["ab".repeat(32), Buffer.from([1, 2, 3])],
    );
    await assert.rejects(client.query("UPDATE modules SET uploaded_by = 'mallory'"), /immutable/);
  });

  test("postgres: row level security is on for both tables", async () => {
    const client = await freshClient();
    const r = await client.query(
      `SELECT relname, relrowsecurity FROM pg_class
       WHERE relname IN ('modules', 'audit_entries') AND relnamespace = current_schema()::regnamespace`,
    );
    assert.equal(r.rows.length, 2);
    assert.ok(r.rows.every((row: { relrowsecurity: boolean }) => row.relrowsecurity === true));
  });
});
