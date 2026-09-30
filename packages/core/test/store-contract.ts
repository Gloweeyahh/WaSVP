/**
 * Shared behaviour every store must have. Run against the in-memory stores,
 * the SQL adapters (via SQLite) and, when DATABASE_URL is set, real Postgres.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AuditLogger,
  buildEntry,
  verifyAuditChain,
  type AuditInput,
  type AuditStore,
} from "../src/service/audit.ts";
import type { ModuleStore, StoredModule } from "../src/service/stores.ts";

const input = (n: number, extra: Record<string, unknown> = {}): AuditInput => ({
  actor: "gloria",
  type: "module.accepted",
  moduleSha256: "ab".repeat(32),
  details: { n, ...extra } as AuditInput["details"],
});

export function auditStoreContract(name: string, make: () => Promise<AuditStore>) {
  test(`${name} audit: empty store`, async () => {
    const store = await make();
    assert.equal(await store.last(), null);
    assert.deepEqual(await store.list(), []);
  });

  test(`${name} audit: append, last and list keep order`, async () => {
    const store = await make();
    const e0 = buildEntry(null, input(0), "2026-01-01T00:00:00.000Z");
    const e1 = buildEntry(e0, input(1), "2026-01-01T00:00:01.000Z");
    assert.ok((await store.append(e0)).ok);
    assert.ok((await store.append(e1)).ok);
    assert.deepEqual(await store.last(), e1);
    assert.deepEqual(await store.list(), [e0, e1]);
  });

  test(`${name} audit: refuses entries that do not extend the chain`, async () => {
    const store = await make();
    const e0 = buildEntry(null, input(0), "2026-01-01T00:00:00.000Z");
    const e1 = buildEntry(e0, input(1), "2026-01-01T00:00:01.000Z");
    assert.ok(!(await store.append(e1)).ok, "cannot skip the first entry");
    assert.ok((await store.append(e0)).ok);
    assert.ok(!(await store.append(e0)).ok, "cannot repeat an entry");
    const forked = buildEntry(null, input(9), "2026-01-01T00:00:02.000Z");
    assert.ok(!(await store.append(forked)).ok, "cannot fork from genesis");
    assert.equal((await store.list()).length, 1);
  });

  test(`${name} audit: values round-trip exactly, so the chain still verifies`, async () => {
    const store = await make();
    const logger = new AuditLogger(store, () => new Date("2026-03-04T05:06:07.089Z"));
    await logger.record(input(0, { text: "héllo ✓ 日本語", nested: { list: [1, 2.5, null, true], z: "a" } }));
    await logger.record({ actor: "ada", type: "run.failed", moduleSha256: null, details: {} });
    const entries = await store.list();
    assert.equal(entries[0]!.timestamp, "2026-03-04T05:06:07.089Z");
    assert.equal(entries[1]!.moduleSha256, null);
    assert.ok(verifyAuditChain(entries).ok);
  });

  test(`${name} audit: concurrent appends through the logger stay one chain`, async () => {
    const store = await make();
    const logger = new AuditLogger(store);
    await Promise.all(Array.from({ length: 15 }, (_, i) => logger.record(input(i))));
    const entries = await store.list();
    assert.equal(entries.length, 15);
    assert.ok(verifyAuditChain(entries).ok);
  });
}

const stored = (sha: string, extra: Partial<StoredModule> = {}): StoredModule => ({
  sha256: sha,
  bytes: new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0xff]),
  signature: { version: 1, nested: { list: [1, 2, 3] } },
  uploadedBy: "gloria",
  uploadedAt: "2026-01-01T00:00:00.000Z",
  ...extra,
});

export function moduleStoreContract(name: string, make: () => Promise<ModuleStore>) {
  const SHA = "cd".repeat(32);

  test(`${name} modules: unknown hash -> null`, async () => {
    const store = await make();
    assert.equal(await store.get(SHA), null);
  });

  test(`${name} modules: put then get returns identical data`, async () => {
    const store = await make();
    const m = stored(SHA);
    assert.equal(await store.put(m), true);
    const got = await store.get(SHA);
    assert.ok(got);
    assert.deepEqual([...got.bytes], [...m.bytes]);
    assert.deepEqual(got.signature, m.signature);
    assert.equal(got.uploadedBy, "gloria");
    assert.equal(got.uploadedAt, "2026-01-01T00:00:00.000Z");
  });

  test(`${name} modules: first upload wins, duplicates are ignored`, async () => {
    const store = await make();
    assert.equal(await store.put(stored(SHA)), true);
    assert.equal(await store.put(stored(SHA, { uploadedBy: "mallory", signature: { forged: true } })), false);
    const got = await store.get(SHA);
    assert.equal(got?.uploadedBy, "gloria");
    assert.deepEqual(got?.signature, { version: 1, nested: { list: [1, 2, 3] } });
  });

  test(`${name} modules: returned bytes are copies`, async () => {
    const store = await make();
    await store.put(stored(SHA));
    const first = await store.get(SHA);
    first!.bytes[0] = 0x99;
    const second = await store.get(SHA);
    assert.equal(second!.bytes[0], 0x00);
  });

  test(`${name} modules: every byte value survives (including 0x00 and 0xff)`, async () => {
    const store = await make();
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    await store.put(stored(SHA, { bytes: all }));
    const got = await store.get(SHA);
    assert.deepEqual([...got!.bytes], [...all]);
  });
}
