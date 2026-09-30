import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AuditLogger,
  GENESIS_HASH,
  InMemoryAuditStore,
  buildEntry,
  canonicalJson,
  verifyAuditChain,
  type AuditInput,
} from "../src/service/audit.ts";

const input = (n: number): AuditInput => ({
  actor: "gloria",
  type: "module.accepted",
  moduleSha256: "ab".repeat(32),
  details: { n },
});

async function logWith(count: number) {
  const store = new InMemoryAuditStore();
  let tick = 0;
  const logger = new AuditLogger(store, () => new Date(Date.UTC(2026, 0, 1, 0, 0, tick++)));
  for (let i = 0; i < count; i++) await logger.record(input(i));
  return { store, logger, entries: await store.list() };
}

test("first entry links to genesis, later entries link to the previous hash", async () => {
  const { entries } = await logWith(3);
  assert.equal(entries[0]!.prevHash, GENESIS_HASH);
  assert.equal(entries[1]!.prevHash, entries[0]!.hash);
  assert.equal(entries[2]!.prevHash, entries[1]!.hash);
  assert.deepEqual(entries.map((e) => e.seq), [0, 1, 2]);
});

test("an untouched chain verifies, and so does an empty one", async () => {
  const { entries } = await logWith(5);
  assert.ok(verifyAuditChain(entries).ok);
  assert.ok(verifyAuditChain([]).ok);
});

test("editing a past entry is detected", async () => {
  const { entries } = await logWith(4);
  const forged = [...entries];
  forged[1] = { ...forged[1]!, actor: "someone-else" };
  const r = verifyAuditChain(forged);
  assert.ok(!r.ok);
  assert.equal(r.error.seq, 1);
  assert.equal(r.error.code, "BAD_HASH");
});

test("deleting an entry is detected", async () => {
  const { entries } = await logWith(4);
  const r = verifyAuditChain([entries[0]!, entries[2]!, entries[3]!]);
  assert.ok(!r.ok);
  assert.equal(r.error.code, "BAD_SEQ");
});

test("reordering entries is detected", async () => {
  const { entries } = await logWith(3);
  const r = verifyAuditChain([entries[0]!, entries[2]!, entries[1]!]);
  assert.ok(!r.ok);
});

test("rewriting an entry AND its hash still breaks the next link", async () => {
  const { entries } = await logWith(3);
  const original = entries[1]!;
  const rebuilt = buildEntry(entries[0]!, { ...input(99), actor: "forger" }, original.timestamp);
  const r = verifyAuditChain([entries[0]!, rebuilt, entries[2]!]);
  assert.ok(!r.ok);
  assert.equal(r.error.seq, 2);
  assert.equal(r.error.code, "BAD_PREV_HASH");
});

test("canonicalJson ignores key order", () => {
  assert.equal(canonicalJson({ a: 1, b: { d: 1, c: 2 } }), canonicalJson({ b: { c: 2, d: 1 }, a: 1 }));
});

test("20 concurrent records still produce one valid chain", async () => {
  const store = new InMemoryAuditStore();
  const logger = new AuditLogger(store);
  await Promise.all(Array.from({ length: 20 }, (_, i) => logger.record(input(i))));
  const entries = await store.list();
  assert.equal(entries.length, 20);
  assert.ok(verifyAuditChain(entries).ok);
});

test("the store refuses an entry that does not extend the chain", async () => {
  const { store, entries } = await logWith(2);
  const stale = buildEntry(entries[0]!, input(7), "2026-01-01T00:00:00.000Z");
  const r = await store.append(stale);
  assert.ok(!r.ok);
});

test("mutating the input after recording does not change the stored entry", async () => {
  const store = new InMemoryAuditStore();
  const logger = new AuditLogger(store);
  const details: { [k: string]: number } = { n: 1 };
  await logger.record({ actor: "a", type: "module.accepted", moduleSha256: null, details });
  details.n = 2;
  const entries = await store.list();
  assert.equal(entries[0]!.details.n, 1);
  assert.ok(verifyAuditChain(entries).ok);
});
