import { test } from "node:test";
import assert from "node:assert/strict";
import { AuditLogger } from "../src/service/audit.ts";
import { PostgresAuditStore, PostgresModuleStore } from "../src/service/postgres.ts";
import { WasvpService } from "../src/service/service.ts";
import { generateSigningKeyPair, keyIdOf, signModule } from "../src/sign.ts";
import { ADD_MODULE } from "./fixtures.ts";
import { openSqlite } from "./sqlite-helper.ts";
import { auditStoreContract, moduleStoreContract } from "./store-contract.ts";

auditStoreContract("sql", async () => new PostgresAuditStore(openSqlite().client));
moduleStoreContract("sql", async () => new PostgresModuleStore(openSqlite().client));

function buildService(client: ReturnType<typeof openSqlite>["client"], policy: unknown) {
  return new WasvpService({
    audit: new AuditLogger(new PostgresAuditStore(client)),
    modules: new PostgresModuleStore(client),
    policy,
  });
}

test("sql: data survives a 'restart' and the audit chain continues", async () => {
  const { client } = openSqlite();
  const keys = generateSigningKeyPair();
  const id = keyIdOf(keys.publicKey);
  assert.ok(id.ok);
  const policy = { version: 1, name: "p", allowedSigners: [id.value] };
  const sig = signModule(ADD_MODULE, keys);
  assert.ok(sig.ok);

  const before = buildService(client, policy);
  const up = await before.submit({ actor: "gloria", bytes: ADD_MODULE, signature: sig.value });
  assert.ok(up.ok);
  assert.ok((await before.run({ actor: "gloria", moduleId: up.value.moduleId, exportName: "add", args: [1, 2] })).ok);

  // New service instance over the same database = a server restart.
  const after = buildService(client, policy);
  const run = await after.run({ actor: "ada", moduleId: up.value.moduleId, exportName: "add", args: [20, 22] });
  assert.ok(run.ok);
  assert.equal(run.value.value, 42);

  const trail = await after.auditTrail();
  assert.equal(trail.entries.length, 3);
  assert.ok(trail.chain.ok);
  assert.deepEqual(trail.entries.map((e) => e.actor), ["gloria", "gloria", "ada"]);
});

test("sql: editing the database directly is caught by the chain check", async () => {
  const { client, db } = openSqlite();
  const keys = generateSigningKeyPair();
  const id = keyIdOf(keys.publicKey);
  assert.ok(id.ok);
  const service = buildService(client, { version: 1, name: "p", allowedSigners: [id.value] });
  const sig = signModule(ADD_MODULE, keys);
  assert.ok(sig.ok);
  const up = await service.submit({ actor: "gloria", bytes: ADD_MODULE, signature: sig.value });
  assert.ok(up.ok);
  await service.run({ actor: "gloria", moduleId: up.value.moduleId, exportName: "add", args: [1, 1] });

  db.exec("UPDATE audit_entries SET actor = 'mallory' WHERE seq = 1");

  const trail = await service.auditTrail();
  assert.ok(!trail.chain.ok);
  assert.equal(trail.chain.error.seq, 1);
  assert.equal(trail.chain.error.code, "BAD_HASH");
});

test("sql: a module edited in the database no longer runs", async () => {
  const { client, db } = openSqlite();
  const keys = generateSigningKeyPair();
  const id = keyIdOf(keys.publicKey);
  assert.ok(id.ok);
  const service = buildService(client, { version: 1, name: "p", allowedSigners: [id.value] });
  const sig = signModule(ADD_MODULE, keys);
  assert.ok(sig.ok);
  const up = await service.submit({ actor: "gloria", bytes: ADD_MODULE, signature: sig.value });
  assert.ok(up.ok);

  const tampered = new Uint8Array(ADD_MODULE);
  tampered[tampered.length - 2]! ^= 0x01;
  db.prepare("UPDATE modules SET bytes = ?1").run(tampered);

  const run = await service.run({ actor: "gloria", moduleId: up.value.moduleId, exportName: "add", args: [1, 1] });
  assert.ok(!run.ok);
  assert.equal(run.error.code, "BLOCKED");
});
