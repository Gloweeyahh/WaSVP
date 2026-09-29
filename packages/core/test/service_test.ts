import { test } from "node:test";
import assert from "node:assert/strict";
import { sha256Hex } from "../src/hash.ts";
import { AuditLogger, InMemoryAuditStore, verifyAuditChain } from "../src/service/audit.ts";
import { InMemoryModuleStore } from "../src/service/stores.ts";
import { WasvpService } from "../src/service/service.ts";
import { generateSigningKeyPair, keyIdOf, signModule } from "../src/sign.ts";
import { ADD_MODULE } from "./fixtures.ts";
import { LOG_MODULE, TRAP_MODULE } from "./runtime-fixtures.ts";

function setup(policyExtra: Record<string, unknown> = {}) {
  const keys = generateSigningKeyPair();
  const id = keyIdOf(keys.publicKey);
  assert.ok(id.ok);
  const policy = { version: 1, name: "test", allowedSigners: [id.value], ...policyExtra };
  const audit = new AuditLogger(new InMemoryAuditStore());
  const service = new WasvpService({ audit, modules: new InMemoryModuleStore(), policy });
  const sign = (bytes: Uint8Array) => {
    const s = signModule(bytes, keys);
    assert.ok(s.ok);
    return s.value;
  };
  return { keys, keyId: id.value, policy, service, sign };
}

const LOG_POLICY = { allowedImports: [{ module: "env", name: "log" }] };

test("submit accepts a signed, trusted module", async () => {
  const { service, sign, keyId } = setup();
  const r = await service.submit({ actor: "gloria", bytes: ADD_MODULE, signature: sign(ADD_MODULE) });
  assert.ok(r.ok);
  assert.equal(r.value.moduleId, sha256Hex(ADD_MODULE));
  assert.equal(r.value.signerKeyId, keyId);
  assert.equal(r.value.newlyStored, true);
});

test("submit blocks an unsigned module and audits which rule failed", async () => {
  const { service } = setup();
  const r = await service.submit({ actor: "gloria", bytes: ADD_MODULE, signature: undefined });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "BLOCKED");
  const { entries } = await service.auditTrail();
  assert.equal(entries[0]!.type, "module.blocked");
  assert.deepEqual((entries[0]!.details.failedRules as string[]).includes("signed"), true);
});

test("submit rejects non-WASM bytes and audits it without a hash", async () => {
  const { service } = setup();
  const r = await service.submit({ actor: "gloria", bytes: new TextEncoder().encode("nope"), signature: {} });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "INVALID_MODULE");
  const { entries } = await service.auditTrail();
  assert.equal(entries[0]!.moduleSha256, null);
});

test("run returns the result and audits who ran what with which permissions", async () => {
  const { service, sign } = setup(LOG_POLICY);
  const up = await service.submit({ actor: "gloria", bytes: LOG_MODULE, signature: sign(LOG_MODULE) });
  assert.ok(up.ok);
  const r = await service.run({ actor: "ada", moduleId: up.value.moduleId, exportName: "run" });
  assert.ok(r.ok);
  assert.deepEqual(r.value.logs, [42]);

  const { entries } = await service.auditTrail();
  const last = entries[entries.length - 1]!;
  assert.equal(last.type, "run.completed");
  assert.equal(last.actor, "ada");
  assert.equal(last.moduleSha256, up.value.moduleId);
  assert.deepEqual(last.details.permissions, ["env.log"]);
});

test("run computes a return value", async () => {
  const { service, sign } = setup();
  const up = await service.submit({ actor: "gloria", bytes: ADD_MODULE, signature: sign(ADD_MODULE) });
  assert.ok(up.ok);
  const r = await service.run({ actor: "gloria", moduleId: up.value.moduleId, exportName: "add", args: [20, 22] });
  assert.ok(r.ok);
  assert.equal(r.value.value, 42);
});

test("revoking a hash blocks a module that was already uploaded", async () => {
  const { service, sign, policy } = setup();
  const up = await service.submit({ actor: "gloria", bytes: ADD_MODULE, signature: sign(ADD_MODULE) });
  assert.ok(up.ok);

  const changed = await service.setPolicy("admin", { ...policy, blockedHashes: [up.value.moduleId] });
  assert.ok(changed.ok);

  const r = await service.run({ actor: "gloria", moduleId: up.value.moduleId, exportName: "add", args: [1, 1] });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "BLOCKED");

  const types = (await service.auditTrail()).entries.map((e) => e.type);
  assert.deepEqual(types, ["module.accepted", "policy.changed", "run.blocked"]);
});

test("an invalid policy is rejected, audited, and the old policy stays active", async () => {
  const { service, sign } = setup();
  const up = await service.submit({ actor: "gloria", bytes: ADD_MODULE, signature: sign(ADD_MODULE) });
  assert.ok(up.ok);

  const r = await service.setPolicy("admin", { version: 1, name: "oops", alowedSigners: [] });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "INVALID_POLICY");

  const run = await service.run({ actor: "gloria", moduleId: up.value.moduleId, exportName: "add", args: [1, 2] });
  assert.ok(run.ok);
  const types = (await service.auditTrail()).entries.map((e) => e.type);
  assert.ok(types.includes("policy.rejected"));
});

test("unknown module id -> NOT_FOUND, and it is audited", async () => {
  const { service } = setup();
  const r = await service.run({ actor: "gloria", moduleId: "f".repeat(64), exportName: "add" });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "NOT_FOUND");
  const { entries } = await service.auditTrail();
  assert.equal(entries[0]!.type, "run.failed");
  assert.equal(entries[0]!.details.code, "NOT_FOUND");
});

test("a trapping module is reported and audited as a failed run", async () => {
  const { service, sign } = setup();
  const up = await service.submit({ actor: "gloria", bytes: TRAP_MODULE, signature: sign(TRAP_MODULE) });
  assert.ok(up.ok);
  const r = await service.run({ actor: "gloria", moduleId: up.value.moduleId, exportName: "boom" });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "TRAP");
  const last = (await service.auditTrail()).entries.at(-1)!;
  assert.equal(last.type, "run.failed");
  assert.equal(last.details.code, "TRAP");
});

test("a blank actor is refused and nothing is audited", async () => {
  const { service, sign } = setup();
  const r = await service.submit({ actor: "  ", bytes: ADD_MODULE, signature: sign(ADD_MODULE) });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "INVALID_REQUEST");
  assert.equal((await service.auditTrail()).entries.length, 0);
});

test("changing the caller's bytes after submit does not affect the stored module", async () => {
  const { service, sign } = setup();
  const bytes = new Uint8Array(ADD_MODULE);
  const up = await service.submit({ actor: "gloria", bytes, signature: sign(bytes) });
  assert.ok(up.ok);
  bytes[bytes.length - 2]! ^= 0x01;
  const r = await service.run({ actor: "gloria", moduleId: up.value.moduleId, exportName: "add", args: [2, 3] });
  assert.ok(r.ok);
  assert.equal(r.value.value, 5);
});

test("uploading the same module twice stores it once", async () => {
  const { service, sign } = setup();
  const sig = sign(ADD_MODULE);
  const a = await service.submit({ actor: "gloria", bytes: ADD_MODULE, signature: sig });
  const b = await service.submit({ actor: "ada", bytes: ADD_MODULE, signature: sig });
  assert.ok(a.ok && b.ok);
  assert.equal(a.value.newlyStored, true);
  assert.equal(b.value.newlyStored, false);
});

test("the audit trail verifies, and forging any entry is detected", async () => {
  const { service, sign } = setup(LOG_POLICY);
  const up = await service.submit({ actor: "gloria", bytes: LOG_MODULE, signature: sign(LOG_MODULE) });
  assert.ok(up.ok);
  await service.run({ actor: "ada", moduleId: up.value.moduleId, exportName: "run" });
  await service.run({ actor: "ada", moduleId: "0".repeat(64), exportName: "run" });

  const { entries, chain } = await service.auditTrail();
  assert.ok(chain.ok);
  assert.equal(entries.length, 3);

  const forged = [...entries];
  forged[1] = { ...forged[1]!, actor: "mallory" };
  assert.ok(!verifyAuditChain(forged).ok);
});
