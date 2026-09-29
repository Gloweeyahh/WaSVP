import { test } from "node:test";
import assert from "node:assert/strict";
import { authorize } from "../src/runtime/verified.ts";
import { runModule } from "../src/runtime/run.ts";
import { generateSigningKeyPair, keyIdOf, signModule } from "../src/sign.ts";
import { ADD_MODULE, IMPORT_MODULE } from "./fixtures.ts";
import { LOG_MODULE, SPIN_MODULE, TRAP_MODULE } from "./runtime-fixtures.ts";

/** Sign a module with a fresh key and build a policy that trusts it. */
function prepare(bytes: Uint8Array, extra: Record<string, unknown> = {}) {
  const keys = generateSigningKeyPair();
  const id = keyIdOf(keys.publicKey);
  assert.ok(id.ok);
  const sig = signModule(bytes, keys);
  assert.ok(sig.ok);
  const policy = { version: 1, name: "test", allowedSigners: [id.value], ...extra };
  return { keys, keyId: id.value, sig: sig.value, policy };
}

function authorized(bytes: Uint8Array, extra: Record<string, unknown> = {}) {
  const p = prepare(bytes, extra);
  const a = authorize(bytes, p.sig, p.policy);
  assert.ok(a.ok, a.ok ? "" : JSON.stringify(a.error));
  return a.value;
}

test("runs an approved module and returns its result", async () => {
  const m = authorized(ADD_MODULE);
  const r = await runModule(m, { exportName: "add", args: [2, 3] });
  assert.ok(r.ok);
  assert.equal(r.value.value, 5);
  assert.deepEqual(r.value.logs, []);
});

test("an approved import works and its calls are captured", async () => {
  const m = authorized(LOG_MODULE, { allowedImports: [{ module: "env", name: "log" }] });
  const r = await runModule(m, { exportName: "run" });
  assert.ok(r.ok);
  assert.deepEqual(r.value.logs, [42]);
});

test("unsigned module is blocked before it can run", () => {
  const p = prepare(ADD_MODULE);
  const a = authorize(ADD_MODULE, undefined, p.policy);
  assert.ok(!a.ok);
  assert.equal(a.error.code, "BLOCKED");
  assert.ok(a.error.reasons.some((r) => r.rule === "signed" && !r.passed));
});

test("untrusted signer is blocked", () => {
  const p = prepare(ADD_MODULE);
  const other = keyIdOf(generateSigningKeyPair().publicKey);
  assert.ok(other.ok);
  const a = authorize(ADD_MODULE, p.sig, { ...p.policy, allowedSigners: [other.value] });
  assert.ok(!a.ok);
  assert.equal(a.error.code, "BLOCKED");
});

test("import not allowed by policy is blocked", () => {
  const p = prepare(LOG_MODULE);
  const a = authorize(LOG_MODULE, p.sig, p.policy);
  assert.ok(!a.ok);
  assert.ok(a.error.reasons.some((r) => r.rule === "imports_allowed" && !r.passed));
});

test("module tampered with after authorization -> HASH_CHANGED", async () => {
  const m = authorized(ADD_MODULE);
  m.bytes[m.bytes.length - 2]! ^= 0x01; // simulate in-memory tampering
  const r = await runModule(m, { exportName: "add", args: [1, 1] });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "HASH_CHANGED");
});

test("infinite loop is stopped at the timeout", async () => {
  const m = authorized(SPIN_MODULE);
  const started = Date.now();
  const r = await runModule(m, { exportName: "spin" }, { timeoutMs: 300 });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "TIMEOUT");
  assert.ok(Date.now() - started < 5000, "should stop promptly");
});

test("a trap is reported, not thrown", async () => {
  const m = authorized(TRAP_MODULE);
  const r = await runModule(m, { exportName: "boom" });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "TRAP");
});

test("missing export -> EXPORT_NOT_FOUND", async () => {
  const m = authorized(ADD_MODULE);
  const r = await runModule(m, { exportName: "nope" });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "EXPORT_NOT_FOUND");
});

test("approved import with no host implementation -> HOST_IMPORT_MISSING", async () => {
  const renamed = new Uint8Array(IMPORT_MODULE);
  renamed.set([0x61, 0x62, 0x63], renamed.length - 5); // env.log -> env.abc
  const m = authorized(renamed, { allowedImports: [{ module: "env", name: "abc" }] });
  const r = await runModule(m, { exportName: "anything" });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "HOST_IMPORT_MISSING");
});

test("bad call arguments -> INVALID_ARGS", async () => {
  const m = authorized(ADD_MODULE);
  for (const call of [
    { exportName: "" },
    { exportName: "add", args: [Number.NaN] },
    { exportName: "add", args: Array.from({ length: 17 }, () => 1) },
  ]) {
    const r = await runModule(m, call);
    assert.ok(!r.ok);
    assert.equal(r.error.code, "INVALID_ARGS");
  }
});

test("non-WASM bytes -> INVALID_MODULE", () => {
  const a = authorize(new TextEncoder().encode("nope"), {}, {});
  assert.ok(!a.ok);
  assert.equal(a.error.code, "INVALID_MODULE");
});

test("runs are isolated: logs from one run never leak into the next", async () => {
  const m = authorized(LOG_MODULE, { allowedImports: [{ module: "env", name: "log" }] });
  const [a, b] = await Promise.all([
    runModule(m, { exportName: "run" }),
    runModule(m, { exportName: "run" }),
  ]);
  assert.ok(a.ok && b.ok);
  assert.deepEqual(a.value.logs, [42]);
  assert.deepEqual(b.value.logs, [42]);
});
