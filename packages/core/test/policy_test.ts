import { test } from "node:test";
import assert from "node:assert/strict";
import { inspectModule } from "../src/inspect.ts";
import { evaluatePolicy, parsePolicy } from "../src/policy.ts";
import {
  generateSigningKeyPair,
  keyIdOf,
  signModule,
  verifyModuleSignature,
} from "../src/sign.ts";
import { ADD_MODULE, IMPORT_MODULE } from "./fixtures.ts";

/** Build facts + a verified signature for a fixture module. */
function setup(bytes: Uint8Array) {
  const keys = generateSigningKeyPair();
  const id = keyIdOf(keys.publicKey);
  assert.ok(id.ok);
  const facts = inspectModule(bytes);
  assert.ok(facts.ok);
  const sig = signModule(bytes, keys);
  assert.ok(sig.ok);
  const verified = verifyModuleSignature(bytes, sig.value);
  assert.ok(verified.ok);
  return { keys, keyId: id.value, facts: facts.value, verified: verified.value };
}

const basePolicy = (keyId: string) => ({
  version: 1,
  name: "test policy",
  allowedSigners: [keyId],
});

const failedRules = (d: ReturnType<typeof evaluatePolicy>) =>
  d.reasons.filter((r) => !r.passed).map((r) => r.rule);

test("trusted signer, clean module -> ALLOW", () => {
  const s = setup(ADD_MODULE);
  const d = evaluatePolicy(basePolicy(s.keyId), s.facts, s.verified);
  assert.equal(d.decision, "ALLOW");
  assert.deepEqual(failedRules(d), []);
});

test("every rule is reported, in a stable order", () => {
  const s = setup(ADD_MODULE);
  const d = evaluatePolicy(basePolicy(s.keyId), s.facts, s.verified);
  assert.deepEqual(
    d.reasons.map((r) => r.rule),
    [
      "policy_valid",
      "not_revoked",
      "signed",
      "signature_matches_module",
      "signer_trusted",
      "size_ok",
      "imports_allowed",
      "exports_present",
    ],
  );
});

test("unsigned module -> BLOCK", () => {
  const s = setup(ADD_MODULE);
  const d = evaluatePolicy(basePolicy(s.keyId), s.facts, null);
  assert.equal(d.decision, "BLOCK");
  assert.ok(failedRules(d).includes("signed"));
  assert.ok(failedRules(d).includes("signer_trusted"));
});

test("valid signature from an unknown signer -> BLOCK", () => {
  const s = setup(ADD_MODULE);
  const other = keyIdOf(generateSigningKeyPair().publicKey);
  assert.ok(other.ok);
  const d = evaluatePolicy(basePolicy(other.value), s.facts, s.verified);
  assert.equal(d.decision, "BLOCK");
  assert.deepEqual(failedRules(d), ["signer_trusted"]);
});

test("default deny: no trusted signers listed -> BLOCK", () => {
  const s = setup(ADD_MODULE);
  const d = evaluatePolicy({ version: 1, name: "empty" }, s.facts, s.verified);
  assert.equal(d.decision, "BLOCK");
  assert.deepEqual(failedRules(d), ["signer_trusted"]);
});

test("revoked hash is blocked even when correctly signed by a trusted signer", () => {
  const s = setup(ADD_MODULE);
  const d = evaluatePolicy(
    { ...basePolicy(s.keyId), blockedHashes: [s.facts.sha256.toUpperCase()] },
    s.facts,
    s.verified,
  );
  assert.equal(d.decision, "BLOCK");
  assert.deepEqual(failedRules(d), ["not_revoked"]);
});

test("signature for a different module -> BLOCK", () => {
  const a = setup(ADD_MODULE);
  const b = setup(IMPORT_MODULE);
  const d = evaluatePolicy(basePolicy(a.keyId), b.facts, a.verified);
  assert.equal(d.decision, "BLOCK");
  assert.ok(failedRules(d).includes("signature_matches_module"));
});

test("module over the size limit -> BLOCK", () => {
  const s = setup(ADD_MODULE);
  const d = evaluatePolicy(
    { ...basePolicy(s.keyId), maxSizeBytes: 10 },
    s.facts,
    s.verified,
  );
  assert.equal(d.decision, "BLOCK");
  assert.deepEqual(failedRules(d), ["size_ok"]);
});

test("unapproved import -> BLOCK and the import is named", () => {
  const s = setup(IMPORT_MODULE);
  const d = evaluatePolicy(basePolicy(s.keyId), s.facts, s.verified);
  assert.equal(d.decision, "BLOCK");
  const reason = d.reasons.find((r) => r.rule === "imports_allowed");
  assert.ok(reason && !reason.passed);
  assert.match(reason.message, /env\.log/);
});

test("explicitly allowed import -> ALLOW", () => {
  const s = setup(IMPORT_MODULE);
  const d = evaluatePolicy(
    { ...basePolicy(s.keyId), allowedImports: [{ module: "env", name: "log" }] },
    s.facts,
    s.verified,
  );
  assert.equal(d.decision, "ALLOW");
});

test("import allowlist matches module AND name", () => {
  const s = setup(IMPORT_MODULE);
  const d = evaluatePolicy(
    { ...basePolicy(s.keyId), allowedImports: [{ module: "env", name: "other" }] },
    s.facts,
    s.verified,
  );
  assert.equal(d.decision, "BLOCK");
});

test("missing required export -> BLOCK", () => {
  const s = setup(ADD_MODULE);
  const d = evaluatePolicy(
    { ...basePolicy(s.keyId), requiredExports: ["add", "run"] },
    s.facts,
    s.verified,
  );
  assert.equal(d.decision, "BLOCK");
  assert.deepEqual(failedRules(d), ["exports_present"]);
});

test("multiple problems are all reported at once", () => {
  const s = setup(IMPORT_MODULE);
  const d = evaluatePolicy(
    { version: 1, name: "strict", maxSizeBytes: 5, requiredExports: ["run"] },
    s.facts,
    null,
  );
  assert.equal(d.decision, "BLOCK");
  assert.deepEqual(failedRules(d), [
    "signed",
    "signature_matches_module",
    "signer_trusted",
    "size_ok",
    "imports_allowed",
    "exports_present",
  ]);
});

test("invalid policies fail closed and never throw", () => {
  const s = setup(ADD_MODULE);
  const bad: unknown[] = [
    null,
    undefined,
    42,
    "policy",
    [],
    {},
    { version: 2, name: "x" },
    { version: 1, name: "" },
    { version: 1, name: "x", allowedSigners: ["not-hex"] },
    { version: 1, name: "x", alowedSigners: [s.keyId] }, // typo'd key
    { version: 1, name: "x", maxSizeBytes: -5 },
    { version: 1, name: "x", maxSizeBytes: 1.5 },
    { version: 1, name: "x", allowedImports: [{ module: "env" }] },
    { version: 1, name: "x", requiredExports: [1, 2] },
  ];
  for (const policy of bad) {
    const d = evaluatePolicy(policy, s.facts, s.verified);
    assert.equal(d.decision, "BLOCK");
    assert.deepEqual(failedRules(d), ["policy_valid"]);
  }
});

test("parsePolicy normalises hex to lowercase and fills defaults", () => {
  const id = "AB".repeat(32);
  const r = parsePolicy({ version: 1, name: "  p  ", allowedSigners: [id] });
  assert.ok(r.ok);
  assert.equal(r.value.name, "p");
  assert.deepEqual(r.value.allowedSigners, ["ab".repeat(32)]);
  assert.deepEqual(r.value.blockedHashes, []);
  assert.equal(r.value.maxSizeBytes, null);
});

test("full chain: inspect -> sign -> verify -> policy", () => {
  const keys = generateSigningKeyPair();
  const id = keyIdOf(keys.publicKey);
  assert.ok(id.ok);
  const facts = inspectModule(ADD_MODULE);
  assert.ok(facts.ok);
  const sig = signModule(ADD_MODULE, keys);
  assert.ok(sig.ok);
  const verified = verifyModuleSignature(ADD_MODULE, sig.value);
  assert.equal(
    evaluatePolicy(basePolicy(id.value), facts.value, verified.ok ? verified.value : null)
      .decision,
    "ALLOW",
  );
  // Same signature, tampered bytes: verification fails, so policy blocks.
  const tampered = new Uint8Array(ADD_MODULE);
  tampered[tampered.length - 2]! ^= 0x01;
  const tamperedFacts = inspectModule(tampered);
  const tamperedVerified = verifyModuleSignature(tampered, sig.value);
  assert.ok(!tamperedVerified.ok);
  if (tamperedFacts.ok) {
    assert.equal(
      evaluatePolicy(basePolicy(id.value), tamperedFacts.value, null).decision,
      "BLOCK",
    );
  }
});
