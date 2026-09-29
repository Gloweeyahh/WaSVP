import { test } from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, sign } from "node:crypto";
import {
  generateSigningKeyPair,
  keyIdOf,
  signModule,
  verifyModuleSignature,
} from "../src/sign.ts";
import { ADD_MODULE } from "./fixtures.ts";

function signedFixture() {
  const keys = generateSigningKeyPair();
  const r = signModule(ADD_MODULE, keys);
  assert.ok(r.ok);
  return { keys, sig: r.value };
}

test("generated keys are 32-byte base64url strings", () => {
  const k = generateSigningKeyPair();
  assert.equal(Buffer.from(k.publicKey, "base64url").length, 32);
  assert.equal(Buffer.from(k.privateKey, "base64url").length, 32);
});

test("keyIdOf returns a 64-char hex fingerprint", () => {
  const k = generateSigningKeyPair();
  const id = keyIdOf(k.publicKey);
  assert.ok(id.ok);
  assert.match(id.value, /^[0-9a-f]{64}$/);
});

test("sign then verify succeeds and reports the signer", () => {
  const { keys, sig } = signedFixture();
  const v = verifyModuleSignature(ADD_MODULE, sig);
  assert.ok(v.ok);
  const expected = keyIdOf(keys.publicKey);
  assert.ok(expected.ok);
  assert.equal(v.value.keyId, expected.value);
});

test("signature survives a JSON round trip", () => {
  const { sig } = signedFixture();
  const v = verifyModuleSignature(ADD_MODULE, JSON.parse(JSON.stringify(sig)));
  assert.ok(v.ok);
});

test("modified module -> HASH_MISMATCH", () => {
  const { sig } = signedFixture();
  const tampered = new Uint8Array(ADD_MODULE);
  tampered[tampered.length - 2]! ^= 0x01;
  const v = verifyModuleSignature(tampered, sig);
  assert.ok(!v.ok);
  assert.equal(v.error.code, "HASH_MISMATCH");
});

test("modified signature bytes -> BAD_SIGNATURE", () => {
  const { sig } = signedFixture();
  const raw = Buffer.from(sig.signature, "base64url");
  raw[0]! ^= 0x01;
  const v = verifyModuleSignature(ADD_MODULE, {
    ...sig,
    signature: raw.toString("base64url"),
  });
  assert.ok(!v.ok);
  assert.equal(v.error.code, "BAD_SIGNATURE");
});

test("swapping in another public key but keeping keyId -> KEY_ID_MISMATCH", () => {
  const { sig } = signedFixture();
  const attacker = generateSigningKeyPair();
  const v = verifyModuleSignature(ADD_MODULE, {
    ...sig,
    publicKey: attacker.publicKey,
  });
  assert.ok(!v.ok);
  assert.equal(v.error.code, "KEY_ID_MISMATCH");
});

test("swapping in another key AND its keyId -> BAD_SIGNATURE", () => {
  const { sig } = signedFixture();
  const attacker = generateSigningKeyPair();
  const attackerId = keyIdOf(attacker.publicKey);
  assert.ok(attackerId.ok);
  const v = verifyModuleSignature(ADD_MODULE, {
    ...sig,
    publicKey: attacker.publicKey,
    keyId: attackerId.value,
  });
  assert.ok(!v.ok);
  assert.equal(v.error.code, "BAD_SIGNATURE");
});

test("signature over the bare hash (no domain prefix) is rejected", () => {
  const { keys, sig } = signedFixture();
  const priv = createPrivateKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      d: keys.privateKey,
      x: keys.publicKey,
    },
    format: "jwk",
  });
  const bare = sign(null, Buffer.from(sig.sha256, "utf8"), priv);
  const v = verifyModuleSignature(ADD_MODULE, {
    ...sig,
    signature: bare.toString("base64url"),
  });
  assert.ok(!v.ok);
  assert.equal(v.error.code, "BAD_SIGNATURE");
});

test("malformed inputs never throw", () => {
  const bad: unknown[] = [null, undefined, 42, "x", {}, [], { version: 1 }];
  for (const input of bad) {
    const v = verifyModuleSignature(ADD_MODULE, input);
    assert.ok(!v.ok);
  }
});

test("unknown version -> UNSUPPORTED_VERSION", () => {
  const { sig } = signedFixture();
  const v = verifyModuleSignature(ADD_MODULE, { ...sig, version: 2 });
  assert.ok(!v.ok);
  assert.equal(v.error.code, "UNSUPPORTED_VERSION");
});

test("refuses to sign non-WASM bytes", () => {
  const r = signModule(new TextEncoder().encode("not wasm"), generateSigningKeyPair());
  assert.ok(!r.ok);
  assert.equal(r.error.code, "INVALID_MODULE");
});

test("refuses a private key that doesn't match the public key", () => {
  const a = generateSigningKeyPair();
  const b = generateSigningKeyPair();
  const r = signModule(ADD_MODULE, { publicKey: a.publicKey, privateKey: b.privateKey });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "KEY_MISMATCH");
});

test("refuses malformed keys", () => {
  const r = signModule(ADD_MODULE, { publicKey: "abc", privateKey: "def" });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "INVALID_KEY");
});
