import { test } from "node:test";
import assert from "node:assert/strict";
import { hashesEqual, sha256Hex } from "../src/hash.ts";
import { ADD_MODULE } from "./fixtures.ts";

test("sha256 of empty input matches known vector", () => {
  assert.equal(
    sha256Hex(new Uint8Array()),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
});

test("sha256 of 'abc' matches known vector", () => {
  assert.equal(
    sha256Hex(new TextEncoder().encode("abc")),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("flipping a single byte changes the hash (tamper detection)", () => {
  const tampered = new Uint8Array(ADD_MODULE);
  tampered[tampered.length - 2]! ^= 0x01;
  assert.notEqual(sha256Hex(tampered), sha256Hex(ADD_MODULE));
});

test("hashesEqual is case-insensitive and length-safe", () => {
  const h = sha256Hex(ADD_MODULE);
  assert.equal(hashesEqual(h, h.toUpperCase()), true);
  assert.equal(hashesEqual(h, h.slice(0, 10)), false);
  assert.equal(hashesEqual(h, "0".repeat(64)), false);
});
