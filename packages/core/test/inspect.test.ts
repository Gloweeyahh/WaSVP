import { test } from "node:test";
import assert from "node:assert/strict";
import { inspectModule } from "../src/inspect.ts";
import { ADD_MODULE, EMPTY_MODULE, IMPORT_MODULE } from "./fixtures.ts";

test("valid module: reports exports, no imports, hash and size", () => {
  const r = inspectModule(ADD_MODULE);
  assert.ok(r.ok);
  assert.deepEqual(r.value.exports, [{ name: "add", kind: "function" }]);
  assert.deepEqual(r.value.imports, []);
  assert.equal(r.value.sizeBytes, ADD_MODULE.byteLength);
  assert.match(r.value.sha256, /^[0-9a-f]{64}$/);
});

test("module with an import: import is surfaced for policy checks", () => {
  const r = inspectModule(IMPORT_MODULE);
  assert.ok(r.ok);
  assert.deepEqual(r.value.imports, [
    { module: "env", name: "log", kind: "function" },
  ]);
});

test("header-only module is valid and empty", () => {
  const r = inspectModule(EMPTY_MODULE);
  assert.ok(r.ok);
  assert.equal(r.value.exports.length, 0);
});

test("empty input -> EMPTY", () => {
  const r = inspectModule(new Uint8Array());
  assert.ok(!r.ok);
  assert.equal(r.error.code, "EMPTY");
});

test("random bytes -> NOT_WASM", () => {
  const r = inspectModule(new TextEncoder().encode("hello world"));
  assert.ok(!r.ok);
  assert.equal(r.error.code, "NOT_WASM");
});

test("oversized module -> TOO_LARGE", () => {
  const r = inspectModule(ADD_MODULE, { maxBytes: 10 });
  assert.ok(!r.ok);
  assert.equal(r.error.code, "TOO_LARGE");
});

test("valid header but truncated body -> INVALID_MODULE", () => {
  const r = inspectModule(ADD_MODULE.slice(0, ADD_MODULE.length - 5));
  assert.ok(!r.ok);
  assert.equal(r.error.code, "INVALID_MODULE");
});

test("inspecting never mutates the input", () => {
  const copy = new Uint8Array(ADD_MODULE);
  inspectModule(copy);
  assert.deepEqual(copy, ADD_MODULE);
});
