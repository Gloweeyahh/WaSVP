import { test } from "node:test";
import assert from "node:assert/strict";
import { parsePolicy } from "../src/policy.ts";
import { AuditLogger, InMemoryAuditStore } from "../src/service/audit.ts";
import { InMemoryModuleStore } from "../src/service/stores.ts";
import { WasvpService } from "../src/service/service.ts";
import { generateSigningKeyPair, keyIdOf, signModule } from "../src/sign.ts";
import { ADD_MODULE } from "./fixtures.ts";

test("parsePolicy is idempotent: a parsed policy parses again to the same thing", () => {
  const first = parsePolicy({
    version: 1,
    name: "p",
    allowedSigners: ["ab".repeat(32)],
    allowedImports: [{ module: "env", name: "log" }],
    requiredExports: ["run"],
  });
  assert.ok(first.ok);
  const second = parsePolicy(first.value);
  assert.ok(second.ok);
  assert.deepEqual(second.value, first.value);
});

test("a policy set through setPolicy still lets trusted modules in", async () => {
  const keys = generateSigningKeyPair();
  const id = keyIdOf(keys.publicKey);
  assert.ok(id.ok);
  const service = new WasvpService({
    audit: new AuditLogger(new InMemoryAuditStore()),
    modules: new InMemoryModuleStore(),
    policy: { version: 1, name: "default-deny" },
  });
  const set = await service.setPolicy("admin", { version: 1, name: "live", allowedSigners: [id.value] });
  assert.ok(set.ok);

  const sig = signModule(ADD_MODULE, keys);
  assert.ok(sig.ok);
  const up = await service.submit({ actor: "gloria", bytes: ADD_MODULE, signature: sig.value });
  assert.ok(up.ok, "module signed by a trusted signer should be accepted after setPolicy");
  const run = await service.run({ actor: "gloria", moduleId: up.value.moduleId, exportName: "add", args: [2, 3] });
  assert.ok(run.ok);
});
