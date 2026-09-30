import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { createApp, type AppConfig } from "../src/api/http.ts";
import { sha256Hex } from "../src/hash.ts";
import { AuditLogger, InMemoryAuditStore, type AuditStore } from "../src/service/audit.ts";
import { InMemoryModuleStore } from "../src/service/stores.ts";
import { WasvpService } from "../src/service/service.ts";
import { generateSigningKeyPair, keyIdOf, signModule } from "../src/sign.ts";
import { ADD_MODULE } from "./fixtures.ts";
import { SPIN_MODULE, TRAP_MODULE } from "./runtime-fixtures.ts";

const ADMIN = "admin-secret-key-123456";
const MEMBER = "member-secret-key-123456";

type Json = Record<string, any>;

async function withApp(
  fn: (ctx: { url: string; keys: ReturnType<typeof generateSigningKeyPair>; keyId: string }) => Promise<void>,
  opts: { auditStore?: AuditStore } & Partial<AppConfig> = {},
) {
  const keys = generateSigningKeyPair();
  const id = keyIdOf(keys.publicKey);
  assert.ok(id.ok);
  const { auditStore, ...overrides } = opts;
  const service = new WasvpService({
    audit: new AuditLogger(auditStore ?? new InMemoryAuditStore()),
    modules: new InMemoryModuleStore(),
    policy: { version: 1, name: "default-deny" },
  });
  const server = createApp({
    service,
    apiKeys: {
      [ADMIN]: { actor: "admin-user", role: "admin" },
      [MEMBER]: { actor: "member-user", role: "member" },
    },
    ...overrides,
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  try {
    await fn({ url: `http://127.0.0.1:${port}`, keys, keyId: id.value });
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
}

const call = (
  url: string,
  method: string,
  key: string | null,
  body?: unknown,
  headers: Record<string, string> = {},
) =>
  fetch(url, {
    method,
    headers: {
      ...(key ? { authorization: `Bearer ${key}` } : {}),
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...headers,
    },
    ...(body !== undefined ? { body: typeof body === "string" ? body : JSON.stringify(body) } : {}),
  });

const json = async (r: Response) => (await r.json()) as Json;
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

async function trust(url: string, keyId: string, extra: Record<string, unknown> = {}) {
  const r = await call(`${url}/policy`, "PUT", ADMIN, {
    version: 1,
    name: "api-test",
    allowedSigners: [keyId],
    ...extra,
  });
  assert.equal(r.status, 200);
}

async function upload(url: string, keys: ReturnType<typeof generateSigningKeyPair>, bytes: Uint8Array) {
  const sig = signModule(bytes, keys);
  assert.ok(sig.ok);
  const r = await call(`${url}/modules`, "POST", MEMBER, { wasmBase64: b64(bytes), signature: sig.value });
  return { r, body: await json(r) };
}

test("health is public", async () => {
  await withApp(async ({ url }) => {
    const r = await call(`${url}/health`, "GET", null);
    assert.equal(r.status, 200);
    assert.deepEqual(await json(r), { ok: true });
  });
});

test("missing or wrong API key -> 401, even for unknown routes", async () => {
  await withApp(async ({ url }) => {
    for (const key of [null, "wrong-key-wrong-key-123"]) {
      for (const path of ["/audit", "/nope"]) {
        const r = await call(`${url}${path}`, "GET", key);
        assert.equal(r.status, 401);
        assert.equal(r.headers.get("www-authenticate"), "Bearer");
      }
    }
  });
});

test("members cannot change the policy; admins can", async () => {
  await withApp(async ({ url, keyId }) => {
    const policy = { version: 1, name: "p", allowedSigners: [keyId] };
    assert.equal((await call(`${url}/policy`, "PUT", MEMBER, policy)).status, 403);
    assert.equal((await call(`${url}/policy`, "PUT", ADMIN, policy)).status, 200);
  });
});

test("full flow: set policy, upload, run, audit", async () => {
  await withApp(async ({ url, keys, keyId }) => {
    await trust(url, keyId);
    const up = await upload(url, keys, ADD_MODULE);
    assert.equal(up.r.status, 201);
    assert.equal(up.body.moduleId, sha256Hex(ADD_MODULE));

    const run = await call(`${url}/modules/${up.body.moduleId}/run`, "POST", MEMBER, {
      exportName: "add",
      args: [2, 3],
    });
    assert.equal(run.status, 200);
    const out = await json(run);
    assert.equal(out.value, 5);
    assert.equal(out.valueType, "number");

    const audit = await json(await call(`${url}/audit`, "GET", MEMBER));
    assert.equal(audit.chainValid, true);
    assert.deepEqual(
      audit.entries.map((e: Json) => e.type),
      ["policy.changed", "module.accepted", "run.completed"],
    );
  });
});

test("audit actor comes from the API key and cannot be spoofed via the body", async () => {
  await withApp(async ({ url, keys, keyId }) => {
    await trust(url, keyId);
    const sig = signModule(ADD_MODULE, keys);
    assert.ok(sig.ok);
    await call(`${url}/modules`, "POST", MEMBER, {
      wasmBase64: b64(ADD_MODULE),
      signature: sig.value,
      actor: "mallory",
    });
    const audit = await json(await call(`${url}/audit`, "GET", ADMIN));
    const accepted = audit.entries.find((e: Json) => e.type === "module.accepted");
    assert.equal(accepted.actor, "member-user");
  });
});

test("re-uploading the same module returns 200 instead of 201", async () => {
  await withApp(async ({ url, keys, keyId }) => {
    await trust(url, keyId);
    assert.equal((await upload(url, keys, ADD_MODULE)).r.status, 201);
    assert.equal((await upload(url, keys, ADD_MODULE)).r.status, 200);
  });
});

test("unsigned module -> 403 BLOCKED with rule-by-rule reasons", async () => {
  await withApp(async ({ url, keyId }) => {
    await trust(url, keyId);
    const r = await call(`${url}/modules`, "POST", MEMBER, { wasmBase64: b64(ADD_MODULE) });
    assert.equal(r.status, 403);
    const body = await json(r);
    assert.equal(body.error.code, "BLOCKED");
    assert.ok(body.error.reasons.some((x: Json) => x.rule === "signed" && x.passed === false));
  });
});

test("revoking a hash via the API stops runs", async () => {
  await withApp(async ({ url, keys, keyId }) => {
    await trust(url, keyId);
    const up = await upload(url, keys, ADD_MODULE);
    await trust(url, keyId, { blockedHashes: [up.body.moduleId] });
    const run = await call(`${url}/modules/${up.body.moduleId}/run`, "POST", MEMBER, { exportName: "add", args: [1, 1] });
    assert.equal(run.status, 403);
  });
});

test("bad requests: invalid JSON, wrong content type, bad base64, bad shapes", async () => {
  await withApp(async ({ url }) => {
    assert.equal((await call(`${url}/modules`, "POST", MEMBER, "{not json")).status, 400);
    const wrongType = await fetch(`${url}/modules`, {
      method: "POST",
      headers: { authorization: `Bearer ${MEMBER}`, "content-type": "text/plain" },
      body: "hi",
    });
    assert.equal(wrongType.status, 415);
    assert.equal((await call(`${url}/modules`, "POST", MEMBER, { wasmBase64: "***" })).status, 400);
    assert.equal((await call(`${url}/modules`, "POST", MEMBER, [1, 2])).status, 400);
  });
});

test("oversized body -> 413", async () => {
  await withApp(
    async ({ url }) => {
      const r = await call(`${url}/modules`, "POST", MEMBER, { wasmBase64: "A".repeat(5000) });
      assert.equal(r.status, 413);
    },
    { maxBodyBytes: 1000 },
  );
});

test("routing: unknown route 404, wrong method 405, malformed module id 404", async () => {
  await withApp(async ({ url }) => {
    assert.equal((await call(`${url}/nope`, "GET", MEMBER)).status, 404);
    const wrong = await call(`${url}/audit`, "POST", MEMBER, {});
    assert.equal(wrong.status, 405);
    assert.equal(wrong.headers.get("allow"), "GET");
    assert.equal((await call(`${url}/modules/not-a-hash/run`, "POST", MEMBER, { exportName: "x" })).status, 404);
    assert.equal((await call(`${url}/modules/${"a".repeat(64)}/run`, "POST", MEMBER, { exportName: "x" })).status, 404);
  });
});

test("run errors map to sensible statuses: trap 422", async () => {
  await withApp(async ({ url, keys, keyId }) => {
    await trust(url, keyId);
    const up = await upload(url, keys, TRAP_MODULE);
    const r = await call(`${url}/modules/${up.body.moduleId}/run`, "POST", MEMBER, { exportName: "boom" });
    assert.equal(r.status, 422);
    assert.equal((await json(r)).error.code, "TRAP");
  });
});

test("callers cannot exceed the server's timeout ceiling", async () => {
  await withApp(
    async ({ url, keys, keyId }) => {
      await trust(url, keyId);
      const up = await upload(url, keys, SPIN_MODULE);
      const started = Date.now();
      const r = await call(`${url}/modules/${up.body.moduleId}/run`, "POST", MEMBER, {
        exportName: "spin",
        timeoutMs: 999_999,
      });
      assert.equal(r.status, 408);
      assert.ok(Date.now() - started < 5000);
    },
    { maxTimeoutMs: 300 },
  );
});

test("invalid run arguments -> 400", async () => {
  await withApp(async ({ url }) => {
    const id = "a".repeat(64);
    const path = `${url}/modules/${id}/run`;
    assert.equal((await call(path, "POST", MEMBER, {})).status, 400);
    assert.equal((await call(path, "POST", MEMBER, { exportName: "x", args: ["1"] })).status, 400);
    assert.equal((await call(path, "POST", MEMBER, { exportName: "x", timeoutMs: -1 })).status, 400);
  });
});

test("audit ?limit returns the latest entries; bad limits -> 400", async () => {
  await withApp(async ({ url, keyId }) => {
    await trust(url, keyId);
    await trust(url, keyId);
    await trust(url, keyId);
    const audit = await json(await call(`${url}/audit?limit=2`, "GET", MEMBER));
    assert.equal(audit.total, 3);
    assert.equal(audit.entries.length, 2);
    assert.equal(audit.entries[1].seq, 2);
    assert.equal((await call(`${url}/audit?limit=0`, "GET", MEMBER)).status, 400);
    assert.equal((await call(`${url}/audit?limit=abc`, "GET", MEMBER)).status, 400);
  });
});

test("internal failures return a generic 500 and never leak details", async () => {
  const broken: AuditStore = {
    last: async () => null,
    list: async () => [],
    append: async () => ({ ok: false as const, error: { message: "secret database detail" } }),
  };
  const logged: string[] = [];
  await withApp(
    async ({ url }) => {
      const r = await call(`${url}/policy`, "PUT", ADMIN, { version: 1, name: "p" });
      assert.equal(r.status, 500);
      const text = await r.text();
      assert.ok(!text.includes("secret database detail"));
      assert.equal(JSON.parse(text).error.code, "INTERNAL");
    },
    { auditStore: broken, log: (m) => logged.push(m) },
  );
  assert.equal(logged.length, 1);
});

test("weak API keys are rejected at startup", () => {
  const service = new WasvpService({
    audit: new AuditLogger(new InMemoryAuditStore()),
    modules: new InMemoryModuleStore(),
    policy: {},
  });
  assert.throws(() => createApp({ service, apiKeys: { short: { actor: "x", role: "admin" } } }));
});
