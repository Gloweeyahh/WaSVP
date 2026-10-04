import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/api/http.ts";
import { AuditLogger, InMemoryAuditStore } from "../src/service/audit.ts";
import { InMemoryModuleStore } from "../src/service/stores.ts";
import { WasvpService } from "../src/service/service.ts";
import { keyIdOf } from "../src/sign.ts";
import { verifyModuleSignature } from "../src/sign.ts";
import { describeKey, generateKeyPair, inspectWasm, signModule, toBase64 } from "../public/crypto.js";
import { ADD_MODULE } from "./fixtures.ts";

const ADMIN = "admin-secret-key-123456";
const MEMBER = "member-secret-key-123456";
const publicFile = (name: string) => readFileSync(new URL(`../public/${name}`, import.meta.url), "utf8");

async function withApp(fn: (url: string) => Promise<void>) {
  const service = new WasvpService({
    audit: new AuditLogger(new InMemoryAuditStore()),
    modules: new InMemoryModuleStore(),
    policy: { version: 1, name: "default-deny" },
  });
  const server = createApp({
    service,
    apiKeys: {
      [ADMIN]: { actor: "admin-user", role: "admin" },
      [MEMBER]: { actor: "member-user", role: "member" },
    },
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
}

const authed = (key: string, extra: Record<string, string> = {}) => ({ authorization: `Bearer ${key}`, ...extra });

test("dashboard files are public and carry a strict content security policy", async () => {
  await withApp(async (url) => {
    const expected: Record<string, RegExp> = {
      "/": /text\/html/,
      "/app.js": /text\/javascript/,
      "/crypto.js": /text\/javascript/,
      "/app.css": /text\/css/,
    };
    for (const [path, type] of Object.entries(expected)) {
      const r = await fetch(`${url}${path}`);
      assert.equal(r.status, 200, path);
      assert.match(r.headers.get("content-type") ?? "", type, path);
      const csp = r.headers.get("content-security-policy") ?? "";
      assert.match(csp, /default-src 'none'/);
      assert.match(csp, /script-src 'self'/);
      assert.match(csp, /frame-ancestors 'none'/);
      assert.equal(r.headers.get("x-content-type-options"), "nosniff");
    }
  });
});

test("dashboard pages only accept GET/HEAD, and other routes still need a key", async () => {
  await withApp(async (url) => {
    const post = await fetch(`${url}/`, { method: "POST" });
    assert.equal(post.status, 405);
    assert.equal((await fetch(`${url}/`, { method: "HEAD" })).status, 200);
    assert.equal((await fetch(`${url}/not-a-page`)).status, 401);
    assert.equal((await fetch(`${url}/audit`)).status, 401);
  });
});

test("GET /me reports who the key belongs to", async () => {
  await withApp(async (url) => {
    assert.equal((await fetch(`${url}/me`)).status, 401);
    const admin = await fetch(`${url}/me`, { headers: authed(ADMIN) });
    assert.deepEqual(await admin.json(), { actor: "admin-user", role: "admin" });
    const member = await fetch(`${url}/me`, { headers: authed(MEMBER) });
    assert.deepEqual(await member.json(), { actor: "member-user", role: "member" });
    assert.equal((await fetch(`${url}/me`, { method: "POST", headers: authed(MEMBER) })).status, 405);
  });
});

test("the page stays compatible with the CSP: no inline scripts, styles or event handlers", () => {
  const html = publicFile("index.html");
  assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), "inline <script> found");
  assert.ok(!/\sstyle\s*=/i.test(html), "inline style attribute found");
  assert.ok(!/\son[a-z]+\s*=/i.test(html), "inline event handler found");
  assert.ok(!/https?:\/\//i.test(html.replace(/xmlns="[^"]*"/g, "")), "external URL found");
});

test("elements marked hidden really are hidden (buttons would otherwise override it)", () => {
  assert.match(publicFile("app.css"), /\[hidden\]\s*\{\s*display:\s*none\s*!important/);
});

test("the dashboard never writes data into the page as HTML (XSS guard)", () => {
  for (const file of ["app.js", "crypto.js"]) {
    const js = publicFile(file);
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(js), `${file} uses an unsafe API`);
  }
});

test("a signature made by the dashboard's browser code is accepted by the server", async () => {
  const pair = await generateKeyPair();
  const { publicKey, keyId } = await describeKey(pair);
  assert.equal(pair.privateKey.extractable, false, "private key must not be extractable");

  const expectedId = keyIdOf(publicKey);
  assert.ok(expectedId.ok);
  assert.equal(keyId, expectedId.value);

  const signature = await signModule(ADD_MODULE, pair);
  const verified = verifyModuleSignature(ADD_MODULE, signature);
  assert.ok(verified.ok);
  assert.equal(verified.value.keyId, keyId);

  const tampered = new Uint8Array(ADD_MODULE);
  tampered[tampered.length - 2]! ^= 0x01;
  const bad = verifyModuleSignature(tampered, signature);
  assert.ok(!bad.ok);
  assert.equal(bad.error.code, "HASH_MISMATCH");
});

test("inspectWasm reads imports and exports like the server does", () => {
  const ok = inspectWasm(ADD_MODULE);
  assert.ok(ok.ok);
  assert.deepEqual(ok.exports, [{ name: "add", kind: "function" }]);
  const bad = inspectWasm(new TextEncoder().encode("nope"));
  assert.ok(!bad.ok);
});

test("end to end: browser-made key and signature -> policy -> upload -> run -> audit", async () => {
  await withApp(async (url) => {
    const pair = await generateKeyPair();
    const { keyId } = await describeKey(pair);
    const json = (key: string) => ({ ...authed(key), "content-type": "application/json" });

    const policy = await fetch(`${url}/policy`, {
      method: "PUT",
      headers: json(ADMIN),
      body: JSON.stringify({ version: 1, name: "dashboard", allowedSigners: [keyId] }),
    });
    assert.equal(policy.status, 200);

    const signature = await signModule(ADD_MODULE, pair);
    const upload = await fetch(`${url}/modules`, {
      method: "POST",
      headers: json(MEMBER),
      body: JSON.stringify({ wasmBase64: toBase64(ADD_MODULE), signature }),
    });
    assert.equal(upload.status, 201);
    const { moduleId } = (await upload.json()) as { moduleId: string };

    const run = await fetch(`${url}/modules/${moduleId}/run`, {
      method: "POST",
      headers: json(MEMBER),
      body: JSON.stringify({ exportName: "add", args: [20, 22] }),
    });
    assert.equal(run.status, 200);
    assert.equal(((await run.json()) as { value: number }).value, 42);

    const audit = (await (await fetch(`${url}/audit`, { headers: authed(MEMBER) })).json()) as {
      chainValid: boolean;
      entries: { type: string; actor: string }[];
    };
    assert.equal(audit.chainValid, true);
    assert.deepEqual(audit.entries.map((e) => e.type), ["policy.changed", "module.accepted", "run.completed"]);

    // A different browser key that the policy doesn't trust is blocked.
    const stranger = await generateKeyPair();
    const blocked = await fetch(`${url}/modules`, {
      method: "POST",
      headers: json(MEMBER),
      body: JSON.stringify({ wasmBase64: toBase64(ADD_MODULE), signature: await signModule(ADD_MODULE, stranger) }),
    });
    assert.equal(blocked.status, 403);
  });
});
