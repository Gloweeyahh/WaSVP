import {
  describeKey,
  ed25519Supported,
  generateKeyPair,
  inspectWasm,
  sha256Hex,
  signModule,
  toBase64,
} from "./crypto.js";

/* ---------- tiny helpers (everything is built as text nodes, never as HTML strings) ---------- */

const $ = (id) => document.getElementById(id);
const HEX64 = /^[0-9a-fA-F]{64}$/;
const short = (hex) => (hex && hex.length > 16 ? `${hex.slice(0, 8)}…${hex.slice(-6)}` : hex ?? "");

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === false || value == null) continue;
    if (key === "class") el.className = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? "" : String(value));
  }
  for (const kid of kids.flat()) {
    if (kid != null && kid !== false) el.append(kid);
  }
  return el;
}

let toastTimer;
function toast(message, kind = "info") {
  const el = $("toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), kind === "error" ? 5000 : 3000);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied.");
  } catch {
    toast("Could not copy. Select the text and copy it by hand.", "error");
  }
}

const RULE_LABELS = {
  policy_valid: "The policy is valid",
  not_revoked: "Not on the block list",
  signed: "Has a valid signature",
  signature_matches_module: "Signature covers this exact module",
  signer_trusted: "Signed by a trusted signer",
  size_ok: "Within the size limit",
  imports_allowed: "Only approved imports",
  exports_present: "Required exports are present",
};

const EVENT_LABELS = {
  "module.accepted": ["Module accepted", true],
  "module.blocked": ["Module blocked", false],
  "run.completed": ["Run completed", true],
  "run.failed": ["Run failed", false],
  "run.blocked": ["Run blocked", false],
  "policy.changed": ["Policy changed", true],
  "policy.rejected": ["Policy rejected", false],
};

/* ---------- state ---------- */

const state = {
  key: sessionStorage.getItem("wasvp.key") ?? "",
  me: null,
  edSupported: false,
  keyPair: null,
  keyInfo: null,
  file: null,
  modules: JSON.parse(sessionStorage.getItem("wasvp.modules") ?? "[]"),
};

function saveModules() {
  sessionStorage.setItem("wasvp.modules", JSON.stringify(state.modules));
}

async function api(method, path, body) {
  try {
    const res = await fetch(path, {
      method,
      headers: {
        ...(state.key ? { authorization: `Bearer ${state.key}` } : {}),
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    let data = null;
    try {
      data = await res.json();
    } catch {
      /* no JSON body */
    }
    return { ok: res.ok, status: res.status, data };
  } catch {
    return { ok: false, status: 0, data: { error: { code: "NETWORK", message: "Could not reach the server." } } };
  }
}

const errorText = (r) => r.data?.error?.message ?? `Something went wrong (status ${r.status}).`;

/* ---------- tabs ---------- */

function go(name) {
  for (const section of document.querySelectorAll(".tab")) section.hidden = section.id !== `tab-${name}`;
  for (const button of document.querySelectorAll(".tabs button")) {
    if (button.dataset.go === name) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  const heading = $(`tab-${name}`).querySelector("h2");
  heading.tabIndex = -1;
  heading.focus({ preventScroll: true });
  window.scrollTo(0, 0);
  if (name === "audit") loadAudit();
}

for (const button of document.querySelectorAll(".tabs button")) {
  button.addEventListener("click", () => go(button.dataset.go));
}

function requireConnected() {
  if (state.me) return true;
  toast("Connect with your API key first.", "error");
  go("connect");
  return false;
}

/* ---------- connect ---------- */

function setWho() {
  const pill = $("who");
  pill.classList.toggle("on", Boolean(state.me));
  pill.textContent = state.me ? `${state.me.actor} · ${state.me.role}` : "Not connected";
  $("connect").hidden = Boolean(state.me);
  $("disconnect").hidden = !state.me;
}

async function connect() {
  const typed = $("api-key").value.trim();
  if (typed) state.key = typed;
  if (!state.key) return toast("Paste your API key first.", "error");
  const r = await api("GET", "/me");
  if (!r.ok) {
    state.key = "";
    state.me = null;
    sessionStorage.removeItem("wasvp.key");
    setWho();
    return toast(r.status === 401 ? "That key was not accepted." : errorText(r), "error");
  }
  state.me = r.data;
  sessionStorage.setItem("wasvp.key", state.key);
  $("api-key").value = "";
  setWho();
  toast(`Connected as ${r.data.actor}.`);
}

function disconnect() {
  state.key = "";
  state.me = null;
  sessionStorage.removeItem("wasvp.key");
  setWho();
  toast("Disconnected.");
}

$("connect").addEventListener("click", connect);
$("disconnect").addEventListener("click", disconnect);
$("api-key").addEventListener("keydown", (e) => {
  if (e.key === "Enter") connect();
});

/* ---------- signing key (kept in IndexedDB, private part is non-extractable) ---------- */

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("wasvp", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("keys");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbRun(mode, fn) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("keys", mode);
    const request = fn(tx.objectStore("keys"));
    tx.oncomplete = () => resolve(request?.result);
    tx.onerror = () => reject(tx.error);
  });
}

async function loadKey() {
  try {
    const pair = await dbRun("readonly", (store) => store.get("main"));
    if (pair) {
      state.keyPair = pair;
      state.keyInfo = await describeKey(pair);
    }
  } catch {
    /* storage unavailable (private browsing): the key will only last for this visit */
  }
}

async function createKey() {
  try {
    const pair = await generateKeyPair();
    state.keyPair = pair;
    state.keyInfo = await describeKey(pair);
    try {
      await dbRun("readwrite", (store) => store.put(pair, "main"));
    } catch {
      toast("Key created, but this browser could not save it. It will be lost when you leave.", "error");
    }
    renderKeyCard();
    toast("Signing key created.");
  } catch {
    toast("Could not create a key in this browser.", "error");
  }
}

async function removeKey() {
  if (!window.confirm("Delete this signing key? Modules signed with it stay valid, but you can't sign new ones with it.")) return;
  try {
    await dbRun("readwrite", (store) => store.delete("main"));
  } catch {
    /* nothing stored */
  }
  state.keyPair = null;
  state.keyInfo = null;
  renderKeyCard();
  toast("Signing key deleted.");
}

function renderKeyCard() {
  const card = $("key-card");
  card.replaceChildren();
  if (!state.edSupported) {
    card.append(
      h("p", {}, "This browser can't create Ed25519 signing keys."),
      h("p", { class: "hint" }, "Use a recent Safari, Chrome or Firefox. You can still upload modules signed elsewhere by choosing \u201cI already have a signature\u201d."),
    );
    return;
  }
  if (!state.keyPair) {
    card.append(
      h("p", {}, "You don't have a signing key on this device yet."),
      h("p", { class: "hint" }, "It is created and kept in this browser. The private part can never be read or exported."),
      h("button", { class: "btn primary", type: "button", onclick: createKey }, "Create signing key"),
    );
    return;
  }
  card.append(
    h("dl", { class: "kv" }, h("dt", {}, "Key ID"), h("dd", {}, h("code", {}, state.keyInfo.keyId))),
    h("p", { class: "hint" }, "Add this key ID under Policy \u2192 Trusted signers so modules you sign are allowed."),
    h(
      "div",
      { class: "row" },
      h("button", { class: "btn small", type: "button", onclick: () => copy(state.keyInfo.keyId) }, "Copy key ID"),
      h("button", { class: "btn small", type: "button", onclick: removeKey }, "Delete key"),
    ),
  );
}

/* ---------- policy builder ---------- */

function makeList(containerId, { label, text, same }) {
  const items = [];
  const ul = h("ul", { class: "chips", "aria-label": label });
  const empty = h("p", { class: "empty" }, "None added yet.");
  $(containerId).append(empty, ul);

  function draw() {
    ul.replaceChildren(
      ...items.map((item) =>
        h(
          "li",
          { class: "chip" },
          h("span", { title: text(item) }, text(item)),
          h(
            "button",
            {
              type: "button",
              "aria-label": `Remove ${text(item)}`,
              onclick: () => {
                items.splice(items.indexOf(item), 1);
                draw();
              },
            },
            "\u00d7",
          ),
        ),
      ),
    );
    empty.hidden = items.length > 0;
    updateJson();
  }

  return {
    items,
    add(item) {
      if (!items.some((i) => same(i, item))) items.push(item);
      draw();
    },
    draw,
  };
}

const signers = makeList("l-signers", { label: "Trusted signers", text: (s) => short(s), same: (a, b) => a === b });
const blocked = makeList("l-blocked", { label: "Blocked hashes", text: (s) => short(s), same: (a, b) => a === b });
const imports = makeList("l-imports", {
  label: "Allowed imports",
  text: (i) => `${i.module}.${i.name}`,
  same: (a, b) => a.module === b.module && a.name === b.name,
});
const exportsList = makeList("l-exports", { label: "Required exports", text: (s) => s, same: (a, b) => a === b });

function currentPolicy() {
  const policy = {
    version: 1,
    name: $("p-name").value.trim(),
    allowedSigners: [...signers.items],
    blockedHashes: [...blocked.items],
    allowedImports: imports.items.map((i) => ({ ...i })),
    requiredExports: [...exportsList.items],
  };
  const max = $("p-max").value.trim();
  if (max !== "") policy.maxSizeBytes = Number(max);
  return policy;
}

function updateJson() {
  $("p-json").textContent = JSON.stringify(currentPolicy(), null, 2);
}

function addHex(inputId, list, what) {
  const value = $(inputId).value.trim();
  if (!HEX64.test(value)) return toast(`A ${what} is 64 letters and numbers (0-9, a-f).`, "error");
  list.add(value.toLowerCase());
  $(inputId).value = "";
}

$("add-signer").addEventListener("click", () => addHex("p-signer", signers, "key ID"));
$("add-block").addEventListener("click", () => addHex("p-block", blocked, "module hash"));
$("add-my-key").addEventListener("click", () => {
  if (!state.keyInfo) {
    toast("Create a signing key first (Connect tab).", "error");
    return go("connect");
  }
  signers.add(state.keyInfo.keyId);
});
$("add-import").addEventListener("click", () => {
  const module = $("p-imp-mod").value.trim();
  const name = $("p-imp-name").value.trim();
  if (!module || !name) return toast("Enter both the module and the name.", "error");
  imports.add({ module, name });
  $("p-imp-mod").value = "";
  $("p-imp-name").value = "";
});
$("add-export").addEventListener("click", () => {
  const value = $("p-export").value.trim();
  if (!value) return toast("Enter an export name.", "error");
  exportsList.add(value);
  $("p-export").value = "";
});
for (const id of ["p-name", "p-max"]) $(id).addEventListener("input", updateJson);

function renderRules(reasons) {
  return h(
    "ul",
    { class: "rules" },
    reasons.map((r) =>
      h(
        "li",
        { class: r.passed ? "pass" : "fail" },
        h("span", { class: "mark", "aria-hidden": "true" }, r.passed ? "\u2713" : "\u2715"),
        h(
          "span",
          {},
          h("strong", {}, `${RULE_LABELS[r.rule] ?? r.rule}: ${r.passed ? "passed" : "failed"}`),
          h("small", {}, r.message),
        ),
      ),
    ),
  );
}

function verdict(kind, title, ...body) {
  return h("div", { class: `verdict ${kind}` }, h("h4", {}, title), ...body);
}

$("apply-policy").addEventListener("click", async () => {
  if (!requireConnected()) return;
  const out = $("policy-result");
  out.replaceChildren();
  const policy = currentPolicy();
  if (policy.allowedSigners.length === 0 && !window.confirm("No trusted signers are listed, so nothing will be allowed to run. Apply anyway?")) return;
  const r = await api("PUT", "/policy", policy);
  if (r.ok) {
    out.append(verdict("allow", "\u2713 Policy applied", h("p", {}, `Fingerprint ${short(r.data.policySha256)}`)));
    toast("Policy applied.");
  } else {
    out.append(verdict("block", "\u2715 Policy not applied", h("p", {}, errorText(r))));
  }
});

/* ---------- modules ---------- */

function formatSize(bytes) {
  return bytes < 1024 ? `${bytes} B` : bytes < 1048576 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1048576).toFixed(1)} MB`;
}

function renderFileInfo() {
  const box = $("m-info");
  box.replaceChildren();
  const f = state.file;
  if (!f) return;
  box.append(
    h(
      "dl",
      { class: "kv" },
      h("dt", {}, "File"), h("dd", {}, f.name),
      h("dt", {}, "Size"), h("dd", {}, formatSize(f.bytes.length)),
      h("dt", {}, "Hash"), h("dd", {}, h("code", {}, f.sha256)),
    ),
  );
  if (!f.info.ok) {
    box.append(verdict("info", "\u26a0 Not a valid module", h("p", {}, f.info.error)));
    return;
  }
  const names = (list) => (list.length ? list.map((x) => (x.module ? `${x.module}.${x.name}` : x.name)).join(", ") : "none");
  box.append(
    h(
      "dl",
      { class: "kv" },
      h("dt", {}, "Imports"), h("dd", {}, names(f.info.imports)),
      h("dt", {}, "Exports"), h("dd", {}, names(f.info.exports)),
    ),
  );
}

$("m-file").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  if (file.size > 10 * 1024 * 1024) {
    state.file = null;
    $("m-info").replaceChildren(verdict("info", "\u26a0 Too large", h("p", {}, "Modules can be at most 10 MB.")));
    return;
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  state.file = { name: file.name, bytes, sha256: await sha256Hex(bytes), info: inspectWasm(bytes) };
  renderFileInfo();
});

for (const radio of document.querySelectorAll('input[name="sign-mode"]')) {
  radio.addEventListener("change", () => {
    $("m-paste").hidden = document.querySelector('input[name="sign-mode"]:checked').value !== "paste";
  });
}

function rememberModule(id, name, exportNames) {
  state.modules = [{ id, name, exports: exportNames }, ...state.modules.filter((m) => m.id !== id)].slice(0, 20);
  saveModules();
  renderModules();
}

$("upload").addEventListener("click", async () => {
  if (!requireConnected()) return;
  const out = $("m-verdict");
  out.replaceChildren();
  if (!state.file) return toast("Choose a module first.", "error");

  let signature;
  if (document.querySelector('input[name="sign-mode"]:checked').value === "paste") {
    try {
      signature = JSON.parse($("m-sig").value);
    } catch {
      return toast("That signature isn't valid JSON.", "error");
    }
  } else {
    if (!state.keyPair) {
      toast("Create a signing key first (Connect tab).", "error");
      return go("connect");
    }
    signature = await signModule(state.file.bytes, state.keyPair);
  }

  const button = $("upload");
  button.disabled = true;
  const r = await api("POST", "/modules", { wasmBase64: toBase64(state.file.bytes), signature });
  button.disabled = false;

  if (r.ok) {
    const exportNames = state.file.info.ok ? state.file.info.exports.filter((e) => e.kind === "function").map((e) => e.name) : [];
    rememberModule(r.data.moduleId, state.file.name, exportNames);
    out.append(
      verdict(
        "allow",
        "\u2713 Allowed",
        h("p", {}, "This module passed every policy check."),
        h(
          "dl",
          { class: "kv" },
          h("dt", {}, "Module ID"), h("dd", {}, h("code", {}, r.data.moduleId)),
          h("dt", {}, "Signer"), h("dd", {}, short(r.data.signerKeyId)),
          h("dt", {}, "Stored"), h("dd", {}, r.data.newlyStored ? "New upload" : "Already stored"),
        ),
      ),
    );
    return;
  }
  const reasons = r.data?.error?.reasons;
  out.append(
    verdict("block", "\u2715 Blocked", h("p", {}, errorText(r)), Array.isArray(reasons) && reasons.length ? renderRules(reasons) : null),
  );
});

function renderModules() {
  const list = $("m-list");
  list.replaceChildren();
  if (state.modules.length === 0) {
    list.append(h("p", { class: "empty" }, "Modules you upload will appear here."));
    return;
  }
  for (const m of state.modules) {
    const runner = h("div", { hidden: true });
    list.append(
      h(
        "div",
        { class: "card module" },
        h("h3", {}, m.name),
        h("p", { class: "hint" }, `ID ${short(m.id)}`),
        h(
          "div",
          { class: "row" },
          h("button", { class: "btn small", type: "button", onclick: () => { runner.hidden = !runner.hidden; if (!runner.hidden) buildRunner(runner, m); } }, "Run\u2026"),
          h("button", { class: "btn small", type: "button", onclick: () => copy(m.id) }, "Copy ID"),
        ),
        runner,
      ),
    );
  }
}

function buildRunner(container, m) {
  container.replaceChildren();
  const exportField =
    m.exports.length > 0
      ? h("select", { id: `exp-${m.id}`, "aria-label": "Function to run" }, m.exports.map((name) => h("option", { value: name }, name)))
      : h("input", { id: `exp-${m.id}`, type: "text", placeholder: "run", autocapitalize: "off", autocomplete: "off", "aria-label": "Function to run" });
  const args = h("input", { type: "text", inputmode: "decimal", placeholder: "e.g. 2, 3", autocomplete: "off", "aria-label": "Arguments, separated by commas" });
  const result = h("div", { role: "status" });
  const run = h("button", { class: "btn primary wide", type: "button" }, "Run");
  run.addEventListener("click", async () => {
    if (!requireConnected()) return;
    result.replaceChildren();
    const exportName = exportField.value.trim();
    if (!exportName) return toast("Enter the function to run.", "error");
    const parts = args.value.trim() === "" ? [] : args.value.split(",").map((s) => Number(s.trim()));
    if (parts.some((n) => !Number.isFinite(n))) return toast("Arguments must be numbers, separated by commas.", "error");
    run.disabled = true;
    const r = await api("POST", `/modules/${m.id}/run`, { exportName, args: parts });
    run.disabled = false;
    if (r.ok) {
      result.append(
        verdict(
          "allow",
          "\u2713 Ran successfully",
          h(
            "dl",
            { class: "kv" },
            h("dt", {}, "Result"), h("dd", {}, r.data.value === null ? "(no value)" : String(r.data.value)),
            h("dt", {}, "Logged"), h("dd", {}, r.data.logs.length ? r.data.logs.join(", ") : "nothing"),
            h("dt", {}, "Time"), h("dd", {}, `${r.data.durationMs} ms`),
          ),
        ),
      );
    } else {
      const reasons = r.data?.error?.reasons;
      result.append(
        verdict(
          "block",
          `\u2715 ${r.data?.error?.code ?? "Failed"}`,
          h("p", {}, errorText(r)),
          Array.isArray(reasons) && reasons.length ? renderRules(reasons) : null,
        ),
      );
    }
  });
  container.append(h("label", {}, "Function"), exportField, h("label", {}, "Arguments"), args, run, result);
}

$("run-by-id").addEventListener("click", () => {
  const id = $("run-id").value.trim().toLowerCase();
  if (!HEX64.test(id)) return toast("A module ID is 64 letters and numbers (0-9, a-f).", "error");
  rememberModule(id, `Module ${short(id)}`, []);
  $("run-id").value = "";
});

/* ---------- audit ---------- */

async function loadAudit() {
  if (!state.me) {
    $("chain").textContent = "Connect to see the audit trail.";
    return;
  }
  const r = await api("GET", "/audit?limit=50");
  const chain = $("chain");
  const list = $("audit-list");
  chain.replaceChildren();
  list.replaceChildren();
  if (!r.ok) {
    chain.append(verdict("info", "\u26a0 Could not load", h("p", {}, errorText(r))));
    return;
  }
  const d = r.data;
  chain.append(
    d.chainValid
      ? verdict("allow", "\u2713 Chain intact", h("p", {}, `${d.total} entries, none altered.`))
      : verdict("block", "\u2715 Chain broken", h("p", {}, `Entry ${d.chainError?.seq} failed: ${d.chainError?.message ?? "the log was altered."}`)),
  );
  if (d.entries.length === 0) {
    list.append(h("p", { class: "empty" }, "Nothing has happened yet."));
    return;
  }
  for (const e of [...d.entries].reverse()) {
    const [label, good] = EVENT_LABELS[e.type] ?? [e.type, true];
    list.append(
      h(
        "article",
        { class: `card entry ${good ? "good" : "bad"}` },
        h("h3", {}, `${good ? "\u2713" : "\u2715"} ${label}`),
        h("p", { class: "meta" }, `#${e.seq} \u00b7 ${e.actor} \u00b7 ${new Date(e.timestamp).toLocaleString()}`),
        e.moduleSha256 ? h("p", { class: "meta" }, `Module ${short(e.moduleSha256)}`) : null,
        h("details", {}, h("summary", {}, "Details"), h("pre", { tabindex: "0" }, JSON.stringify(e.details, null, 2))),
      ),
    );
  }
}

$("refresh-audit").addEventListener("click", loadAudit);

/* ---------- start up ---------- */

(async function init() {
  state.edSupported = await ed25519Supported();
  if (state.edSupported) await loadKey();
  renderKeyCard();
  renderModules();
  updateJson();
  setWho();
  if (state.key) await connect();
})();
