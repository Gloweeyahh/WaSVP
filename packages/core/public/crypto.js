// Browser-side helpers for the WaSVP dashboard.
// Private keys never leave the browser: signing happens here, and only the
// finished signature is sent to the server.

const encoder = new TextEncoder();

export function toHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function binaryString(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return out;
}

/** Standard base64 (used to upload the .wasm file). */
export function toBase64(bytes) {
  return btoa(binaryString(bytes));
}

/** URL-safe base64 without padding (used for keys and signatures). */
export function toBase64Url(bytes) {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function sha256Hex(bytes) {
  return toHex(await crypto.subtle.digest("SHA-256", bytes));
}

/** Can this browser sign with Ed25519? (Needs Chrome 137+, Safari 17+, Firefox 129+.) */
export async function ed25519Supported() {
  try {
    await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    return true;
  } catch {
    return false;
  }
}

/** The private key is non-extractable: it can sign, but can never be read out. */
export function generateKeyPair() {
  return crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
}

export async function describeKey(pair) {
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { publicKey: toBase64Url(raw), keyId: await sha256Hex(raw) };
}

/** Build a signature object in exactly the format the WaSVP server verifies. */
export async function signModule(wasmBytes, pair) {
  const sha256 = await sha256Hex(wasmBytes);
  const { publicKey, keyId } = await describeKey(pair);
  const message = encoder.encode(`wasvp:v1:module-sha256:${sha256}`);
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, message),
  );
  return {
    version: 1,
    algorithm: "ed25519",
    sha256,
    keyId,
    publicKey,
    signature: toBase64Url(signature),
  };
}

/** Look inside a module without running it. */
export function inspectWasm(bytes) {
  try {
    const module = new WebAssembly.Module(bytes);
    return {
      ok: true,
      imports: WebAssembly.Module.imports(module).map((i) => ({ module: i.module, name: i.name, kind: i.kind })),
      exports: WebAssembly.Module.exports(module).map((e) => ({ name: e.name, kind: e.kind })),
    };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : "Not a valid WebAssembly module." };
  }
}
