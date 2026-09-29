import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { hashesEqual, sha256Hex } from "./hash.ts";
import { inspectModule } from "./inspect.ts";
import { err, ok, type Result } from "./types.ts";

/**
 * Ed25519 signing for WebAssembly modules.
 *
 * What a signature MEANS: "the holder of this key vouches for the module
 * whose SHA-256 is X." It does NOT mean the signer is trusted. Deciding
 * which signers to trust is the policy engine's job (step 3).
 *
 * Keys are raw 32-byte Ed25519 keys encoded as base64url strings.
 */

const SIGNATURE_VERSION = 1;
const ALGORITHM = "ed25519";

/**
 * Domain separation: signatures are made over a labelled message, never the
 * bare hash. This stops a signature made for some other purpose from being
 * replayed as a module signature.
 */
const messageFor = (sha256: string): Buffer =>
  Buffer.from(`wasvp:v1:module-sha256:${sha256}`, "utf8");

export interface SigningKeyPair {
  readonly publicKey: string;
  readonly privateKey: string;
}

export interface ModuleSignature {
  readonly version: 1;
  readonly algorithm: "ed25519";
  /** SHA-256 of the module the signer vouches for (hex). */
  readonly sha256: string;
  /** Fingerprint of publicKey: SHA-256 of the raw public key bytes (hex). */
  readonly keyId: string;
  /** Raw Ed25519 public key, base64url. */
  readonly publicKey: string;
  /** Ed25519 signature, base64url. */
  readonly signature: string;
}

export type SignErrorCode = "INVALID_KEY" | "KEY_MISMATCH" | "INVALID_MODULE";
export interface SignError {
  readonly code: SignErrorCode;
  readonly message: string;
}

export type VerifyErrorCode =
  | "MALFORMED_SIGNATURE"
  | "UNSUPPORTED_VERSION"
  | "KEY_ID_MISMATCH"
  | "HASH_MISMATCH"
  | "BAD_SIGNATURE";
export interface VerifyError {
  readonly code: VerifyErrorCode;
  readonly message: string;
}

export interface VerifiedSignature {
  readonly keyId: string;
  readonly sha256: string;
}

/** Strictly decode base64url to exactly `length` bytes, or return null. */
function decodeKey(value: unknown, length: number): Buffer | null {
  if (typeof value !== "string") return null;
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== length) return null;
  // Reject non-canonical encodings (stray characters, padding bits).
  if (bytes.toString("base64url") !== value) return null;
  return bytes;
}

const fingerprint = (rawPublicKey: Buffer): string =>
  sha256Hex(new Uint8Array(rawPublicKey));

function publicKeyObject(raw: Buffer) {
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

function privateKeyObject(rawPrivate: Buffer, rawPublic: Buffer) {
  return createPrivateKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      d: rawPrivate.toString("base64url"),
      x: rawPublic.toString("base64url"),
    },
    format: "jwk",
  });
}

export function generateSigningKeyPair(): SigningKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "jwk" });
  const priv = privateKey.export({ format: "jwk" });
  return { publicKey: pub.x as string, privateKey: priv.d as string };
}

/** Fingerprint of a public key, or an error if the key is malformed. */
export function keyIdOf(publicKey: string): Result<string, SignError> {
  const raw = decodeKey(publicKey, 32);
  if (!raw) {
    return err({ code: "INVALID_KEY", message: "Public key is malformed." });
  }
  return ok(fingerprint(raw));
}

/** Sign a module. Refuses to sign anything that isn't a valid WASM module. */
export function signModule(
  bytes: Uint8Array,
  keyPair: SigningKeyPair,
): Result<ModuleSignature, SignError> {
  const rawPub = decodeKey(keyPair.publicKey, 32);
  const rawPriv = decodeKey(keyPair.privateKey, 32);
  if (!rawPub || !rawPriv) {
    return err({ code: "INVALID_KEY", message: "Key pair is malformed." });
  }

  const facts = inspectModule(bytes);
  if (!facts.ok) {
    return err({ code: "INVALID_MODULE", message: facts.error.message });
  }

  const privKey = privateKeyObject(rawPriv, rawPub);
  // Make sure the private key really belongs to the stated public key.
  const derived = createPublicKey(privKey).export({ format: "jwk" }).x;
  if (derived !== keyPair.publicKey) {
    return err({
      code: "KEY_MISMATCH",
      message: "Private key does not match the public key.",
    });
  }

  const signature = sign(null, messageFor(facts.value.sha256), privKey);
  return ok({
    version: SIGNATURE_VERSION,
    algorithm: ALGORITHM,
    sha256: facts.value.sha256,
    keyId: fingerprint(rawPub),
    publicKey: keyPair.publicKey,
    signature: signature.toString("base64url"),
  });
}

/**
 * Verify a signature against the module bytes actually in hand.
 *
 * Nothing in the signature is trusted: the hash is recomputed from `bytes`,
 * and the keyId is recomputed from the public key.
 */
export function verifyModuleSignature(
  bytes: Uint8Array,
  input: unknown,
): Result<VerifiedSignature, VerifyError> {
  const fail = (code: VerifyErrorCode, message: string) =>
    err<VerifyError>({ code, message });

  if (typeof input !== "object" || input === null) {
    return fail("MALFORMED_SIGNATURE", "Signature must be an object.");
  }
  const s = input as Record<string, unknown>;

  if (s.version !== SIGNATURE_VERSION || s.algorithm !== ALGORITHM) {
    return fail("UNSUPPORTED_VERSION", "Unsupported signature version.");
  }
  const rawPub = decodeKey(s.publicKey, 32);
  const rawSig = decodeKey(s.signature, 64);
  if (
    !rawPub ||
    !rawSig ||
    typeof s.sha256 !== "string" ||
    typeof s.keyId !== "string"
  ) {
    return fail("MALFORMED_SIGNATURE", "Signature fields are missing or invalid.");
  }

  const actualKeyId = fingerprint(rawPub);
  if (!hashesEqual(s.keyId, actualKeyId)) {
    return fail("KEY_ID_MISMATCH", "keyId does not match the public key.");
  }

  const actualHash = sha256Hex(bytes);
  if (!hashesEqual(s.sha256, actualHash)) {
    return fail("HASH_MISMATCH", "Module does not match the signed hash.");
  }

  const valid = verify(
    null,
    messageFor(actualHash),
    publicKeyObject(rawPub),
    rawSig,
  );
  if (!valid) return fail("BAD_SIGNATURE", "Signature is not valid.");

  return ok({ keyId: actualKeyId, sha256: actualHash });
}
