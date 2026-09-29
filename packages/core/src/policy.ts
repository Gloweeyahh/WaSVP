import type { VerifiedSignature } from "./sign.ts";
import { err, ok, type ModuleFacts, type Result } from "./types.ts";

/**
 * Trust policy engine.
 *
 * Design rules:
 *  - DEFAULT DENY: a module is allowed only if every rule passes.
 *  - FAIL CLOSED: a malformed policy blocks everything; it never throws.
 *  - NO SHORT-CIRCUIT: every rule is evaluated, so the UI can show all
 *    the reasons (✓ / ✕), not just the first failure.
 */

export interface AllowedImport {
  readonly module: string;
  readonly name: string;
}

/** A validated, normalised policy. Build one with parsePolicy(). */
export interface TrustPolicy {
  readonly version: 1;
  readonly name: string;
  /** keyIds (hex fingerprints) of signers you trust. Empty = trust nobody. */
  readonly allowedSigners: readonly string[];
  /** Hashes that are always blocked, even if correctly signed (revocation). */
  readonly blockedHashes: readonly string[];
  readonly maxSizeBytes: number | null;
  /** Imports a module may request. Anything else is blocked. */
  readonly allowedImports: readonly AllowedImport[];
  readonly requiredExports: readonly string[];
}

export interface PolicyError {
  readonly code: "INVALID_POLICY";
  readonly message: string;
}

export type RuleId =
  | "policy_valid"
  | "not_revoked"
  | "signed"
  | "signature_matches_module"
  | "signer_trusted"
  | "size_ok"
  | "imports_allowed"
  | "exports_present";

export interface Reason {
  readonly rule: RuleId;
  readonly passed: boolean;
  readonly message: string;
}

export interface Decision {
  readonly decision: "ALLOW" | "BLOCK";
  readonly reasons: readonly Reason[];
}

const KNOWN_KEYS: ReadonlySet<string> = new Set([
  "version",
  "name",
  "allowedSigners",
  "blockedHashes",
  "maxSizeBytes",
  "allowedImports",
  "requiredExports",
]);

const HEX64 = /^[0-9a-fA-F]{64}$/;

function bad(message: string) {
  return err<PolicyError>({ code: "INVALID_POLICY", message });
}

function hexList(value: unknown, field: string): Result<string[], PolicyError> {
  if (value === undefined) return ok([]);
  if (!Array.isArray(value)) return bad(`${field} must be an array.`);
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || !HEX64.test(item)) {
      return bad(`${field} must contain 64-character hex strings.`);
    }
    out.push(item.toLowerCase());
  }
  return ok(out);
}

/** Validate untrusted input (e.g. JSON from the UI or DB) into a TrustPolicy. */
export function parsePolicy(input: unknown): Result<TrustPolicy, PolicyError> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return bad("Policy must be an object.");
  }
  const p = input as Record<string, unknown>;

  // Strict: a typo like "alowedSigners" must not be silently ignored.
  for (const key of Object.keys(p)) {
    if (!KNOWN_KEYS.has(key)) return bad(`Unknown policy field: ${key}.`);
  }

  if (p.version !== 1) return bad("Unsupported policy version.");
  if (typeof p.name !== "string" || p.name.trim() === "" || p.name.length > 100) {
    return bad("name must be a non-empty string (max 100 characters).");
  }

  const signers = hexList(p.allowedSigners, "allowedSigners");
  if (!signers.ok) return signers;
  const blocked = hexList(p.blockedHashes, "blockedHashes");
  if (!blocked.ok) return blocked;

  let maxSizeBytes: number | null = null;
  if (p.maxSizeBytes !== undefined) {
    if (
      typeof p.maxSizeBytes !== "number" ||
      !Number.isInteger(p.maxSizeBytes) ||
      p.maxSizeBytes <= 0
    ) {
      return bad("maxSizeBytes must be a positive integer.");
    }
    maxSizeBytes = p.maxSizeBytes;
  }

  const allowedImports: AllowedImport[] = [];
  if (p.allowedImports !== undefined) {
    if (!Array.isArray(p.allowedImports)) {
      return bad("allowedImports must be an array.");
    }
    for (const item of p.allowedImports) {
      const i = item as Record<string, unknown> | null;
      if (
        typeof i !== "object" ||
        i === null ||
        typeof i.module !== "string" ||
        typeof i.name !== "string"
      ) {
        return bad("allowedImports entries need string module and name.");
      }
      allowedImports.push({ module: i.module, name: i.name });
    }
  }

  const requiredExports: string[] = [];
  if (p.requiredExports !== undefined) {
    if (
      !Array.isArray(p.requiredExports) ||
      !p.requiredExports.every((e) => typeof e === "string")
    ) {
      return bad("requiredExports must be an array of strings.");
    }
    requiredExports.push(...(p.requiredExports as string[]));
  }

  return ok({
    version: 1,
    name: p.name.trim(),
    allowedSigners: signers.value,
    blockedHashes: blocked.value,
    maxSizeBytes,
    allowedImports,
    requiredExports,
  });
}

const preview = (items: readonly string[]): string =>
  items.length <= 5
    ? items.join(", ")
    : `${items.slice(0, 5).join(", ")} and ${items.length - 5} more`;

/**
 * Decide whether a module may run.
 *
 * @param policy     untrusted policy input; validated here (fails closed)
 * @param facts      from inspectModule()
 * @param signature  from verifyModuleSignature(), or null if unsigned/invalid
 */
export function evaluatePolicy(
  policy: unknown,
  facts: ModuleFacts,
  signature: VerifiedSignature | null,
): Decision {
  const parsed = parsePolicy(policy);
  if (!parsed.ok) {
    return {
      decision: "BLOCK",
      reasons: [
        { rule: "policy_valid", passed: false, message: parsed.error.message },
      ],
    };
  }
  const p = parsed.value;

  const reasons: Reason[] = [
    { rule: "policy_valid", passed: true, message: `Policy "${p.name}" is valid.` },
  ];
  const add = (rule: RuleId, passed: boolean, message: string) => {
    reasons.push({ rule, passed, message });
  };

  // 1. Revocation beats everything else.
  const revoked = p.blockedHashes.includes(facts.sha256);
  add(
    "not_revoked",
    !revoked,
    revoked ? "This module's hash is on the block list." : "Hash is not on the block list.",
  );

  // 2. Signature checks.
  add(
    "signed",
    signature !== null,
    signature ? "Module has a valid signature." : "Module has no valid signature.",
  );
  const matches = signature !== null && signature.sha256 === facts.sha256;
  add(
    "signature_matches_module",
    matches,
    matches
      ? "Signature covers this exact module."
      : "Signature does not cover this module.",
  );
  const trusted = signature !== null && p.allowedSigners.includes(signature.keyId);
  add(
    "signer_trusted",
    trusted,
    trusted ? "Signed by a trusted signer." : "Signer is not in the trusted list.",
  );

  // 3. Size.
  const sizeOk = p.maxSizeBytes === null || facts.sizeBytes <= p.maxSizeBytes;
  add(
    "size_ok",
    sizeOk,
    p.maxSizeBytes === null
      ? "No size limit set."
      : sizeOk
        ? `Size ${facts.sizeBytes} B is within the ${p.maxSizeBytes} B limit.`
        : `Size ${facts.sizeBytes} B exceeds the ${p.maxSizeBytes} B limit.`,
  );

  // 4. Imports: anything not explicitly allowed is blocked.
  const unapproved = facts.imports
    .filter(
      (i) => !p.allowedImports.some((a) => a.module === i.module && a.name === i.name),
    )
    .map((i) => `${i.module}.${i.name}`);
  add(
    "imports_allowed",
    unapproved.length === 0,
    unapproved.length === 0
      ? "All imports are approved."
      : `Unapproved imports: ${preview(unapproved)}.`,
  );

  // 5. Required exports.
  const missing = p.requiredExports.filter(
    (name) => !facts.exports.some((e) => e.name === name),
  );
  add(
    "exports_present",
    missing.length === 0,
    missing.length === 0
      ? "All required exports are present."
      : `Missing required exports: ${preview(missing)}.`,
  );

  return {
    decision: reasons.every((r) => r.passed) ? "ALLOW" : "BLOCK",
    reasons,
  };
}
