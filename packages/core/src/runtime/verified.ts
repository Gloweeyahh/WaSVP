import { inspectModule } from "../inspect.ts";
import { evaluatePolicy, type Decision, type Reason } from "../policy.ts";
import { verifyModuleSignature } from "../sign.ts";
import { err, ok, type ModuleFacts, type Result } from "../types.ts";

/**
 * The brand symbol is deliberately NOT exported. Without it, no other file
 * can build a VerifiedModule by hand, so the only way to get one (and
 * therefore the only way to call runModule) is through authorize().
 */
declare const verifiedBrand: unique symbol;

export interface VerifiedModule {
  readonly [verifiedBrand]: true;
  /** Private copy of the bytes, taken at authorization time. */
  readonly bytes: Uint8Array;
  readonly facts: ModuleFacts;
  readonly signerKeyId: string;
  readonly decision: Decision;
}

export interface AuthorizeError {
  readonly code: "INVALID_MODULE" | "BLOCKED";
  readonly message: string;
  /** Rule-by-rule results, ready to show in the UI or audit log. */
  readonly reasons: readonly Reason[];
}

/**
 * The gate: module bytes + signature + policy in, VerifiedModule out.
 * Anything short of a full ALLOW returns an error.
 */
export function authorize(
  bytes: Uint8Array,
  signature: unknown,
  policy: unknown,
): Result<VerifiedModule, AuthorizeError> {
  const facts = inspectModule(bytes);
  if (!facts.ok) {
    return err({
      code: "INVALID_MODULE",
      message: facts.error.message,
      reasons: [],
    });
  }

  const verified = verifyModuleSignature(bytes, signature);
  const decision = evaluatePolicy(
    policy,
    facts.value,
    verified.ok ? verified.value : null,
  );

  if (decision.decision !== "ALLOW" || !verified.ok) {
    return err({
      code: "BLOCKED",
      message: "Module was blocked by policy.",
      reasons: decision.reasons,
    });
  }

  return ok(
    Object.freeze({
      bytes: new Uint8Array(bytes),
      facts: facts.value,
      signerKeyId: verified.value.keyId,
      decision,
    }) as VerifiedModule,
  );
}
