import { sha256Hex } from "../hash.ts";
import { parsePolicy, type Reason } from "../policy.ts";
import { runModule, type RunErrorCode, type RunLimits, type RunOutput } from "../runtime/run.ts";
import { authorize } from "../runtime/verified.ts";
import { err, ok, type Result } from "../types.ts";
import { canonicalJson, verifyAuditChain, type AuditEntry, type AuditLogger, type ChainError, type Json } from "./audit.ts";
import type { ModuleStore } from "./stores.ts";

export type ServiceErrorCode =
  | "INVALID_REQUEST"
  | "INVALID_MODULE"
  | "INVALID_POLICY"
  | "BLOCKED"
  | "NOT_FOUND"
  | RunErrorCode;

export interface ServiceError {
  readonly code: ServiceErrorCode;
  readonly message: string;
  /** Rule-by-rule policy results when a module was blocked. */
  readonly reasons?: readonly Reason[];
}

export interface ServiceDeps {
  readonly audit: AuditLogger;
  readonly modules: ModuleStore;
  /** Initial policy (untrusted input; an invalid one blocks everything). */
  readonly policy: unknown;
  readonly now?: () => Date;
}

const MAX_ACTOR = 100;
const failedRules = (reasons: readonly Reason[]): string[] =>
  reasons.filter((r) => !r.passed).map((r) => r.rule);

/**
 * The application layer. HTTP routes (next step) should be thin wrappers
 * around these methods: all the real decisions and all the auditing live here.
 *
 * Every action, allowed or refused, leaves an audit entry.
 */
export class WasvpService {
  private policy: unknown;
  private readonly audit: AuditLogger;
  private readonly modules: ModuleStore;
  private readonly now: () => Date;

  constructor(deps: ServiceDeps) {
    this.policy = deps.policy;
    this.audit = deps.audit;
    this.modules = deps.modules;
    this.now = deps.now ?? (() => new Date());
  }

  private static actorError(actor: unknown): ServiceError | null {
    return typeof actor === "string" && actor.trim() !== "" && actor.length <= MAX_ACTOR
      ? null
      : { code: "INVALID_REQUEST", message: `actor must be a non-empty string (max ${MAX_ACTOR} chars).` };
  }

  /** Replace the active policy. Invalid policies are rejected and the old one stays. */
  async setPolicy(actor: string, policy: unknown): Promise<Result<{ policySha256: string }, ServiceError>> {
    const bad = WasvpService.actorError(actor);
    if (bad) return err(bad);

    const parsed = parsePolicy(policy);
    if (!parsed.ok) {
      await this.audit.record({
        actor,
        type: "policy.rejected",
        moduleSha256: null,
        details: { reason: parsed.error.message },
      });
      return err({ code: "INVALID_POLICY", message: parsed.error.message });
    }

    const policySha256 = sha256Hex(
      new TextEncoder().encode(canonicalJson(parsed.value as unknown as Json)),
    );
    this.policy = parsed.value;
    await this.audit.record({
      actor,
      type: "policy.changed",
      moduleSha256: null,
      details: {
        policyName: parsed.value.name,
        policySha256,
        trustedSigners: parsed.value.allowedSigners.length,
        blockedHashes: parsed.value.blockedHashes.length,
      },
    });
    return ok({ policySha256 });
  }

  /** Upload a module + signature. Stored only if the current policy allows it. */
  async submit(input: {
    actor: string;
    bytes: Uint8Array;
    signature: unknown;
  }): Promise<Result<{ moduleId: string; signerKeyId: string; newlyStored: boolean }, ServiceError>> {
    const bad = WasvpService.actorError(input.actor);
    if (bad) return err(bad);

    const decision = authorize(input.bytes, input.signature, this.policy);
    if (!decision.ok) {
      await this.audit.record({
        actor: input.actor,
        type: "module.blocked",
        moduleSha256: decision.error.code === "INVALID_MODULE" ? null : sha256Hex(input.bytes),
        details: {
          code: decision.error.code,
          failedRules: failedRules(decision.error.reasons),
        },
      });
      return err({
        code: decision.error.code,
        message: decision.error.message,
        reasons: decision.error.reasons,
      });
    }

    const m = decision.value;
    const newlyStored = await this.modules.put({
      sha256: m.facts.sha256,
      bytes: m.bytes,
      signature: input.signature,
      uploadedBy: input.actor,
      uploadedAt: this.now().toISOString(),
    });
    await this.audit.record({
      actor: input.actor,
      type: "module.accepted",
      moduleSha256: m.facts.sha256,
      details: {
        sizeBytes: m.facts.sizeBytes,
        signerKeyId: m.signerKeyId,
        imports: m.facts.imports.map((i) => `${i.module}.${i.name}`),
        exports: m.facts.exports.map((e) => e.name),
        newlyStored,
      },
    });
    return ok({ moduleId: m.facts.sha256, signerKeyId: m.signerKeyId, newlyStored });
  }

  /**
   * Run a stored module. It is re-authorised against the CURRENT policy
   * every time, so revoking a hash or signer takes effect immediately.
   */
  async run(input: {
    actor: string;
    moduleId: string;
    exportName: string;
    args?: readonly number[];
    limits?: RunLimits;
  }): Promise<Result<RunOutput, ServiceError>> {
    const bad = WasvpService.actorError(input.actor);
    if (bad) return err(bad);

    const stored = await this.modules.get(input.moduleId);
    if (!stored) {
      await this.audit.record({
        actor: input.actor,
        type: "run.failed",
        moduleSha256: null,
        details: { code: "NOT_FOUND", requestedId: String(input.moduleId).slice(0, 100) },
      });
      return err({ code: "NOT_FOUND", message: "No such module." });
    }

    const decision = authorize(stored.bytes, stored.signature, this.policy);
    if (!decision.ok) {
      await this.audit.record({
        actor: input.actor,
        type: "run.blocked",
        moduleSha256: stored.sha256,
        details: { failedRules: failedRules(decision.error.reasons) },
      });
      return err({
        code: "BLOCKED",
        message: "Module is no longer allowed by the current policy.",
        reasons: decision.error.reasons,
      });
    }

    const permissions = decision.value.facts.imports.map((i) => `${i.module}.${i.name}`);
    const args = input.args ?? [];
    const result = await runModule(decision.value, { exportName: input.exportName, args }, input.limits);

    if (result.ok) {
      await this.audit.record({
        actor: input.actor,
        type: "run.completed",
        moduleSha256: stored.sha256,
        details: {
          exportName: input.exportName,
          args: [...args],
          permissions,
          result: result.value.value === null ? null : String(result.value.value),
          logCount: result.value.logs.length,
          durationMs: Math.round(result.value.durationMs),
        },
      });
      return ok(result.value);
    }

    await this.audit.record({
      actor: input.actor,
      type: "run.failed",
      moduleSha256: stored.sha256,
      details: {
        exportName: String(input.exportName).slice(0, 100),
        permissions,
        code: result.error.code,
        message: result.error.message,
      },
    });
    return err({ code: result.error.code, message: result.error.message });
  }

  /** The full audit trail plus the result of checking its hash chain. */
  async auditTrail(): Promise<{
    entries: readonly AuditEntry[];
    chain: Result<{ length: number }, ChainError>;
  }> {
    const entries = await this.audit.list();
    return { entries, chain: verifyAuditChain(entries) };
  }
}
