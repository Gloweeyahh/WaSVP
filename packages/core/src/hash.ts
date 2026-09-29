import { createHash, timingSafeEqual } from "node:crypto";
import type { Sha256Hex } from "./types.ts";

export function sha256Hex(bytes: Uint8Array): Sha256Hex {
  return createHash("sha256").update(bytes).digest("hex") as Sha256Hex;
}

/**
 * Constant-time comparison of two hex digests.
 * Use this (not ===) whenever comparing an expected hash to a computed one.
 */
export function hashesEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a.toLowerCase(), "utf8");
  const bb = Buffer.from(b.toLowerCase(), "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
