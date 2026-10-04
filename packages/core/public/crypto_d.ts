export function toHex(buffer: ArrayBuffer | Uint8Array): string;
export function toBase64(bytes: Uint8Array): string;
export function toBase64Url(bytes: Uint8Array): string;
export function sha256Hex(bytes: Uint8Array): Promise<string>;
export function ed25519Supported(): Promise<boolean>;
export function generateKeyPair(): Promise<CryptoKeyPair>;
export function describeKey(pair: CryptoKeyPair): Promise<{ publicKey: string; keyId: string }>;
export function signModule(wasmBytes: Uint8Array, pair: CryptoKeyPair): Promise<{
  version: 1;
  algorithm: "ed25519";
  sha256: string;
  keyId: string;
  publicKey: string;
  signature: string;
}>;
export function inspectWasm(bytes: Uint8Array):
  | { ok: true; imports: { module: string; name: string; kind: string }[]; exports: { name: string; kind: string }[] }
  | { ok: false; error: string };
