/** Storage port for uploaded modules. Swap for PostgreSQL + object storage later. */
export interface StoredModule {
  readonly sha256: string;
  readonly bytes: Uint8Array;
  /** The signature exactly as submitted; re-verified on every run. */
  readonly signature: unknown;
  readonly uploadedBy: string;
  readonly uploadedAt: string;
}

export interface ModuleStore {
  /** Returns true if newly stored, false if that hash already existed. */
  put(module: StoredModule): Promise<boolean>;
  get(sha256: string): Promise<StoredModule | null>;
}

/** Content-addressed and immutable: first upload of a hash wins. */
export class InMemoryModuleStore implements ModuleStore {
  private readonly modules = new Map<string, StoredModule>();

  async put(module: StoredModule) {
    if (this.modules.has(module.sha256)) return false;
    this.modules.set(module.sha256, {
      ...module,
      bytes: new Uint8Array(module.bytes),
      signature: structuredClone(module.signature),
    });
    return true;
  }

  async get(sha256: string) {
    const m = this.modules.get(sha256);
    return m
      ? { ...m, bytes: new Uint8Array(m.bytes), signature: structuredClone(m.signature) }
      : null;
  }
}
