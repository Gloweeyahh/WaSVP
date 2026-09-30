import { InMemoryAuditStore } from "../src/service/audit.ts";
import { InMemoryModuleStore } from "../src/service/stores.ts";
import { auditStoreContract, moduleStoreContract } from "./store-contract.ts";

auditStoreContract("memory", async () => new InMemoryAuditStore());
moduleStoreContract("memory", async () => new InMemoryModuleStore());
