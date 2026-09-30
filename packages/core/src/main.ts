/**
 * Start the API:
 *   WASVP_ADMIN_KEY=...16+chars... WASVP_MEMBER_KEY=...16+chars... node src/main.ts
 *
 * Add DATABASE_URL=postgres://... to keep modules and the audit log in
 * Postgres. Without it, data is held in memory and resets on restart.
 *
 * The policy always starts as "default-deny": nothing is allowed until an
 * admin sets a policy with PUT /policy (after a restart, set it again).
 */
import { createApp } from "./api/http.ts";
import { AuditLogger, InMemoryAuditStore, type AuditStore } from "./service/audit.ts";
import { WasvpService } from "./service/service.ts";
import { InMemoryModuleStore, type ModuleStore } from "./service/stores.ts";

const admin = process.env.WASVP_ADMIN_KEY ?? "";
const member = process.env.WASVP_MEMBER_KEY ?? "";
if (admin.length < 16 || member.length < 16 || admin === member) {
  console.error(
    "Set WASVP_ADMIN_KEY and WASVP_MEMBER_KEY to two different secrets of at least 16 characters.",
  );
  process.exit(1);
}

let auditStore: AuditStore = new InMemoryAuditStore();
let modules: ModuleStore = new InMemoryModuleStore();
let close: () => Promise<void> = async () => undefined;

const databaseUrl = process.env.DATABASE_URL;
if (databaseUrl) {
  try {
    const { connectPostgres } = await import("./db.ts");
    const db = await connectPostgres(databaseUrl);
    auditStore = db.audit;
    modules = db.modules;
    close = () => db.close();
    console.log("Using Postgres storage.");
  } catch (error) {
    console.error("Could not connect to the database:", error instanceof Error ? error.message : error);
    process.exit(1);
  }
} else {
  console.log("No DATABASE_URL set: using in-memory storage (resets on restart).");
}

const service = new WasvpService({
  audit: new AuditLogger(auditStore),
  modules,
  policy: { version: 1, name: "default-deny" },
});

const server = createApp({
  service,
  apiKeys: {
    [admin]: { actor: "admin", role: "admin" },
    [member]: { actor: "member", role: "member" },
  },
  log: (message, error) => console.error(message, error),
});

const port = Number(process.env.PORT ?? 3000);
server.listen(port, "127.0.0.1", () => {
  console.log(`WaSVP API listening on http://127.0.0.1:${port}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    server.close(() => void close().finally(() => process.exit(0)));
  });
}
