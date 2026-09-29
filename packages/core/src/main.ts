/**
 * Start the API:
 *   WASVP_ADMIN_KEY=...16+chars... WASVP_MEMBER_KEY=...16+chars... node src/main.ts
 *
 * Data is held in memory for now, so it resets when the server restarts.
 * The policy starts as "default-deny": nothing is allowed until an admin
 * sets a policy with PUT /policy.
 */
import { createApp } from "./api/http.ts";
import { AuditLogger, InMemoryAuditStore } from "./service/audit.ts";
import { WasvpService } from "./service/service.ts";
import { InMemoryModuleStore } from "./service/stores.ts";

const admin = process.env.WASVP_ADMIN_KEY ?? "";
const member = process.env.WASVP_MEMBER_KEY ?? "";
if (admin.length < 16 || member.length < 16 || admin === member) {
  console.error(
    "Set WASVP_ADMIN_KEY and WASVP_MEMBER_KEY to two different secrets of at least 16 characters.",
  );
  process.exit(1);
}

const service = new WasvpService({
  audit: new AuditLogger(new InMemoryAuditStore()),
  modules: new InMemoryModuleStore(),
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
