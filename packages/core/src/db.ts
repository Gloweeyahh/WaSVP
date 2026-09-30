import { PostgresAuditStore, PostgresModuleStore, type SqlClient } from "./service/postgres.ts";

/**
 * Connect to Postgres (Supabase or any other) and return WaSVP's stores.
 * `pg` is loaded on demand, so running without a database needs no driver.
 */
export async function connectPostgres(connectionString: string) {
  const { default: pg } = await import("pg");

  // Hosted databases need TLS. `rejectUnauthorized: false` encrypts the
  // connection but does not verify the server's certificate; fine for
  // development, tighten it with your provider's CA certificate for production.
  const isLocal = /(localhost|127\.0\.0\.1)/.test(connectionString);
  const pool = new pg.Pool({
    connectionString,
    max: 5,
    ssl: isLocal ? false : { rejectUnauthorized: false },
  });

  const client: SqlClient = { query: (text, values) => pool.query(text, values) };
  await client.query("SELECT 1"); // fail fast if the connection is wrong

  return {
    audit: new PostgresAuditStore(client),
    modules: new PostgresModuleStore(client),
    close: () => pool.end(),
  };
}
