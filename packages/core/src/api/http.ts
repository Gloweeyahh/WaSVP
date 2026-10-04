import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { sha256Hex } from "../hash.ts";
import type { Reason } from "../policy.ts";
import { verifyAuditChain } from "../service/audit.ts";
import type { ServiceErrorCode, WasvpService } from "../service/service.ts";
import { err, ok, type Result } from "../types.ts";

/**
 * HTTP API. Zero dependencies (node:http) and deliberately thin:
 * it authenticates, parses, calls WasvpService, and formats the reply.
 * All security decisions live in the service and core.
 */

export type Role = "admin" | "member";

export interface ApiKeyConfig {
  /** Name written to the audit log. Comes from the key, never from the request. */
  readonly actor: string;
  readonly role: Role;
}

export interface AppConfig {
  readonly service: WasvpService;
  /** Map of secret API key -> who it belongs to. Keys must be 16+ characters. */
  readonly apiKeys: Readonly<Record<string, ApiKeyConfig>>;
  /** Max request body. Default 15 MB (a 10 MB module is ~13.4 MB in base64). */
  readonly maxBodyBytes?: number;
  /** Server-side ceiling on run time, whatever the caller asks for. Default 5000. */
  readonly maxTimeoutMs?: number;
  /** Called with unexpected errors. They are never sent to the client. */
  readonly log?: (message: string, error?: unknown) => void;
}

interface ApiError {
  readonly status: number;
  readonly code: string;
  readonly message: string;
  readonly reasons?: readonly Reason[];
}

const MIN_KEY_LENGTH = 16;
const HEX64 = /^[0-9a-f]{64}$/;

/** The dashboard: plain files in packages/core/public, served by this same server. */
const PUBLIC_DIR = new URL("../../public/", import.meta.url);
const STATIC_FILES: Record<string, { file: string; type: string }> = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/app.js": { file: "app.js", type: "text/javascript; charset=utf-8" },
  "/crypto.js": { file: "crypto.js", type: "text/javascript; charset=utf-8" },
  "/app.css": { file: "app.css", type: "text/css; charset=utf-8" },
};

/** Only this site's own files may load or connect: no inline scripts, no third parties. */
const PAGE_SECURITY_HEADERS = {
  "content-security-policy":
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": "no-cache",
};

const STATUS: Record<ServiceErrorCode, number> = {
  INVALID_REQUEST: 400,
  INVALID_MODULE: 400,
  INVALID_POLICY: 400,
  INVALID_ARGS: 400,
  BLOCKED: 403,
  NOT_FOUND: 404,
  TIMEOUT: 408,
  TRAP: 422,
  EXPORT_NOT_FOUND: 422,
  HOST_IMPORT_MISSING: 422,
  INSTANTIATION_FAILED: 422,
  HASH_CHANGED: 500,
  WORKER_FAILED: 500,
};

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...extra,
  });
  res.end(JSON.stringify(body));
}

function sendError(res: ServerResponse, e: ApiError, extra: Record<string, string> = {}) {
  sendJson(
    res,
    e.status,
    { error: { code: e.code, message: e.message, ...(e.reasons ? { reasons: e.reasons } : {}) } },
    extra,
  );
}

const apiError = (status: number, code: string, message: string) =>
  err<ApiError>({ status, code, message });

function readBody(req: IncomingMessage, maxBytes: number): Promise<Result<Buffer, ApiError>> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    const finish = (r: Result<Buffer, ApiError>) => {
      if (!done) {
        done = true;
        resolve(r);
      }
    };
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        finish(apiError(413, "PAYLOAD_TOO_LARGE", `Request body exceeds ${maxBytes} bytes.`));
      } else {
        chunks.push(chunk);
      }
    });
    req.on("end", () => finish(ok(Buffer.concat(chunks))));
    req.on("error", () => finish(apiError(400, "INVALID_REQUEST", "Could not read request body.")));
  });
}

async function readJson(req: IncomingMessage, maxBytes: number): Promise<Result<unknown, ApiError>> {
  const type = req.headers["content-type"] ?? "";
  if (!type.toLowerCase().startsWith("application/json")) {
    return apiError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json.");
  }
  const body = await readBody(req, maxBytes);
  if (!body.ok) return body;
  try {
    return ok(JSON.parse(body.value.toString("utf8")) as unknown);
  } catch {
    return apiError(400, "INVALID_REQUEST", "Body is not valid JSON.");
  }
}

function decodeBase64(value: unknown): Buffer | null {
  if (typeof value !== "string" || value === "") return null;
  const bytes = Buffer.from(value, "base64");
  return bytes.toString("base64") === value ? bytes : null; // reject sloppy encodings
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** Build the HTTP server. Call .listen() on the result yourself. */
export function createApp(config: AppConfig): Server {
  const keys = new Map<string, ApiKeyConfig>();
  for (const [secret, who] of Object.entries(config.apiKeys)) {
    if (secret.length < MIN_KEY_LENGTH) {
      throw new Error(`API keys must be at least ${MIN_KEY_LENGTH} characters.`);
    }
    // Store only hashes, so lookups never compare raw secrets.
    keys.set(sha256Hex(new TextEncoder().encode(secret)), who);
  }
  const maxBody = config.maxBodyBytes ?? 15 * 1024 * 1024;
  const maxTimeout = config.maxTimeoutMs ?? 5000;
  const log = config.log ?? (() => undefined);
  const { service } = config;

  const assets = new Map<string, { body: Buffer; type: string }>();
  for (const [route, { file, type }] of Object.entries(STATIC_FILES)) {
    try {
      assets.set(route, { body: readFileSync(new URL(file, PUBLIC_DIR)), type });
    } catch (error) {
      log(`Dashboard file missing: ${file}`, error);
    }
  }

  function authenticate(req: IncomingMessage): ApiKeyConfig | null {
    const header = req.headers.authorization ?? "";
    const match = /^Bearer (.+)$/.exec(header);
    if (!match) return null;
    return keys.get(sha256Hex(new TextEncoder().encode(match[1]!))) ?? null;
  }

  async function route(req: IncomingMessage, res: ServerResponse) {
    const method = req.method ?? "GET";
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    const url = new URL(req.url ?? "/", "http://localhost");

    if (path === "/health") {
      if (method !== "GET") return sendError(res, { status: 405, code: "METHOD_NOT_ALLOWED", message: "Use GET." }, { allow: "GET" });
      return sendJson(res, 200, { ok: true });
    }

    // Dashboard files are public (they contain no secrets).
    const asset = assets.get(path);
    if (asset) {
      if (method !== "GET" && method !== "HEAD") {
        return sendError(res, { status: 405, code: "METHOD_NOT_ALLOWED", message: "Use GET." }, { allow: "GET, HEAD" });
      }
      res.writeHead(200, { "content-type": asset.type, ...PAGE_SECURITY_HEADERS });
      return void res.end(method === "HEAD" ? undefined : asset.body);
    }

    // Authenticate before routing so unknown paths reveal nothing.
    const who = authenticate(req);
    if (!who) {
      return sendError(
        res,
        { status: 401, code: "UNAUTHORIZED", message: "Missing or invalid API key." },
        { "www-authenticate": "Bearer" },
      );
    }

    const notAllowed = (allow: string) =>
      sendError(res, { status: 405, code: "METHOD_NOT_ALLOWED", message: `Use ${allow}.` }, { allow });
    const fromService = (e: { code: ServiceErrorCode; message: string; reasons?: readonly Reason[] }) =>
      sendError(res, {
        status: STATUS[e.code],
        code: e.code,
        message: e.message,
        ...(e.reasons ? { reasons: e.reasons } : {}),
      });

    // GET /me: who am I?
    if (path === "/me") {
      if (method !== "GET") return notAllowed("GET");
      return sendJson(res, 200, { actor: who.actor, role: who.role });
    }

    // POST /modules: upload
    if (path === "/modules") {
      if (method !== "POST") return notAllowed("POST");
      const body = await readJson(req, maxBody);
      if (!body.ok) return sendError(res, body.error);
      if (!isObject(body.value)) {
        return sendError(res, { status: 400, code: "INVALID_REQUEST", message: "Body must be a JSON object." });
      }
      const bytes = decodeBase64(body.value.wasmBase64);
      if (!bytes) {
        return sendError(res, { status: 400, code: "INVALID_REQUEST", message: "wasmBase64 must be a valid base64 string." });
      }
      const r = await service.submit({
        actor: who.actor,
        bytes: new Uint8Array(bytes),
        signature: body.value.signature,
      });
      if (!r.ok) return fromService(r.error);
      return sendJson(res, r.value.newlyStored ? 201 : 200, r.value);
    }

    // POST /modules/:id/run
    const runMatch = /^\/modules\/([^/]+)\/run$/.exec(path);
    if (runMatch) {
      const moduleId = runMatch[1]!;
      if (method !== "POST") return notAllowed("POST");
      if (!HEX64.test(moduleId)) {
        return sendError(res, { status: 404, code: "NOT_FOUND", message: "No such module." });
      }
      const body = await readJson(req, maxBody);
      if (!body.ok) return sendError(res, body.error);
      if (!isObject(body.value) || typeof body.value.exportName !== "string") {
        return sendError(res, { status: 400, code: "INVALID_REQUEST", message: "exportName (string) is required." });
      }
      const { args, timeoutMs } = body.value;
      if (args !== undefined && (!Array.isArray(args) || !args.every((a) => typeof a === "number"))) {
        return sendError(res, { status: 400, code: "INVALID_REQUEST", message: "args must be an array of numbers." });
      }
      if (timeoutMs !== undefined && (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs <= 0)) {
        return sendError(res, { status: 400, code: "INVALID_REQUEST", message: "timeoutMs must be a positive number." });
      }
      const r = await service.run({
        actor: who.actor,
        moduleId,
        exportName: body.value.exportName,
        args: (args as number[] | undefined) ?? [],
        limits: { timeoutMs: Math.min(timeoutMs ?? maxTimeout, maxTimeout) },
      });
      if (!r.ok) return fromService(r.error);
      const v = r.value;
      return sendJson(res, 200, {
        value: typeof v.value === "bigint" ? v.value.toString() : v.value,
        valueType: typeof v.value === "bigint" ? "bigint" : v.value === null ? "none" : "number",
        logs: v.logs,
        durationMs: Math.round(v.durationMs),
      });
    }

    // PUT /policy (admin only)
    if (path === "/policy") {
      if (method !== "PUT") return notAllowed("PUT");
      if (who.role !== "admin") {
        return sendError(res, { status: 403, code: "FORBIDDEN", message: "Admin key required." });
      }
      const body = await readJson(req, maxBody);
      if (!body.ok) return sendError(res, body.error);
      const r = await service.setPolicy(who.actor, body.value);
      if (!r.ok) return fromService(r.error);
      return sendJson(res, 200, r.value);
    }

    // GET /audit?limit=N
    if (path === "/audit") {
      if (method !== "GET") return notAllowed("GET");
      const raw = url.searchParams.get("limit");
      const limit = raw === null ? 100 : Number(raw);
      if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
        return sendError(res, { status: 400, code: "INVALID_REQUEST", message: "limit must be an integer from 1 to 1000." });
      }
      const trail = await service.auditTrail();
      const chain = verifyAuditChain(trail.entries);
      return sendJson(res, 200, {
        total: trail.entries.length,
        chainValid: chain.ok,
        ...(chain.ok ? {} : { chainError: chain.error }),
        entries: trail.entries.slice(-limit),
      });
    }

    return sendError(res, { status: 404, code: "NOT_FOUND", message: "No such route." });
  }

  return createServer((req, res) => {
    route(req, res).catch((error: unknown) => {
      log("Unhandled error while handling request", error);
      if (!res.headersSent) {
        sendError(res, { status: 500, code: "INTERNAL", message: "Internal error." });
      } else {
        res.end();
      }
    });
  });
}
