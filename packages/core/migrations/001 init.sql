-- WaSVP schema, version 1. Run once in the Supabase SQL Editor (or psql).
--
-- Design notes
--  * Timestamps and JSON are stored as TEXT on purpose. The audit hash chain
--    covers their exact text, so the database must hand back byte-identical
--    values. (timestamptz / jsonb would reformat them.)
--  * audit_entries is append-only, enforced by triggers.
--  * Row Level Security is switched on with NO policies, so Supabase's public
--    API keys (anon / authenticated) can never read or write these tables.
--    The WaSVP server connects with the database connection string instead.

CREATE TABLE modules (
  sha256         TEXT PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  bytes          BYTEA NOT NULL CHECK (octet_length(bytes) > 0),
  signature_json TEXT NOT NULL,
  uploaded_by    TEXT NOT NULL,
  uploaded_at    TEXT NOT NULL
);

CREATE TABLE audit_entries (
  seq           INTEGER PRIMARY KEY CHECK (seq >= 0),
  created_at    TEXT NOT NULL,
  actor         TEXT NOT NULL,
  event_type    TEXT NOT NULL,
  module_sha256 TEXT,
  details_json  TEXT NOT NULL,
  prev_hash     TEXT NOT NULL UNIQUE CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
  hash          TEXT NOT NULL UNIQUE CHECK (hash ~ '^[0-9a-f]{64}$')
);

-- Append-only: no edits, deletes or truncation of audit entries.
CREATE FUNCTION wasvp_block_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% on % is not allowed (append-only / immutable)', TG_OP, TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER audit_entries_no_change
  BEFORE UPDATE OR DELETE ON audit_entries
  FOR EACH ROW EXECUTE FUNCTION wasvp_block_change();

CREATE TRIGGER audit_entries_no_truncate
  BEFORE TRUNCATE ON audit_entries
  FOR EACH STATEMENT EXECUTE FUNCTION wasvp_block_change();

-- Modules are content-addressed, so a stored row must never be edited.
CREATE TRIGGER modules_no_update
  BEFORE UPDATE ON modules
  FOR EACH ROW EXECUTE FUNCTION wasvp_block_change();

-- Lock out Supabase's public API roles.
ALTER TABLE modules       ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_entries ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL ON modules, audit_entries FROM anon';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL ON modules, audit_entries FROM authenticated';
  END IF;
END;
$$;
