CREATE TABLE IF NOT EXISTS events_raw (
  event_uid text PRIMARY KEY,
  agent_id text NOT NULL REFERENCES agents(id),
  batch_id text,
  log_type text NOT NULL,
  message text NOT NULL,
  message_truncated boolean NOT NULL DEFAULT false,
  file_meta jsonb NOT NULL,
  agent_meta jsonb NOT NULL,
  collected_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION events_raw_no_update() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'events_raw là append-only';
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    WHERE t.tgname = 'events_raw_immutable'
      AND c.relname = 'events_raw'
      AND NOT t.tgisinternal
  ) THEN
    CREATE TRIGGER events_raw_immutable
      BEFORE UPDATE ON events_raw
      FOR EACH ROW EXECUTE FUNCTION events_raw_no_update();
  END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS events (
  event_uid text PRIMARY KEY REFERENCES events_raw(event_uid),
  ts timestamptz NOT NULL,
  ingested_at timestamptz NOT NULL DEFAULT now(),
  agent_id text NOT NULL,
  host_name text,
  dataset text,
  category text[],
  action text,
  outcome text,
  source_ip inet,
  user_name text,
  process_name text,
  parse_status text NOT NULL DEFAULT 'ok',
  doc jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS events_ts        ON events (ts);
CREATE INDEX IF NOT EXISTS events_action_ts ON events (action, ts);
CREATE INDEX IF NOT EXISTS events_srcip_ts  ON events (source_ip, ts);
CREATE INDEX IF NOT EXISTS events_user_ts   ON events (user_name, ts);
CREATE INDEX IF NOT EXISTS events_bad_parse ON events (parse_status) WHERE parse_status <> 'ok';
