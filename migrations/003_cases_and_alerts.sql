CREATE TABLE IF NOT EXISTS cases (
  id bigserial PRIMARY KEY,
  case_key text NOT NULL,
  source_ip inet,
  level text NOT NULL,
  status text NOT NULL DEFAULT 'open',
  first_activity_at timestamptz NOT NULL,
  last_activity_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  ai_report jsonb,
  ai_investigated_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS cases_one_open_per_key ON cases (case_key) WHERE status = 'open';

CREATE TABLE IF NOT EXISTS alerts (
  id bigserial PRIMARY KEY,
  alert_key text UNIQUE NOT NULL,
  rule_id text NOT NULL,
  title text,
  level text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  window_start timestamptz,
  window_end timestamptz,
  group_key jsonb,
  event_count int,
  event_uids text[],
  status text NOT NULL DEFAULT 'new',
  case_id bigint REFERENCES cases(id)
);

CREATE INDEX IF NOT EXISTS alerts_case ON alerts (case_id);
