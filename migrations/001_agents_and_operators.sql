CREATE TABLE IF NOT EXISTS agents (
  id text PRIMARY KEY,
  api_key_hash text NOT NULL UNIQUE,
  hostname text,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  last_seen timestamptz
);

CREATE TABLE IF NOT EXISTS operators (
  id text PRIMARY KEY,
  token_hash text NOT NULL UNIQUE,
  scopes text[] NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
