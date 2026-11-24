
CREATE TABLE IF NOT EXISTS nsg_users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  profile JSONB NOT NULL DEFAULT '{}'::jsonb,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nsg_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES nsg_users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS nsg_sessions_user_idx ON nsg_sessions(user_id);
CREATE INDEX IF NOT EXISTS nsg_sessions_expiry_idx ON nsg_sessions(expires_at);

CREATE TABLE IF NOT EXISTS nsg_records (
  workspace TEXT NOT NULL DEFAULT 'nsg-pr-branding-main',
  module TEXT NOT NULL,
  record_id TEXT NOT NULL,
  payload JSONB NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT REFERENCES nsg_users(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (workspace, module, record_id)
);
CREATE INDEX IF NOT EXISTS nsg_records_module_idx ON nsg_records(workspace, module);

CREATE TABLE IF NOT EXISTS nsg_meta (
  workspace TEXT NOT NULL DEFAULT 'nsg-pr-branding-main',
  meta_key TEXT NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_by TEXT REFERENCES nsg_users(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (workspace, meta_key)
);

CREATE TABLE IF NOT EXISTS nsg_audit (
  id TEXT PRIMARY KEY,
  workspace TEXT NOT NULL DEFAULT 'nsg-pr-branding-main',
  actor_id TEXT REFERENCES nsg_users(id),
  actor_email TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS nsg_audit_created_idx ON nsg_audit(workspace, created_at DESC);
