-- ============================================================
-- HYR INJECTOR v2.0 — DATABASE SCHEMA
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
  id                BIGSERIAL PRIMARY KEY,
  username          VARCHAR(64) UNIQUE,
  password_hash     VARCHAR(255),
  access_key_hash   VARCHAR(64) UNIQUE,
  role              VARCHAR(16) DEFAULT 'FREE',
  is_active         BOOLEAN DEFAULT TRUE,
  created_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_devices (
  user_id       BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  device_id     VARCHAR(128) NOT NULL,
  device_label  VARCHAR(255),
  first_ip      INET,
  last_ip       INET,
  bound_at      TIMESTAMPTZ DEFAULT NOW(),
  last_seen_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash    VARCHAR(255) PRIMARY KEY,
  user_id       BIGINT REFERENCES users(id) ON DELETE CASCADE,
  device_id     VARCHAR(128) NOT NULL,
  ip_address    INET,
  user_agent    TEXT,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  expires_at    TIMESTAMPTZ NOT NULL,
  revoked       BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS access_keys (
  id            BIGSERIAL PRIMARY KEY,
  key_hash      VARCHAR(64) UNIQUE NOT NULL,
  key_label     VARCHAR(64) NOT NULL,
  role          VARCHAR(16) DEFAULT 'VIP',
  status        VARCHAR(16) DEFAULT 'ACTIVE',
  used_by       BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  expires_at    TIMESTAMPTZ,
  used_at       TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS config (
  key           VARCHAR(64) PRIMARY KEY,
  value         TEXT NOT NULL,
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO config (key, value) VALUES ('maintenance', 'false')
ON CONFLICT (key) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_keys_status      ON access_keys(status);
