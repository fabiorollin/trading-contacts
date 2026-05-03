-- Login-attempt audit log + brute-force protection.
-- Run AFTER schema-users.sql.

CREATE TABLE IF NOT EXISTS login_attempts (
  id           SERIAL PRIMARY KEY,
  username     VARCHAR(80),
  ip_address   VARCHAR(45),
  user_agent   TEXT,
  success      BOOLEAN NOT NULL,
  failure_code VARCHAR(40),    -- 'bad-credentials', 'rate-limited', 'locked', etc.
  attempted_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_username_time
  ON login_attempts (username, attempted_at DESC);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
  ON login_attempts (ip_address, attempted_at DESC);

GRANT SELECT, INSERT ON login_attempts TO trading_app;
GRANT USAGE, SELECT ON SEQUENCE login_attempts_id_seq TO trading_app;
