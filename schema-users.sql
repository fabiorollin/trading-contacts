-- Wave 1: add users table for local username/password auth.
-- Run this AFTER the original schema.sql. The app will seed 5 users on startup.

CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  username      VARCHAR(40) UNIQUE NOT NULL,
  display_name  VARCHAR(100),
  password_hash VARCHAR(120) NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Allow the app user to read/insert.
GRANT SELECT, INSERT ON users TO trading_app;
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO trading_app;
