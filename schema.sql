-- Acme Trading — Counterparty Contacts schema
-- Run this against your RDS Aurora PostgreSQL instance with master credentials.

CREATE TABLE IF NOT EXISTS contacts (
  id          SERIAL PRIMARY KEY,
  name        VARCHAR(100) NOT NULL,
  role        VARCHAR(80),
  desk        VARCHAR(80),
  phone       VARCHAR(40)  NOT NULL,
  email       VARCHAR(120),
  notes       TEXT,
  created_at  TIMESTAMPTZ  DEFAULT NOW(),
  updated_at  TIMESTAMPTZ  DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS call_log (
  id            SERIAL PRIMARY KEY,
  contact_id    INTEGER REFERENCES contacts(id) ON DELETE SET NULL,
  contact_name  VARCHAR(100),
  phone         VARCHAR(40),
  caller        VARCHAR(160),  -- Teleport JWT 'sub' claim if available
  called_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Seed data — fictional counterparties on a global trading desk.
INSERT INTO contacts (name, role, desk, phone, email) VALUES
  ('Sarah Chen',       'FX Trader',          'EUR/USD',         '+1-555-201-1001',  'sarah.chen@globalmarkets.com'),
  ('Marcus Webb',      'Equities Trader',    'Tech Sector',     '+44-20-7946-0123', 'marcus.webb@londonsecurities.co.uk'),
  ('Priya Patel',      'Fixed Income',       'US Treasuries',   '+65-6555-2233',    'priya.patel@asiabond.sg'),
  ('James Morrison',   'Commodities',        'Energy & Metals', '+1-212-555-7890',  'james.morrison@nytrading.com'),
  ('Yuki Tanaka',      'Asia Pacific Desk',  'JPY / AUD',       '+81-3-5555-3344',  'yuki.tanaka@tokyobroker.jp'),
  ('Elena Rodriguez',  'EMEA Desk',          'EUR / GBP',       '+49-69-555-4455',  'elena.rodriguez@frankfurtfx.de'),
  ('David Kim',        'Derivatives',        'Equity Options',  '+1-312-555-9988',  'david.kim@chicagoderiv.com'),
  ('Aisha Okonkwo',    'EM Desk',            'CEEMEA',          '+27-11-555-1122',  'aisha.okonkwo@jburgcap.za')
ON CONFLICT DO NOTHING;

-- Application user — used by the trading-contacts webapp (NOT by humans;
-- humans get to RDS via Teleport's database protocol with rds_iam).
-- Replace 'CHANGE_ME' with a strong password before running.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trading_app') THEN
    CREATE ROLE trading_app WITH LOGIN PASSWORD 'CHANGE_ME';
  END IF;
END$$;

GRANT CONNECT ON DATABASE postgres TO trading_app;
GRANT USAGE  ON SCHEMA public TO trading_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON contacts, call_log TO trading_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO trading_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO trading_app;
