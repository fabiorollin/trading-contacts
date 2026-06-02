// Acme Trading — Counterparty Contacts API (v2)
// Auth model:
//   1. If the request carries a `Teleport-Jwt-Assertion` header (i.e. it came
//      through Teleport's app proxy), decode it and treat the user as logged in.
//   2. Otherwise, check the `session` cookie (signed JWT). If valid, treat as logged in.
//   3. Otherwise, the only allowed routes are GET / (login page) and POST /api/auth/login.
//
// Five demo users are seeded on first startup if the users table is empty.

const express      = require('express');
const cookieParser = require('cookie-parser');
const rateLimit    = require('express-rate-limit');
const { Pool }     = require('pg');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const path         = require('path');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET env var is required');
  process.exit(1);
}

const app = express();
// Trust the ALB / Teleport proxy so req.ip reflects the real client IP via X-Forwarded-For.
app.set('trust proxy', 1);
app.use(express.json());
app.use(cookieParser());

// ── Brute-force protection: 5 login attempts per IP per 10 minutes.
//    Anything past that gets a 429 (and is also written to login_attempts as 'rate-limited').
const loginLimiter = rateLimit({
  windowMs:        10 * 60 * 1000,
  limit:           5,
  standardHeaders: 'draft-7',
  legacyHeaders:   false,
  keyGenerator:    (req) => `${req.ip}:${(req.body && req.body.username) || ''}`,
  handler: async (req, res) => {
    await logLoginAttempt(req, false, 'rate-limited').catch(() => {});
    res.status(429).json({ error: 'too many login attempts; try again in a few minutes' });
  },
});

// Helper: log every login attempt (success or failure) for audit.
async function logLoginAttempt(req, success, failureCode = null) {
  try {
    const username  = (req.body && req.body.username) || null;
    const ip        = req.ip || null;
    const userAgent = req.headers['user-agent'] || null;
    await pool.query(
      `INSERT INTO login_attempts (username, ip_address, user_agent, success, failure_code)
       VALUES ($1, $2, $3, $4, $5)`,
      [username, ip, userAgent, success, failureCode]
    );
  } catch (e) {
    console.error('login_attempts insert failed:', e.message);
  }
}

// SSL is on by default (for Aurora / RDS), but can be disabled with
// DB_SSL=false (e.g. for in-cluster Postgres that wasn't configured with TLS).
const useSsl = (process.env.DB_SSL || 'true').toLowerCase() !== 'false';
const pool = new Pool({
  host:     process.env.DB_HOST,
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'postgres',
  user:     process.env.DB_USER || 'trading_app',
  password: process.env.DB_PASSWORD,
  ssl:      useSsl ? { rejectUnauthorized: false } : false,
  max:      5,
});

// ── Seed default users on startup if empty
const SEED_USERS = [
  { username: 'sarah',  display: 'Sarah Chen — FX Trader',         password: 'trading2026' },
  { username: 'marcus', display: 'Marcus Webb — Equities Trader',  password: 'trading2026' },
  { username: 'priya',  display: 'Priya Patel — Fixed Income',     password: 'trading2026' },
  { username: 'james',  display: 'James Morrison — Commodities',   password: 'trading2026' },
  { username: 'admin',  display: 'Acme Admin',                     password: 'admin2026' },
];

async function ensureUsers() {
  try {
    const r = await pool.query('SELECT COUNT(*) FROM users');
    if (parseInt(r.rows[0].count, 10) > 0) {
      console.log(`users table has ${r.rows[0].count} rows — skipping seed`);
      return;
    }
    for (const s of SEED_USERS) {
      const hash = await bcrypt.hash(s.password, 10);
      await pool.query(
        `INSERT INTO users (username, display_name, password_hash)
         VALUES ($1, $2, $3)
         ON CONFLICT (username) DO NOTHING`,
        [s.username, s.display, hash]
      );
    }
    console.log(`Seeded ${SEED_USERS.length} users`);
  } catch (e) {
    console.error('User seeding failed:', e.message);
  }
}

// ── Auth middleware
//
// Sets req.user to {username, display, source} where source is 'teleport' | 'local'.
// If neither auth method is present, leaves req.user unset.
async function auth(req, res, next) {
  // (1) Teleport JWT injected by app proxy
  const tjwt = req.headers['teleport-jwt-assertion'];
  if (tjwt) {
    try {
      const payload = JSON.parse(Buffer.from(tjwt.split('.')[1], 'base64').toString());
      req.user = {
        username: payload.username || payload.sub || 'teleport-user',
        display:  payload.username || payload.sub,
        source:   'teleport',
      };
      return next();
    } catch (e) {
      // fall through to cookie
    }
  }

  // (2) session cookie — covers both registered users (source: 'local') and
  // demo-entry visitors who provided just an email (source: 'demo').
  const cookie = req.cookies && req.cookies.session;
  if (cookie) {
    try {
      const decoded = jwt.verify(cookie, JWT_SECRET);
      req.user = {
        username: decoded.username,
        display:  decoded.display,
        source:   decoded.role === 'demo' ? 'demo' : 'local',
      };
      return next();
    } catch (e) {
      // bad/expired cookie — drop it
      res.clearCookie('session');
    }
  }

  next();
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'authentication required' });
  next();
}

app.use(auth);

// ── Health (no auth)
app.get('/healthz', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch (e) {
    res.status(503).json({ status: 'db down', error: e.message });
  }
});

// ── Auth endpoints
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    await logLoginAttempt(req, false, 'missing-fields');
    return res.status(400).json({ error: 'username and password required' });
  }
  try {
    const r = await pool.query('SELECT id, username, display_name, password_hash FROM users WHERE username = $1', [username]);
    if (r.rows.length === 0) {
      await logLoginAttempt(req, false, 'unknown-user');
      return res.status(401).json({ error: 'invalid credentials' });
    }
    const u = r.rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) {
      await logLoginAttempt(req, false, 'bad-password');
      return res.status(401).json({ error: 'invalid credentials' });
    }

    const token = jwt.sign(
      { username: u.username, display: u.display_name },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.cookie('session', token, {
      httpOnly: true,
      secure:   true,         // requires https; Teleport / ALB both terminate TLS
      sameSite: 'lax',
      maxAge:   8 * 60 * 60 * 1000,
    });
    await logLoginAttempt(req, true);
    res.json({ username: u.username, display: u.display_name });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ── Demo entry: any visitor enters their email and gets an 8h session.
//
// Lower-trust than the password-backed login above: we don't verify the email,
// we don't check it against the users table. We just sign a JWT with role='demo'
// and the supplied email so it shows up in the audit log.
//
// The contacts data is mock; visitors can edit/delete freely. A weekly CronJob
// re-seeds the table.
app.post('/api/auth/demo', async (req, res) => {
  const raw = (req.body && req.body.email) || '';
  const email = String(raw).trim().toLowerCase();
  // Light validation: must look vaguely like an email or be at least 3 chars.
  if (!email || email.length < 3 || email.length > 200) {
    return res.status(400).json({ error: 'Please enter your email or name to continue' });
  }
  try {
    const token = jwt.sign(
      { username: email, display: email, role: 'demo' },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.cookie('session', token, {
      httpOnly: true,
      secure:   true,
      sameSite: 'lax',
      maxAge:   8 * 60 * 60 * 1000,
    });
    // Audit-log this as a 'demo' login attempt — surfaces in the audit panel.
    await pool.query(
      `INSERT INTO login_attempts (username, ip_address, user_agent, success, failure_code)
       VALUES ($1, $2, $3, $4, $5)`,
      [email, req.ip || null, req.headers['user-agent'] || null, true, 'demo']
    );
    // Optional Slack ping — fire-and-forget, never blocks the response.
    if (process.env.SLACK_WEBHOOK_URL) {
      const ref = req.headers.referer ? new URL(req.headers.referer).hostname : 'direct';
      const ua  = req.headers['user-agent'] || '';
      const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox/.test(ua) ? 'Firefox' : /Chrome/.test(ua) ? 'Chrome' : /Safari/.test(ua) ? 'Safari' : 'Unknown';
      const msg = `🟣 *trading-contacts demo entered* by \`${email}\`\n   ${browser} · ref: ${ref} · IP: ${req.ip || 'unknown'}`;
      fetch(process.env.SLACK_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: msg }),
      }).catch(() => {});
    }
    res.json({ username: email, display: email, role: 'demo' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'not authenticated' });
  res.json({ username: req.user.username, display: req.user.display, source: req.user.source });
});

// ── Contacts CRUD (auth required)
app.get('/api/contacts', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM contacts ORDER BY name');
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/contacts/:id', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM contacts WHERE id = $1', [req.params.id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'not found' });
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/contacts', requireAuth, async (req, res) => {
  const { name, role, desk, phone, email, notes } = req.body || {};
  if (!name || !phone) return res.status(400).json({ error: 'name and phone required' });
  try {
    const r = await pool.query(
      `INSERT INTO contacts (name, role, desk, phone, email, notes)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [name, role || null, desk || null, phone, email || null, notes || null]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/contacts/:id', requireAuth, async (req, res) => {
  const { name, role, desk, phone, email, notes } = req.body || {};
  try {
    const r = await pool.query(
      `UPDATE contacts SET
         name       = COALESCE($1, name),
         role       = COALESCE($2, role),
         desk       = COALESCE($3, desk),
         phone      = COALESCE($4, phone),
         email      = COALESCE($5, email),
         notes      = COALESCE($6, notes),
         updated_at = NOW()
       WHERE id = $7 RETURNING *`,
      [name, role, desk, phone, email, notes, req.params.id]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'not found' });
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/contacts/:id', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM contacts WHERE id = $1 RETURNING id', [req.params.id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'not found' });
    res.json({ deleted: r.rows[0].id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/contacts/:id/log-call', requireAuth, async (req, res) => {
  try {
    const c = await pool.query('SELECT name, phone FROM contacts WHERE id = $1', [req.params.id]);
    if (c.rows.length === 0) return res.status(404).json({ error: 'not found' });
    const r = await pool.query(
      `INSERT INTO call_log (contact_id, contact_name, phone, caller)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [req.params.id, c.rows[0].name, c.rows[0].phone, `${req.user.username} (${req.user.source})`]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/calls', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM call_log ORDER BY called_at DESC LIMIT 50');
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Login audit log (admin can see the last 100 attempts; non-admin sees 401)
app.get('/api/audit/logins', requireAuth, async (req, res) => {
  if (req.user.username !== 'admin') {
    return res.status(403).json({ error: 'admin only' });
  }
  try {
    const r = await pool.query(
      'SELECT id, username, ip_address, success, failure_code, attempted_at FROM login_attempts ORDER BY attempted_at DESC LIMIT 100'
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Static frontend (login page is also static; auth happens via fetch)
app.use(express.static(path.join(__dirname, 'public')));

// ──────────────────────────────────────────────────────────────────────────
// Realtime: presence + 1:1 direct messages over Socket.IO
//
// Design notes:
//   - Auth: read the `session` cookie from the websocket handshake and verify
//     the JWT. We support both 'local' (registered) and 'demo' users.
//   - Presence: in-memory Map. Keyed by socket id, but UI dedupes by username
//     so multiple tabs from the same user collapse into one entry.
//   - DMs: ephemeral, not persisted. If both ends are connected we deliver;
//     otherwise the message is dropped (caller sees "user went offline").
//   - Single-pod: this state lives in process memory. If you scale beyond
//     one replica, swap in Redis pub/sub. For now we have replicas: 1.
// ──────────────────────────────────────────────────────────────────────────

const http   = require('http');
const cookie = require('cookie');
const { Server: SocketIOServer } = require('socket.io');

const httpServer = http.createServer(app);
const io = new SocketIOServer(httpServer, {
  // Same-origin only — no CORS needed since we serve the page from here.
  cors: { origin: false },
  // Tune for ALB long-poll fallback if WebSocket upgrade is blocked anywhere.
  transports: ['websocket', 'polling'],
});

// Map<socketId, { username, display, source, connectedAt }>
const presence = new Map();

function presenceList() {
  // Dedupe by username so multiple tabs from one user become one entry.
  const byUser = new Map();
  for (const [, info] of presence) {
    const existing = byUser.get(info.username);
    if (!existing || info.connectedAt < existing.connectedAt) {
      byUser.set(info.username, info);
    }
  }
  return Array.from(byUser.values()).sort((a, b) => a.connectedAt - b.connectedAt);
}

function broadcastPresence() {
  io.emit('presence:list', presenceList());
}

// Auth middleware — runs on every websocket handshake.
io.use((socket, next) => {
  const raw = socket.handshake.headers.cookie || '';
  const parsed = cookie.parse(raw);
  const token = parsed.session;
  if (!token) return next(new Error('unauthenticated'));
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.data.user = {
      username: decoded.username,
      display:  decoded.display,
      source:   decoded.role === 'demo' ? 'demo' : 'local',
    };
    next();
  } catch {
    next(new Error('bad token'));
  }
});

io.on('connection', (socket) => {
  const u = socket.data.user;
  presence.set(socket.id, { ...u, connectedAt: Date.now() });
  // Send the current presence list to the just-connected user, then announce.
  socket.emit('presence:list', presenceList());
  broadcastPresence();

  // Direct message: { to: <username>, text: <string> }
  socket.on('dm:send', (msg) => {
    if (!msg || typeof msg.to !== 'string' || typeof msg.text !== 'string') return;
    const text = msg.text.trim().slice(0, 1000);
    if (!text) return;
    // Find all sockets currently connected as the target user (covers multiple tabs).
    const targets = [...presence.entries()]
      .filter(([, info]) => info.username === msg.to)
      .map(([sid]) => sid);
    const payload = {
      from:       u.username,
      fromDisplay:u.display,
      text,
      at:         Date.now(),
    };
    if (targets.length === 0) {
      // Echo back to sender so their UI can show "user is offline"
      socket.emit('dm:undelivered', { to: msg.to, text, reason: 'offline' });
      return;
    }
    targets.forEach((sid) => io.to(sid).emit('dm:received', payload));
    // Echo back to sender so their UI can show their own message in the thread
    socket.emit('dm:received', { ...payload, to: msg.to, self: true });
  });

  // Lightweight typing indicator
  socket.on('dm:typing', ({ to, on }) => {
    const targets = [...presence.entries()]
      .filter(([, info]) => info.username === to)
      .map(([sid]) => sid);
    targets.forEach((sid) => io.to(sid).emit('dm:typing', { from: u.username, on: !!on }));
  });

  socket.on('disconnect', () => {
    presence.delete(socket.id);
    broadcastPresence();
  });
});

const PORT = process.env.PORT || 8080;
ensureUsers().then(() => {
  httpServer.listen(PORT, () => console.log(`trading-contacts v2 listening on :${PORT} (with realtime presence)`));
});
