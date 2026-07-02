import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import cookieParser from 'cookie-parser';
import express from 'express';
import jwt from 'jsonwebtoken';
import webpush from 'web-push';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ACCESS_TOKEN_TTL = '15m';
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const IS_PROD = process.env.NODE_ENV === 'production';

// ---------------------------------------------------------------------------
// VAPID keys: from env, or generated once and persisted next to the server
// ---------------------------------------------------------------------------
const vapidFile = path.join(__dirname, '.vapid.json');
let vapidKeys;
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  vapidKeys = {
    publicKey: process.env.VAPID_PUBLIC_KEY,
    privateKey: process.env.VAPID_PRIVATE_KEY,
  };
} else if (fs.existsSync(vapidFile)) {
  vapidKeys = JSON.parse(fs.readFileSync(vapidFile, 'utf8'));
} else {
  vapidKeys = webpush.generateVAPIDKeys();
  fs.writeFileSync(vapidFile, JSON.stringify(vapidKeys, null, 2));
}
webpush.setVapidDetails(
  process.env.VAPID_SUBJECT || 'mailto:admin@example.com',
  vapidKeys.publicKey,
  vapidKeys.privateKey,
);

// ---------------------------------------------------------------------------
// In-memory stores (swap for a database in production)
// ---------------------------------------------------------------------------
const users = new Map(); // id -> { id, email, passwordHash, salt }
const sessions = new Map(); // sessionId -> session record
const refreshIndex = new Map(); // sha256(refreshToken) -> { sessionId, used }
const pushSubscriptions = new Map(); // endpoint -> { userId, subscription }

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function createUser(email, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const user = {
    id: `user_${crypto.randomUUID()}`,
    email,
    salt,
    passwordHash: hashPassword(password, salt),
  };
  users.set(user.id, user);
  return user;
}

// Demo account so the app is usable out of the box
const demoUser = createUser('demo@example.com', 'demo1234');
console.log(`Demo login: ${demoUser.email} / demo1234`);

// ---------------------------------------------------------------------------
// Token + session helpers
// ---------------------------------------------------------------------------
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

function issueAccessToken(user, sessionId) {
  return jwt.sign({ sub: user.id, email: user.email, sid: sessionId }, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_TTL,
  });
}

function issueRefreshToken(sessionId) {
  const token = crypto.randomBytes(48).toString('base64url');
  refreshIndex.set(sha256(token), { sessionId, used: false });
  return token;
}

function createSession(user, req) {
  const session = {
    id: `sess_${crypto.randomUUID()}`,
    userId: user.id,
    device: req.headers['user-agent'] || 'unknown',
    ip: req.ip,
    createdAt: new Date().toISOString(),
    lastActive: new Date().toISOString(),
    expiresAt: Date.now() + REFRESH_TOKEN_TTL_MS,
    revoked: false,
  };
  sessions.set(session.id, session);
  return session;
}

function revokeSession(sessionId) {
  const session = sessions.get(sessionId);
  if (session) session.revoked = true;
}

function sessionIsLive(session) {
  return session && !session.revoked && session.expiresAt > Date.now();
}

function setRefreshCookie(res, token) {
  res.cookie('refresh_token', token, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'strict',
    path: '/auth',
    maxAge: REFRESH_TOKEN_TTL_MS,
  });
}

function tokenResponse(res, user, session) {
  session.lastActive = new Date().toISOString();
  setRefreshCookie(res, issueRefreshToken(session.id));
  res.json({
    access_token: issueAccessToken(user, session.id),
    token_type: 'Bearer',
    expires_in: 900,
  });
}

// ---------------------------------------------------------------------------
// App + middleware
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing_token' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const session = sessions.get(payload.sid);
    if (!sessionIsLive(session)) {
      return res.status(401).json({ error: 'session_revoked' });
    }
    session.lastActive = new Date().toISOString();
    req.user = users.get(payload.sub);
    req.session = session;
    next();
  } catch (err) {
    const error = err.name === 'TokenExpiredError' ? 'token_expired' : 'invalid_token';
    res.status(401).json({ error });
  }
}

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------
app.post('/auth/register', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password || password.length < 8) {
    return res.status(400).json({ error: 'invalid_credentials', message: 'Email and a password of 8+ characters are required.' });
  }
  if ([...users.values()].some((u) => u.email === email)) {
    return res.status(409).json({ error: 'email_taken' });
  }
  const user = createUser(email, password);
  tokenResponse(res.status(201), user, createSession(user, req));
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = [...users.values()].find((u) => u.email === email);
  const valid =
    user &&
    crypto.timingSafeEqual(
      Buffer.from(user.passwordHash, 'hex'),
      Buffer.from(hashPassword(password || '', user.salt), 'hex'),
    );
  if (!valid) return res.status(401).json({ error: 'invalid_credentials' });

  tokenResponse(res, user, createSession(user, req));
});

app.post('/auth/refresh', (req, res) => {
  const token = req.cookies.refresh_token;
  if (!token) return res.status(401).json({ error: 'missing_refresh_token' });

  const record = refreshIndex.get(sha256(token));
  if (!record) return res.status(401).json({ error: 'invalid_refresh_token' });

  // Rotation with reuse detection: a token presented twice means it may have
  // been stolen, so the whole session is revoked.
  if (record.used) {
    revokeSession(record.sessionId);
    return res.status(401).json({ error: 'refresh_token_reused', message: 'Session revoked for safety. Log in again.' });
  }

  const session = sessions.get(record.sessionId);
  if (!sessionIsLive(session)) return res.status(401).json({ error: 'session_expired' });

  record.used = true;
  tokenResponse(res, users.get(session.userId), session);
});

app.post('/auth/logout', requireAuth, (req, res) => {
  revokeSession(req.session.id);
  res.clearCookie('refresh_token', { path: '/auth' });
  res.json({ ok: true });
});

app.post('/auth/logout-all', requireAuth, (req, res) => {
  for (const session of sessions.values()) {
    if (session.userId === req.user.id) session.revoked = true;
  }
  res.clearCookie('refresh_token', { path: '/auth' });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Session management routes
// ---------------------------------------------------------------------------
app.get('/v1/sessions', requireAuth, (req, res) => {
  const list = [...sessions.values()]
    .filter((s) => s.userId === req.user.id && sessionIsLive(s))
    .map((s) => ({
      id: s.id,
      device: s.device,
      ip: s.ip,
      created_at: s.createdAt,
      last_active: s.lastActive,
      current: s.id === req.session.id,
    }));
  res.json({ sessions: list });
});

app.delete('/v1/sessions/:id', requireAuth, (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session || session.userId !== req.user.id) {
    return res.status(404).json({ error: 'session_not_found' });
  }
  revokeSession(session.id);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Push notification routes
// ---------------------------------------------------------------------------
app.get('/api/push/vapid-public-key', (req, res) => {
  res.json({ publicKey: vapidKeys.publicKey });
});

app.post('/api/push/subscribe', requireAuth, (req, res) => {
  const subscription = req.body;
  if (!subscription?.endpoint || !subscription?.keys) {
    return res.status(400).json({ error: 'invalid_subscription' });
  }
  pushSubscriptions.set(subscription.endpoint, { userId: req.user.id, subscription });
  res.status(201).json({ ok: true });
});

app.post('/api/push/unsubscribe', requireAuth, (req, res) => {
  const { endpoint } = req.body || {};
  if (endpoint) pushSubscriptions.delete(endpoint);
  res.json({ ok: true });
});

app.post('/api/push/send', requireAuth, async (req, res) => {
  const { title = 'Notification', body = '', url = '/' } = req.body || {};
  const mine = [...pushSubscriptions.values()].filter((s) => s.userId === req.user.id);

  const results = await Promise.allSettled(
    mine.map(({ subscription }) =>
      webpush.sendNotification(subscription, JSON.stringify({ title, body, url })).catch((err) => {
        // 404/410 mean the subscription is dead — drop it
        if (err.statusCode === 404 || err.statusCode === 410) {
          pushSubscriptions.delete(subscription.endpoint);
        }
        throw err;
      }),
    ),
  );

  res.json({
    sent: results.filter((r) => r.status === 'fulfilled').length,
    failed: results.filter((r) => r.status === 'rejected').length,
  });
});

app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
