import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createClient } from '@supabase/supabase-js';
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
// Supabase client (service-role key: server-side only, bypasses RLS)
// ---------------------------------------------------------------------------
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error(
    'Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY.\n' +
    'Copy .env.example to .env, fill in your Supabase project credentials,\n' +
    'and apply db/schema.sql in the Supabase SQL editor first.',
  );
  process.exit(1);
}
const db = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

// Throws on any query error so route handlers can rely on try/catch → 500
function unwrap({ data, error }) {
  if (error) throw new Error(`supabase: ${error.message}`);
  return data;
}

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
// Password + token helpers
// ---------------------------------------------------------------------------
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function issueAccessToken(user, sessionId) {
  return jwt.sign({ sub: user.id, email: user.email, sid: sessionId }, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_TTL,
  });
}

async function createUser(email, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const { data, error } = await db
    .from('users')
    .insert({ email, salt, password_hash: hashPassword(password, salt) })
    .select()
    .single();
  if (error?.code === '23505') return null; // unique_violation: email taken
  if (error) throw new Error(`supabase: ${error.message}`);
  return data;
}

async function getUserByEmail(email) {
  return unwrap(await db.from('users').select().eq('email', email).maybeSingle());
}

async function createSession(user, req) {
  return unwrap(
    await db
      .from('sessions')
      .insert({
        user_id: user.id,
        device: req.headers['user-agent'] || 'unknown',
        ip: req.ip,
        expires_at: new Date(Date.now() + REFRESH_TOKEN_TTL_MS).toISOString(),
      })
      .select()
      .single(),
  );
}

async function getSession(sessionId) {
  return unwrap(await db.from('sessions').select().eq('id', sessionId).maybeSingle());
}

async function revokeSession(sessionId) {
  unwrap(await db.from('sessions').update({ revoked: true }).eq('id', sessionId));
}

function sessionIsLive(session) {
  return session && !session.revoked && new Date(session.expires_at) > new Date();
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

async function tokenResponse(res, user, session) {
  const refreshToken = crypto.randomBytes(48).toString('base64url');
  unwrap(
    await db
      .from('refresh_tokens')
      .insert({ token_hash: sha256(refreshToken), session_id: session.id }),
  );
  unwrap(
    await db
      .from('sessions')
      .update({ last_active: new Date().toISOString() })
      .eq('id', session.id),
  );
  setRefreshCookie(res, refreshToken);
  res.json({
    access_token: issueAccessToken(user, session.id),
    token_type: 'Bearer',
    expires_in: 900,
  });
}

// ---------------------------------------------------------------------------
// Demo account so the app is usable out of the box
// ---------------------------------------------------------------------------
async function ensureDemoUser() {
  if (process.env.DISABLE_DEMO_USER) return;
  const existing = await getUserByEmail('demo@example.com');
  if (!existing) await createUser('demo@example.com', 'demo1234');
  console.log('Demo login: demo@example.com / demo1234');
}

// ---------------------------------------------------------------------------
// App + middleware
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Express 4 does not catch async errors — wrap every async handler
const h = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const requireAuth = h(async (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing_token' });

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    const error = err.name === 'TokenExpiredError' ? 'token_expired' : 'invalid_token';
    return res.status(401).json({ error });
  }

  const session = await getSession(payload.sid);
  if (!sessionIsLive(session)) {
    return res.status(401).json({ error: 'session_revoked' });
  }
  unwrap(
    await db
      .from('sessions')
      .update({ last_active: new Date().toISOString() })
      .eq('id', session.id),
  );
  req.user = { id: payload.sub, email: payload.email };
  req.session = session;
  next();
});

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------
app.post('/auth/register', h(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password || password.length < 8) {
    return res.status(400).json({ error: 'invalid_credentials', message: 'Email and a password of 8+ characters are required.' });
  }
  const user = await createUser(email, password);
  if (!user) return res.status(409).json({ error: 'email_taken' });
  await tokenResponse(res.status(201), user, await createSession(user, req));
}));

app.post('/auth/login', h(async (req, res) => {
  const { email, password } = req.body || {};
  const user = email ? await getUserByEmail(email) : null;
  const valid =
    user &&
    crypto.timingSafeEqual(
      Buffer.from(user.password_hash, 'hex'),
      Buffer.from(hashPassword(password || '', user.salt), 'hex'),
    );
  if (!valid) return res.status(401).json({ error: 'invalid_credentials' });

  await tokenResponse(res, user, await createSession(user, req));
}));

app.post('/auth/refresh', h(async (req, res) => {
  const token = req.cookies.refresh_token;
  if (!token) return res.status(401).json({ error: 'missing_refresh_token' });
  const tokenHash = sha256(token);

  // Atomically claim the token: the conditional update means two concurrent
  // requests with the same token can never both succeed.
  const claimed = unwrap(
    await db
      .from('refresh_tokens')
      .update({ used: true })
      .eq('token_hash', tokenHash)
      .eq('used', false)
      .select()
      .maybeSingle(),
  );

  if (!claimed) {
    const existing = unwrap(
      await db.from('refresh_tokens').select().eq('token_hash', tokenHash).maybeSingle(),
    );
    // A known-but-used token means it may have been stolen — revoke the
    // whole session (and with it every descendant refresh token).
    if (existing) {
      await revokeSession(existing.session_id);
      return res.status(401).json({ error: 'refresh_token_reused', message: 'Session revoked for safety. Log in again.' });
    }
    return res.status(401).json({ error: 'invalid_refresh_token' });
  }

  const session = await getSession(claimed.session_id);
  if (!sessionIsLive(session)) return res.status(401).json({ error: 'session_expired' });

  const user = unwrap(await db.from('users').select().eq('id', session.user_id).single());
  await tokenResponse(res, user, session);
}));

app.post('/auth/logout', requireAuth, h(async (req, res) => {
  await revokeSession(req.session.id);
  res.clearCookie('refresh_token', { path: '/auth' });
  res.json({ ok: true });
}));

app.post('/auth/logout-all', requireAuth, h(async (req, res) => {
  unwrap(await db.from('sessions').update({ revoked: true }).eq('user_id', req.user.id));
  res.clearCookie('refresh_token', { path: '/auth' });
  res.json({ ok: true });
}));

// ---------------------------------------------------------------------------
// Session management routes
// ---------------------------------------------------------------------------
app.get('/v1/sessions', requireAuth, h(async (req, res) => {
  const rows = unwrap(
    await db
      .from('sessions')
      .select('id, device, ip, created_at, last_active')
      .eq('user_id', req.user.id)
      .eq('revoked', false)
      .gt('expires_at', new Date().toISOString())
      .order('last_active', { ascending: false }),
  );
  res.json({
    sessions: rows.map((s) => ({ ...s, current: s.id === req.session.id })),
  });
}));

app.delete('/v1/sessions/:id', requireAuth, h(async (req, res) => {
  const updated = unwrap(
    await db
      .from('sessions')
      .update({ revoked: true })
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .select()
      .maybeSingle(),
  );
  if (!updated) return res.status(404).json({ error: 'session_not_found' });
  res.json({ ok: true });
}));

// ---------------------------------------------------------------------------
// Push notification routes
// ---------------------------------------------------------------------------
app.get('/api/push/vapid-public-key', (req, res) => {
  res.json({ publicKey: vapidKeys.publicKey });
});

app.post('/api/push/subscribe', requireAuth, h(async (req, res) => {
  const subscription = req.body;
  if (!subscription?.endpoint || !subscription?.keys) {
    return res.status(400).json({ error: 'invalid_subscription' });
  }
  unwrap(
    await db
      .from('push_subscriptions')
      .upsert(
        { endpoint: subscription.endpoint, user_id: req.user.id, subscription },
        { onConflict: 'endpoint' },
      ),
  );
  res.status(201).json({ ok: true });
}));

app.post('/api/push/unsubscribe', requireAuth, h(async (req, res) => {
  const { endpoint } = req.body || {};
  if (endpoint) {
    unwrap(
      await db
        .from('push_subscriptions')
        .delete()
        .eq('endpoint', endpoint)
        .eq('user_id', req.user.id),
    );
  }
  res.json({ ok: true });
}));

async function sendPushToUser(userId, payload) {
  const rows = unwrap(
    await db.from('push_subscriptions').select('subscription').eq('user_id', userId),
  );
  const results = await Promise.allSettled(
    rows.map(({ subscription }) =>
      webpush.sendNotification(subscription, JSON.stringify(payload)).catch(async (err) => {
        // 404/410 mean the subscription is dead — drop it
        if (err.statusCode === 404 || err.statusCode === 410) {
          await db.from('push_subscriptions').delete().eq('endpoint', subscription.endpoint);
        }
        throw err;
      }),
    ),
  );
  return {
    sent: results.filter((r) => r.status === 'fulfilled').length,
    failed: results.filter((r) => r.status === 'rejected').length,
  };
}

app.post('/api/push/send', requireAuth, h(async (req, res) => {
  const { title = 'Notification', body = '', url = '/' } = req.body || {};
  res.json(await sendPushToUser(req.user.id, { title, body, url }));
}));

// ---------------------------------------------------------------------------
// Notification settings (default: every reminder fires at 07:00 user-local)
// ---------------------------------------------------------------------------
const DEFAULT_SETTINGS = { notify_time: '07:00', tz_offset_minutes: 0 };
const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;

async function getSettings(userId) {
  const row = unwrap(
    await db.from('user_settings').select('notify_time, tz_offset_minutes').eq('user_id', userId).maybeSingle(),
  );
  return row ?? { ...DEFAULT_SETTINGS };
}

app.get('/v1/settings', requireAuth, h(async (req, res) => {
  res.json(await getSettings(req.user.id));
}));

app.put('/v1/settings', requireAuth, h(async (req, res) => {
  const { notify_time, tz_offset_minutes } = req.body || {};
  if (notify_time !== undefined && !TIME_RE.test(notify_time)) {
    return res.status(400).json({ error: 'invalid_time', message: 'notify_time must be HH:MM (24-hour).' });
  }
  if (tz_offset_minutes !== undefined && !(Number.isInteger(tz_offset_minutes) && Math.abs(tz_offset_minutes) <= 14 * 60)) {
    return res.status(400).json({ error: 'invalid_timezone' });
  }
  const current = await getSettings(req.user.id);
  const next = {
    user_id: req.user.id,
    notify_time: notify_time ?? current.notify_time,
    tz_offset_minutes: tz_offset_minutes ?? current.tz_offset_minutes,
    updated_at: new Date().toISOString(),
  };
  unwrap(await db.from('user_settings').upsert(next, { onConflict: 'user_id' }));
  res.json({ notify_time: next.notify_time, tz_offset_minutes: next.tz_offset_minutes });
}));

// ---------------------------------------------------------------------------
// Reminders: schedulable up to 6 days ahead, deletable until sent
// ---------------------------------------------------------------------------
const MAX_REMINDER_DAYS = 6;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

// "Today" as the user sees it, given their timezone offset
function userLocalDate(tzOffsetMinutes, at = new Date()) {
  return new Date(at.getTime() - tzOffsetMinutes * 60_000).toISOString().slice(0, 10);
}

function userLocalTime(tzOffsetMinutes, at = new Date()) {
  return new Date(at.getTime() - tzOffsetMinutes * 60_000).toISOString().slice(11, 16);
}

app.get('/v1/reminders', requireAuth, h(async (req, res) => {
  const rows = unwrap(
    await db
      .from('reminders')
      .select('id, title, body, due_date, sent_at, created_at')
      .eq('user_id', req.user.id)
      .order('due_date', { ascending: true }),
  );
  res.json({ reminders: rows });
}));

app.post('/v1/reminders', requireAuth, h(async (req, res) => {
  const { title, body = '', due_date } = req.body || {};
  if (!title?.trim() || title.length > 120) {
    return res.status(400).json({ error: 'invalid_title', message: 'Title is required (max 120 chars).' });
  }
  if (!DATE_RE.test(due_date ?? '') || Number.isNaN(Date.parse(due_date))) {
    return res.status(400).json({ error: 'invalid_date', message: 'due_date must be YYYY-MM-DD.' });
  }

  const { tz_offset_minutes } = await getSettings(req.user.id);
  const today = userLocalDate(tz_offset_minutes);
  const max = userLocalDate(tz_offset_minutes, new Date(Date.now() + MAX_REMINDER_DAYS * 86_400_000));
  if (due_date < today) {
    return res.status(400).json({ error: 'date_in_past', message: 'due_date cannot be in the past.' });
  }
  if (due_date > max) {
    return res.status(400).json({ error: 'date_too_far', message: `due_date can be at most ${MAX_REMINDER_DAYS} days ahead.` });
  }

  const reminder = unwrap(
    await db
      .from('reminders')
      .insert({ user_id: req.user.id, title: title.trim(), body, due_date })
      .select('id, title, body, due_date, sent_at, created_at')
      .single(),
  );
  res.status(201).json(reminder);
}));

app.delete('/v1/reminders/:id', requireAuth, h(async (req, res) => {
  const deleted = unwrap(
    await db
      .from('reminders')
      .delete()
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .select('id')
      .maybeSingle(),
  );
  if (!deleted) return res.status(404).json({ error: 'reminder_not_found' });
  res.json({ ok: true });
}));

// ---------------------------------------------------------------------------
// Reminder scheduler: fires each due reminder at the user's notify time.
// Claims rows with a conditional update so overlapping ticks (or multiple
// server instances) never send the same reminder twice.
// ---------------------------------------------------------------------------
async function deliverDueReminders() {
  const pending = unwrap(
    await db
      .from('reminders')
      .select('id, user_id, title, body, due_date')
      .is('sent_at', null)
      .lte('due_date', userLocalDate(-14 * 60)), // cheap prefilter: earliest timezone's today
  );
  if (!pending.length) return;

  const settingsCache = new Map();
  for (const reminder of pending) {
    if (!settingsCache.has(reminder.user_id)) {
      settingsCache.set(reminder.user_id, await getSettings(reminder.user_id));
    }
    const { notify_time, tz_offset_minutes } = settingsCache.get(reminder.user_id);
    const today = userLocalDate(tz_offset_minutes);
    const now = userLocalTime(tz_offset_minutes);
    const due = reminder.due_date < today || (reminder.due_date === today && now >= notify_time);
    if (!due) continue;

    const claimed = unwrap(
      await db
        .from('reminders')
        .update({ sent_at: new Date().toISOString() })
        .eq('id', reminder.id)
        .is('sent_at', null)
        .select('id')
        .maybeSingle(),
    );
    if (!claimed) continue; // another instance got it first

    await sendPushToUser(reminder.user_id, {
      title: reminder.title,
      body: reminder.body || `Reminder for ${reminder.due_date}`,
      url: '/',
    }).catch((err) => console.error('reminder push failed:', err.message));
  }
}

setInterval(() => deliverDueReminders().catch((err) => console.error('scheduler:', err.message)), 60_000);

// ---------------------------------------------------------------------------
// Error handler: never leak internals, always answer JSON
// ---------------------------------------------------------------------------
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'internal_error' });
});

ensureDemoUser()
  .then(() => {
    app.listen(PORT, () => console.log(`App running at http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error('Failed to reach Supabase on boot:', err.message);
    console.error('Check SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY and that db/schema.sql has been applied.');
    process.exit(1);
  });
