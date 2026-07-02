// Access token lives only in memory; the refresh token is an httpOnly cookie
// scoped to /auth, so scripts (and XSS) can never read it.
let accessToken = null;
let refreshTimer = null;

const $ = (id) => document.getElementById(id);
const setStatus = (msg) => { $('status').textContent = msg; };

// --------------------------------------------------------------------------
// Auth: login, silent refresh, authenticated fetch with 401 retry
// --------------------------------------------------------------------------
function storeToken(data) {
  accessToken = data.access_token;
  // Refresh 60s before expiry so users never see an interruption
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refresh, (data.expires_in - 60) * 1000);
}

async function login(email, password) {
  const res = await fetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error((await res.json()).error);
  storeToken(await res.json());
}

async function refresh() {
  const res = await fetch('/auth/refresh', { method: 'POST' });
  if (!res.ok) {
    accessToken = null;
    return false;
  }
  storeToken(await res.json());
  return true;
}

async function api(url, options = {}) {
  const withAuth = () => ({
    ...options,
    headers: { ...options.headers, Authorization: `Bearer ${accessToken}` },
  });
  let res = await fetch(url, withAuth());
  if (res.status === 401 && (await refresh())) {
    res = await fetch(url, withAuth()); // retry once with the fresh token
  }
  return res;
}

// --------------------------------------------------------------------------
// Sessions UI
// --------------------------------------------------------------------------
async function renderSessions() {
  const res = await api('/v1/sessions');
  if (!res.ok) return;
  const { sessions } = await res.json();
  $('sessions').innerHTML = sessions.map((s) => `
    <div class="session">
      <div>
        <div>${s.device.slice(0, 48)} ${s.current ? '<span class="badge">this device</span>' : ''}</div>
        <div class="meta">${s.ip} · last active ${new Date(s.last_active).toLocaleString()}</div>
      </div>
      ${s.current ? '' : `<button class="danger" data-revoke="${s.id}">Revoke</button>`}
    </div>
  `).join('');

  for (const btn of $('sessions').querySelectorAll('[data-revoke]')) {
    btn.onclick = async () => {
      await api(`/v1/sessions/${btn.dataset.revoke}`, { method: 'DELETE' });
      renderSessions();
    };
  }
}

// --------------------------------------------------------------------------
// Push notifications
// --------------------------------------------------------------------------
function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}

async function enablePush() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    setStatus('Push is not supported in this browser.');
    return;
  }
  const permission = await Notification.requestPermission();
  if (permission !== 'granted') {
    setStatus('Notification permission was denied.');
    return;
  }

  const reg = await navigator.serviceWorker.ready;
  const { publicKey } = await (await fetch('/api/push/vapid-public-key')).json();
  const subscription =
    (await reg.pushManager.getSubscription()) ??
    (await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(publicKey),
    }));

  const res = await api('/api/push/subscribe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(subscription),
  });
  if (res.ok) {
    setStatus('Push notifications enabled.');
    $('test-push-btn').disabled = false;
  }
}

async function sendTestPush() {
  const res = await api('/api/push/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      title: 'Hello from PWA Auth App',
      body: 'Push notifications are working correctly.',
      url: '/',
    }),
  });
  const { sent, failed } = await res.json();
  setStatus(`Test notification: ${sent} sent, ${failed} failed.`);
}

// --------------------------------------------------------------------------
// Notification settings + reminders
// --------------------------------------------------------------------------
async function loadSettings() {
  const res = await api('/v1/settings');
  if (res.ok) {
    const { notify_time } = await res.json();
    $('notify-time').value = notify_time;
  }
}

async function saveSettings() {
  const res = await api('/v1/settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      notify_time: $('notify-time').value,
      tz_offset_minutes: new Date().getTimezoneOffset(),
    }),
  });
  setStatus(res.ok ? 'Settings saved.' : `Could not save: ${(await res.json()).message ?? 'error'}`);
}

function setReminderDateBounds() {
  const fmt = (d) => d.toISOString().slice(0, 10);
  const today = new Date();
  const max = new Date(today.getTime() + 6 * 86_400_000);
  $('reminder-date').min = fmt(today);
  $('reminder-date').max = fmt(max);
  $('reminder-date').value = fmt(today);
}

async function renderReminders() {
  const res = await api('/v1/reminders');
  if (!res.ok) return;
  const { reminders } = await res.json();
  $('reminders').innerHTML = reminders.length
    ? reminders.map((r) => `
        <div class="session">
          <div>
            <div>${r.title}</div>
            <div class="meta">${r.due_date}${r.sent_at ? ' · sent' : ''}</div>
          </div>
          <button class="danger" data-del-reminder="${r.id}">Delete</button>
        </div>
      `).join('')
    : '<p class="meta" style="font-size:.85rem;color:#5b6b73;">No reminders yet.</p>';

  for (const btn of $('reminders').querySelectorAll('[data-del-reminder]')) {
    btn.onclick = async () => {
      await api(`/v1/reminders/${btn.dataset.delReminder}`, { method: 'DELETE' });
      renderReminders();
    };
  }
}

async function addReminder() {
  const title = $('reminder-title').value.trim();
  if (!title) { setStatus('Reminder title is required.'); return; }
  const res = await api('/v1/reminders', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title, due_date: $('reminder-date').value }),
  });
  if (res.ok) {
    $('reminder-title').value = '';
    setStatus('Reminder added.');
    renderReminders();
  } else {
    setStatus(`Could not add: ${(await res.json()).message ?? 'error'}`);
  }
}

// --------------------------------------------------------------------------
// Wiring
// --------------------------------------------------------------------------
function showApp(loggedIn) {
  $('login-view').classList.toggle('hidden', loggedIn);
  $('app-view').classList.toggle('hidden', !loggedIn);
}

$('login-btn').onclick = async () => {
  try {
    await login($('email').value, $('password').value);
    setStatus('');
    $('whoami').textContent = `Logged in as ${$('email').value}`;
    showApp(true);
    renderSessions();
    loadSettings();
    setReminderDateBounds();
    renderReminders();
  } catch (err) {
    setStatus(`Login failed: ${err.message}`);
  }
};

$('logout-btn').onclick = async () => {
  await api('/auth/logout', { method: 'POST' });
  accessToken = null;
  clearTimeout(refreshTimer);
  showApp(false);
};

$('logout-all-btn').onclick = async () => {
  await api('/auth/logout-all', { method: 'POST' });
  accessToken = null;
  clearTimeout(refreshTimer);
  showApp(false);
};

$('enable-push-btn').onclick = enablePush;
$('test-push-btn').onclick = sendTestPush;
$('save-settings-btn').onclick = saveSettings;
$('add-reminder-btn').onclick = addReminder;

// Boot: register SW, then try a silent refresh to restore the session
(async () => {
  if ('serviceWorker' in navigator) {
    await navigator.serviceWorker.register('/sw.js');
  }
  if (await refresh()) {
    $('whoami').textContent = 'Session restored';
    showApp(true);
    renderSessions();
    loadSettings();
    setReminderDateBounds();
    renderReminders();
  }
})();
