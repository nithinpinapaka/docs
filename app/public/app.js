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

// Boot: register SW, then try a silent refresh to restore the session
(async () => {
  if ('serviceWorker' in navigator) {
    await navigator.serviceWorker.register('/sw.js');
  }
  if (await refresh()) {
    $('whoami').textContent = 'Session restored';
    showApp(true);
    renderSessions();
  }
})();
