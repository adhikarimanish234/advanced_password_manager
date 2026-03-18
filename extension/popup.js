/*
  popup.js — Password Manager Extension
  ======================================
  Talks to the Flask backend at http://127.0.0.1:5000
  Auth:  token stored in chrome.storage.local, sent as X-Ext-Token header
  Every action (save/get/autofill/generate) mirrors what the web dashboard does,
  using the same API endpoints — so data is always shared / in sync.
*/

const BASE = 'http://127.0.0.1:5000';
const STRENGTH_COLORS = ['#dc3545','#fd7e14','#ffc107','#28a745','#20c997'];
const STRENGTH_LABELS = ['Very Weak','Weak','Fair','Strong','Very Strong'];

// ── chrome.storage helpers ────────────────────────────────────────────────────
const store = {
  get: (key)       => new Promise(r => chrome.storage.local.get(key, d => r(d[key] ?? null))),
  set: (key, val)  => new Promise(r => chrome.storage.local.set({ [key]: val }, r)),
  del: (...keys)   => new Promise(r => chrome.storage.local.remove(keys, r)),
};

// ── Authenticated fetch (adds X-Ext-Token automatically) ─────────────────────
async function api(path, opts = {}) {
  const token = await store.get('ext_token');
  const res = await fetch(BASE + path, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'X-Ext-Token': token } : {}),
      ...(opts.headers || {}),
    },
  });
  return res.json();
}

// ── Alert helper ─────────────────────────────────────────────────────────────
function alert(msg, type = 'err') {
  const el = document.getElementById('alertBox');
  el.textContent = msg;
  el.className   = 'alert alert-' + type;
  el.style.display = 'block';
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.style.display = 'none'; }, 3500);
}

// ── Strength bar UI ───────────────────────────────────────────────────────────
function setStrength(score) {
  document.getElementById('strengthFill').style.cssText =
    `width:${((score+1)/5)*100}%;background:${STRENGTH_COLORS[score]}`;
  const lbl = document.getElementById('strengthLabel');
  lbl.textContent  = STRENGTH_LABELS[score];
  lbl.style.color  = STRENGTH_COLORS[score];
}
function clearStrength() {
  document.getElementById('strengthFill').style.width = '0%';
  document.getElementById('strengthLabel').textContent = '—';
  document.getElementById('strengthLabel').style.color = '#a8c0e8';
}

// ── Show correct section based on stored token ────────────────────────────────
async function refreshUI() {
  const token    = await store.get('ext_token');
  const username = await store.get('ext_username');

  if (token) {
    // Verify the token is still valid (in case server restarted)
    try {
      const s = await api('/api/ext/status');
      if (!s.logged_in) { await doLogout(true); return; }
    } catch (_) { /* server might be down — still show main section */ }

    document.getElementById('loginSection').style.display = 'none';
    document.getElementById('mainSection').style.display  = 'block';
    document.getElementById('loggedUser').textContent     = username || '?';
    populateDropdown();
    detectSite();
  } else {
    document.getElementById('loginSection').style.display = 'block';
    document.getElementById('mainSection').style.display  = 'none';
  }
}

// ── Populate the "select saved entry" dropdown ────────────────────────────────
async function populateDropdown() {
  try {
    const list = await api('/api/passwords/list');
    const sel  = document.getElementById('savedSelect');
    sel.innerHTML = '<option value="">— Select saved entry to load —</option>';
    if (Array.isArray(list)) {
      list.forEach(e => {
        const o = document.createElement('option');
        o.value       = e.id;
        o.textContent = `${e.website}  (${e.username})`;
        sel.appendChild(o);
      });
    }
  } catch (_) {}
}

// ── Auto-detect current tab hostname ─────────────────────────────────────────
async function detectSite() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
      const { hostname } = new URL(tab.url);
      if (hostname) document.getElementById('siteInput').value = hostname;
    }
  } catch (_) {}
}

// ── Logout helper ─────────────────────────────────────────────────────────────
async function doLogout(silent = false) {
  try { await api('/api/ext/logout', { method: 'POST' }); } catch (_) {}
  await store.del('ext_token', 'ext_username');
  if (!silent) alert('Logged out.', 'ok');
  refreshUI();
}

// ══════════════════════════════════════════════════════════════════════════════
//  EVENT LISTENERS
// ══════════════════════════════════════════════════════════════════════════════

// ── LOGIN ─────────────────────────────────────────────────────────────────────
document.getElementById('btnLogin').addEventListener('click', async () => {
  const username = document.getElementById('loginUser').value.trim();
  const password = document.getElementById('loginPass').value.trim();
  if (!username || !password) { alert('Enter your username and master password.'); return; }

  try {
    const data = await fetch(BASE + '/api/ext/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password }),
    }).then(r => r.json());

    if (data.token) {
      await store.set('ext_token',    data.token);
      await store.set('ext_username', data.username);
      alert('Login successful!', 'ok');
      refreshUI();
    } else {
      alert(data.error || 'Login failed.');
    }
  } catch (_) {
    alert('Cannot reach server. Make sure Flask is running on port 5000.');
  }
});

// Allow Enter key on login fields
['loginUser','loginPass'].forEach(id =>
  document.getElementById(id).addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('btnLogin').click();
  })
);

// ── LOGOUT ────────────────────────────────────────────────────────────────────
document.getElementById('btnLogout').addEventListener('click', () => doLogout());

// ── LOAD ENTRY FROM DROPDOWN ──────────────────────────────────────────────────
document.getElementById('savedSelect').addEventListener('change', async function () {
  if (!this.value) return;
  try {
    const d = await api('/api/passwords/decrypt/' + this.value);
    if (d.error) { alert(d.error); return; }
    document.getElementById('siteInput').value = d.website;
    document.getElementById('userInput').value = d.username;
    document.getElementById('passInput').value = d.password;
    setStrength(d.strength_score ?? 0);
  } catch (_) { alert('Failed to load entry.'); }
});

// ── LIVE STRENGTH ON TYPING ───────────────────────────────────────────────────
document.getElementById('passInput').addEventListener('input', async function () {
  const pw = this.value;
  if (!pw) { clearStrength(); return; }
  try {
    const d = await fetch(BASE + '/api/strength/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw }),
    }).then(r => r.json());
    if (d.score !== undefined) setStrength(d.score);
  } catch (_) {}
});

// ── GENERATE PASSWORD ─────────────────────────────────────────────────────────
document.getElementById('btnGenerate').addEventListener('click', () => {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  const pw = Array.from(bytes).map(b => chars[b % chars.length]).join('');
  document.getElementById('passInput').value = pw;
  document.getElementById('passInput').dispatchEvent(new Event('input'));
});

// ── COPY USERNAME ─────────────────────────────────────────────────────────────
document.getElementById('btnCopyUser').addEventListener('click', async () => {
  const val = document.getElementById('userInput').value;
  if (!val) { alert('No username to copy.'); return; }
  try {
    await navigator.clipboard.writeText(val);
    alert('Username copied!', 'ok');
  } catch (_) { alert('Clipboard access denied.'); }
});

// ── COPY PASSWORD ─────────────────────────────────────────────────────────────
document.getElementById('btnCopyPass').addEventListener('click', async () => {
  const val = document.getElementById('passInput').value;
  if (!val) { alert('No password to copy.'); return; }
  try {
    await navigator.clipboard.writeText(val);
    alert('Password copied!', 'ok');
  } catch (_) { alert('Clipboard access denied.'); }
});

// ── SAVE ──────────────────────────────────────────────────────────────────────
document.getElementById('btnSave').addEventListener('click', async () => {
  const website  = document.getElementById('siteInput').value.trim();
  const username = document.getElementById('userInput').value.trim();
  const password = document.getElementById('passInput').value.trim();
  if (!website || !username || !password) {
    alert('Please fill in Site, Username and Password.'); return;
  }
  try {
    const d = await api('/api/passwords/store', {
      method: 'POST',
      body:   JSON.stringify({ website, username, password, category: 'General' }),
    });
    if (d.error) { alert(d.error); return; }
    alert(`Saved!  Strength: ${STRENGTH_LABELS[d.strength_score ?? 0]}`, 'ok');
    populateDropdown();   // refresh dropdown with new entry
  } catch (_) { alert('Save failed.'); }
});

// ── GET (find best-matching entry for current site) ───────────────────────────
document.getElementById('btnGet').addEventListener('click', async () => {
  const site = document.getElementById('siteInput').value.trim();
  try {
    const list = await api('/api/passwords/list');
    if (!Array.isArray(list)) { alert(list.error || 'Could not fetch list.'); return; }

    const match = list.find(e =>
      e.website.toLowerCase().includes(site.toLowerCase()) ||
      site.toLowerCase().includes(e.website.toLowerCase())
    );
    if (!match) { alert(`No saved entry found for "${site}".`); return; }

    const d = await api('/api/passwords/decrypt/' + match.id);
    if (d.error) { alert(d.error); return; }
    document.getElementById('siteInput').value = d.website;
    document.getElementById('userInput').value = d.username;
    document.getElementById('passInput').value = d.password;
    setStrength(d.strength_score ?? 0);
    alert(`Loaded: ${d.website}`, 'ok');
  } catch (_) { alert('Get failed.'); }
});

// ── AUTO FILL ─────────────────────────────────────────────────────────────────
document.getElementById('btnAutoFill').addEventListener('click', async () => {
  const username = document.getElementById('userInput').value.trim();
  const password = document.getElementById('passInput').value.trim();
  if (!username || !password) {
    alert('Load or enter credentials first, then click Auto Fill.'); return;
  }
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: (u, p) => {
        /*
          Smart fill: tries common username/email selectors first,
          then falls back to the first visible text/email input.
          Uses native value setter so React / Vue / Angular inputs
          trigger their internal state change correctly.
        */
        const nativeSet = Object.getOwnPropertyDescriptor(
          window.HTMLInputElement.prototype, 'value').set;

        function fill(el, val) {
          nativeSet.call(el, val);
          el.dispatchEvent(new Event('input',  { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
        }

        const userSels = [
          'input[type=email]',
          'input[autocomplete=username]',
          'input[autocomplete=email]',
          'input[name*=user i]',
          'input[id*=user i]',
          'input[name*=email i]',
          'input[id*=email i]',
          'input[name*=login i]',
        ];
        const passSels = ['input[type=password]'];

        let uFilled = false, pFilled = false;

        for (const sel of userSels) {
          const el = document.querySelector(sel);
          if (el) { fill(el, u); uFilled = true; break; }
        }
        if (!uFilled) {
          // Fall back: first visible text input that isn't password
          const inputs = [...document.querySelectorAll('input[type=text],input:not([type])')];
          const vis    = inputs.find(el => el.offsetParent !== null);
          if (vis) { fill(vis, u); uFilled = true; }
        }

        for (const sel of passSels) {
          const el = document.querySelector(sel);
          if (el) { fill(el, p); pFilled = true; break; }
        }

        return { uFilled, pFilled };
      },
      args: [username, password],
    });
    alert('Auto-filled!', 'ok');
  } catch (e) {
    alert('Auto-fill failed: ' + e.message);
  }
});

// ── INIT ──────────────────────────────────────────────────────────────────────
refreshUI();
