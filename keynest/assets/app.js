// ============================================================
// KeyNest — App Logic
// Depends on: crypto.js, api.js (loaded before this in index.html)
// ============================================================

// ── STATE ──────────────────────────────────────────────────
let currentUser   = null;  // { id, email, salt }
let encKey        = null;  // CryptoKey — derived from password, never leaves memory
let entries       = [];    // decrypted entry objects
let trashItems    = [];    // decrypted trash objects
let allTags       = [];    // tag objects { id, name }
let activeView    = 'all';
let editId        = null;
let modalType     = 'password';
let selectedTags  = [];
let shownPasswords = {};
let confirmCallback = null;
let authMode      = 'login';

const genOpts = { upper: true, lower: true, nums: true, syms: true, length: 16 };

const APP_VERSION = 'v1_php';

// ── BOOT ───────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  // Clear stale sessions
  if (sessionStorage.getItem('kn_version') !== APP_VERSION) {
    sessionStorage.clear();
    sessionStorage.setItem('kn_version', APP_VERSION);
  }

  try {
    const session = await API.auth.check();
    if (session.authenticated) {
      // Restore session — but we need the key, so ask user to re-enter password
      // (key is never stored — this is by design)
      showResumeScreen(session);
    }
  } catch {
    // Not authenticated — show login
  }
});

// ── AUTH ───────────────────────────────────────────────────
function switchAuthTab(mode) {
  authMode = mode;
  document.getElementById('tab-login').classList.toggle('active', mode === 'login');
  document.getElementById('tab-register').classList.toggle('active', mode === 'register');
  document.getElementById('auth-submit-btn').textContent = mode === 'login' ? 'Sign In' : 'Create Account';
  document.getElementById('auth-subtitle').textContent = mode === 'login'
    ? 'Welcome back. Sign in to access your vault.'
    : 'Create your account to get started.';
  document.getElementById('auth-strength-wrap').style.display = mode === 'register' ? '' : 'none';
  document.getElementById('auth-error').classList.remove('show');
  document.getElementById('auth-password').value = '';
  document.getElementById('auth-str-fill').style.cssText = 'width:0%';
}

function toggleAuthPw() {
  const inp = document.getElementById('auth-password');
  inp.type = inp.type === 'password' ? 'text' : 'password';
}

function updateAuthStrength() {
  if (authMode !== 'register') return;
  const pw = document.getElementById('auth-password').value;
  const s = getStrength(pw);
  document.getElementById('auth-str-fill').style.cssText = `width:${s.score}%;background:${s.color}`;
  const lbl = document.getElementById('auth-str-label');
  lbl.textContent = s.label;
  lbl.style.color = s.color || 'var(--text3)';
}

function showAuthError(msg) {
  const el = document.getElementById('auth-error');
  el.textContent = msg;
  el.classList.add('show');
}

async function submitAuth() {
  const email    = document.getElementById('auth-email').value.trim().toLowerCase();
  const password = document.getElementById('auth-password').value;
  document.getElementById('auth-error').classList.remove('show');

  if (!email || !password) { showAuthError('Please fill in all fields.'); return; }
  if (!email.includes('@')) { showAuthError('Enter a valid email address.'); return; }
  if (authMode === 'register' && password.length < 8) {
    showAuthError('Password must be at least 8 characters.'); return;
  }

  const btn = document.getElementById('auth-submit-btn');
  btn.textContent = 'Loading…';
  btn.disabled = true;

  try {
    const fn = authMode === 'register' ? API.auth.register : API.auth.login;
    const user = await fn(email, password);

    // Derive encryption key from password + server salt
    encKey = await Crypto.deriveKey(password, user.salt);
    currentUser = { id: user.id, email: user.email, salt: user.salt };

    await initVault();
  } catch (err) {
    showAuthError(err.message || 'Something went wrong. Please try again.');
  } finally {
    btn.textContent = authMode === 'login' ? 'Sign In' : 'Create Account';
    btn.disabled = false;
  }
}

// Resume screen — shown when session exists but key isn't in memory
function showResumeScreen(session) {
  document.getElementById('auth-subtitle').textContent =
    `Welcome back, ${session.email}. Enter your password to unlock your vault.`;
  document.getElementById('auth-email').value = session.email;
  switchAuthTab('login');
  document.getElementById('tab-login').style.display = 'none';
  document.getElementById('tab-register').style.display = 'none';

  // Override submit to just derive key + load vault
  document.getElementById('auth-submit-btn').textContent = 'Unlock Vault';
  document.getElementById('auth-submit-btn').onclick = async () => {
    const password = document.getElementById('auth-password').value;
    if (!password) { showAuthError('Enter your password.'); return; }
    try {
      encKey = await Crypto.deriveKey(password, session.salt);
      currentUser = { id: session.id, email: session.email, salt: session.salt };
      await initVault();
    } catch {
      showAuthError('Incorrect password.');
    }
  };
}

async function logout() {
  try { await API.auth.logout(); } catch {}
  encKey = null;
  currentUser = null;
  entries = []; trashItems = []; allTags = [];
  shownPasswords = {}; activeView = 'all';
  document.getElementById('fab').style.display = 'none';
  document.getElementById('vault-shell').classList.add('hidden');
  document.getElementById('auth-screen').classList.remove('hidden');
  // restore auth form
  document.getElementById('auth-email').closest('.auth-field').style.display = '';
  document.getElementById('auth-email').value = '';
  document.getElementById('auth-password').value = '';
  document.getElementById('auth-error').classList.remove('show');
  document.getElementById('tab-login').style.display = '';
  document.getElementById('tab-register').style.display = '';
  document.getElementById('auth-submit-btn').onclick = submitAuth;
  switchAuthTab('login');
}

// ── VAULT INIT ─────────────────────────────────────────────
async function initVault() {
  showToast('Loading vault…');

  try {
    // Load all data in parallel
    const [rawEntries, rawTrash, rawTags] = await Promise.all([
      API.entries.list(),
      API.trash.list(),
      API.tags.list(),
    ]);

    // Decrypt entries
    entries = await Promise.all(rawEntries.map(async row => {
      try {
        const plain = await Crypto.decrypt(encKey, row.ciphertext);
        return { ...plain, _dbId: row.id, _type: row.type, _updatedAt: row.updated_at };
      } catch {
        return null; // skip corrupted entries
      }
    }));
    entries = entries.filter(Boolean);

    // Decrypt trash
    trashItems = await Promise.all(rawTrash.map(async row => {
      try {
        const plain = await Crypto.decrypt(encKey, row.ciphertext);
        return { ...plain, _dbId: row.id, _type: row.type, deletedAt: new Date(row.deleted_at).getTime() };
      } catch {
        return null;
      }
    }));
    trashItems = trashItems.filter(Boolean);

    allTags = rawTags; // [{ id, name }]

    // Seed demo data for brand new accounts
    if (!entries.length && !trashItems.length) {
      await seedDemoData();
    }

  } catch (err) {
    showToast('Failed to load vault: ' + err.message);
    return;
  }

  // Show vault
  const initials = currentUser.email.split('@')[0].slice(0, 2).toUpperCase();
  const avatarEl = document.getElementById('user-avatar');
  if (avatarEl) { avatarEl.textContent = initials; avatarEl.title = currentUser.email; }
  document.getElementById('fab').style.display = '';
  document.getElementById('auth-screen').classList.add('hidden');
  document.getElementById('vault-shell').classList.remove('hidden');
  activeView = 'all';
  document.getElementById('search').value = '';
  renderSidebar();
  renderMain();
}

async function seedDemoData() {
  const demos = [
    { id: uid(), type: 'password', site: 'GitHub',      username: currentUser.email, password: 'Xk#9mP2vQr!',  tags: [] },
    { id: uid(), type: 'password', site: 'Vercel',      username: currentUser.email, password: 'v3rc3L!2024#', tags: [] },
    { id: uid(), type: 'password', site: 'Twitter / X', username: currentUser.email, password: 'password1',    tags: [] },
    { id: uid(), type: 'note',     title: 'WiFi Password', body: 'Network: HomeNetwork_5G\nPassword: SuperSecret2024!', tags: [] },
  ];

  for (const entry of demos) {
    const ciphertext = await Crypto.encrypt(encKey, entry);
    const row = await API.entries.create(entry.id, entry.type, ciphertext);
    entries.push({ ...entry, _dbId: row.id });
  }

  // Seed two starter tags
  for (const name of ['Work', 'Personal']) {
    const tag = await API.tags.create(name);
    allTags.push(tag);
  }
}

// ── STRENGTH ───────────────────────────────────────────────
function getStrength(pw) {
  if (!pw) return { score: 0, label: '—', cls: '', color: '' };
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[A-Z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  if (s <= 1) return { score: 20, label: 'Weak',   cls: 'weak',   color: '#dc2626' };
  if (s <= 3) return { score: 55, label: 'Medium', cls: 'medium', color: '#b45309' };
  return           { score: 100, label: 'Strong', cls: 'strong', color: '#16a34a' };
}

// ── SIDEBAR ────────────────────────────────────────────────
function renderSidebar() {
  const pwCount   = entries.filter(e => e.type !== 'note').length;
  const noteCount = entries.filter(e => e.type === 'note').length;
  const tagCounts = {};
  entries.forEach(e => (e.tags||[]).forEach(t => { tagCounts[t] = (tagCounts[t]||0)+1; }));

  const item = (view, icon, label, count, extra='') => `
    <div class="sidebar-item ${extra} ${activeView===view?'active':''}" onclick="setView('${view}')">
      <div class="si-left"><div class="si-icon">${icon}</div><span class="si-label">${label}</span></div>
      ${count !== null ? `<span class="sidebar-count">${count}</span>` : ''}
    </div>`;

  const icons = {
    key:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3"/></svg>`,
    note:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`,
    tag:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>`,
    trash:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>`,
    health: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
    gen:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>`,
  };

  const tagsHtml = allTags.map(t => `
    <div class="sidebar-item ${activeView===t.name?'active':''}" onclick="setView('${esc(t.name)}')">
      <div class="si-left">
        <div class="si-icon">${icons.tag}</div>
        <span class="si-label">${esc(t.name)}</span>
      </div>
      <div style="display:flex;align-items:center;gap:4px;flex-shrink:0">
        <span class="sidebar-count">${tagCounts[t.name]||0}</span>
        <button onclick="event.stopPropagation();deleteTag(${t.id},'${esc(t.name)}')"
          style="background:none;border:none;cursor:pointer;color:var(--text3);font-size:15px;line-height:1;padding:2px 3px;border-radius:4px;transition:color 0.12s,background 0.12s"
          onmouseover="this.style.color='var(--danger)';this.style.background='var(--danger-bg)'"
          onmouseout="this.style.color='var(--text3)';this.style.background='none'"
          title="Delete tag">×</button>
      </div>
    </div>`).join('');

  const html = `
    <div class="sidebar-section-title">Vault</div>
    ${item('all',       icons.key,    'All Passwords', pwCount)}
    ${item('notes',     icons.note,   'Secure Notes',  noteCount)}
    ${allTags.length ? `<div class="sidebar-divider"></div><div class="sidebar-section-title">Tags</div>${tagsHtml}` : '<div class="sidebar-divider"></div><div class="sidebar-section-title">Tags</div>'}
    <div class="sidebar-item" id="sidebar-add-tag-row" onclick="toggleSidebarTagInput()" style="color:var(--text3);font-size:12px;">
      <div class="si-left">
        <div class="si-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        </div>
        <span class="si-label">New tag</span>
      </div>
    </div>
    <div id="sidebar-tag-input-wrap" style="display:none;padding:4px 6px 8px;">
      <div style="display:flex;gap:6px;">
        <input id="sidebar-tag-input" type="text" placeholder="Tag name…"
          style="flex:1;padding:7px 10px;font-size:12px;font-family:'Outfit',sans-serif;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);outline:none;color:var(--text);"
          onkeydown="if(event.key==='Enter'){createSidebarTag();event.preventDefault();}if(event.key==='Escape'){toggleSidebarTagInput();}"
          onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'" />
        <button onclick="createSidebarTag()"
          style="background:var(--text);color:#fff;border:none;padding:7px 12px;border-radius:var(--radius-sm);font-family:'Outfit',sans-serif;font-size:12px;font-weight:500;cursor:pointer;white-space:nowrap;">
          Add
        </button>
      </div>
    </div>
    <div class="sidebar-divider"></div>
    ${item('trash',     icons.trash,  'Trash',         trashItems.length, 'trash-item')}
    <div class="sidebar-divider"></div>
    ${item('health',    icons.health, 'Health',        null)}
    ${item('generator', icons.gen,    'Generator',     null)}
  `;

  document.getElementById('sidebar').innerHTML = html;
}

function setView(view) {
  activeView = view;
  document.getElementById('search').value = '';
  renderSidebar();
  renderMain();
}

// ── STATS ──────────────────────────────────────────────────
function renderStats() {
  const pw = entries.filter(e => e.type !== 'note');
  const strong = pw.filter(e => getStrength(e.password).cls === 'strong').length;
  const weak   = pw.filter(e => getStrength(e.password).cls === 'weak').length;
  const pws    = pw.map(e => e.password);
  const reused = pws.length - new Set(pws).size;
  document.getElementById('stats').innerHTML = `
    <div class="stat-card"><div class="stat-num">${pw.length}</div><div class="stat-label">Stored</div></div>
    <div class="stat-card"><div class="stat-num" style="color:var(--success)">${strong}</div><div class="stat-label">Strong</div></div>
    <div class="stat-card"><div class="stat-num" style="color:var(--danger)">${weak}</div><div class="stat-label">Weak</div></div>
    <div class="stat-card"><div class="stat-num" style="color:var(--warn)">${reused}</div><div class="stat-label">Reused</div></div>
    <div class="stat-card"><div class="stat-num">${entries.filter(e=>e.type==='note').length}</div><div class="stat-label">Notes</div></div>
  `;
}

// ── MAIN RENDER ────────────────────────────────────────────
function renderMain() {
  const q       = document.getElementById('search').value.toLowerCase();
  const wrap    = document.getElementById('main-content');
  const statsEl = document.getElementById('stats');
  const toolEl  = document.querySelector('.toolbar');

  if (activeView === 'generator') {
    statsEl.style.display = 'none'; toolEl.style.display = 'none';
    renderGenerator(wrap); return;
  }
  if (activeView === 'health') {
    statsEl.style.display = 'none'; toolEl.style.display = 'none';
    renderHealth(wrap); return;
  }

  statsEl.style.display = ''; toolEl.style.display = '';
  renderStats();

  if (activeView === 'trash') { renderTrash(wrap, q); return; }

  let filtered = entries.filter(e => {
    const matchQ = e.type === 'note'
      ? (e.title||'').toLowerCase().includes(q)||(e.body||'').toLowerCase().includes(q)
      : (e.site||'').toLowerCase().includes(q)||(e.username||'').toLowerCase().includes(q);
    if (!matchQ) return false;
    if (activeView === 'all')   return e.type !== 'note';
    if (activeView === 'notes') return e.type === 'note';
    return (e.tags||[]).includes(activeView);
  });

  const labels = { all:'All Passwords', notes:'Secure Notes' };
  const label  = labels[activeView] || `#${activeView}`;

  if (!filtered.length) {
    wrap.innerHTML = `
      <div class="section-heading"><h2>${label}</h2></div>
      <div class="entries"><div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5">
          <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <p>${entries.length===0?'Your vault is empty.<br>Add your first entry.':'Nothing here yet.'}</p>
      </div></div>`;
    return;
  }

  wrap.innerHTML = `
    <div class="section-heading"><h2>${label}</h2><span class="sub">${filtered.length} item${filtered.length!==1?'s':''}</span></div>
    <div class="entries">${filtered.map((e,i) => e.type==='note' ? renderNoteCard(e,i) : renderPwCard(e,i)).join('')}</div>
  `;
}

// ── CARD HTML ──────────────────────────────────────────────
function renderPwCard(e, i) {
  const s      = getStrength(e.password);
  const shown  = shownPasswords[e.id];
  const masked = '•'.repeat(Math.min((e.password||'').length, 14));
  const tags   = (e.tags||[]).map(t=>`<span class="entry-tag">${esc(t)}</span>`).join('');
  return `
  <div class="entry-card" style="animation-delay:${i*0.04}s">
    <div class="entry-main">
      <div class="entry-icon">${(e.site||'?').charAt(0).toUpperCase()}</div>
      <div class="entry-info">
        <div class="entry-site">${esc(e.site)}</div>
        <div class="entry-user">${esc(e.username)}</div>
        ${tags?`<div class="entry-tags">${tags}</div>`:''}
      </div>
      <div class="entry-actions">
        <button class="icon-btn" title="Copy username" onclick="copyField('${e.id}','username')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        </button>
        <button class="icon-btn" title="Edit" onclick="openEdit('${e.id}')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
        <button class="icon-btn del" title="Move to trash" onclick="askTrash('${e.id}','${esc(e.site).replace(/'/g,"\\'")}')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
        </button>
      </div>
    </div>
    <div class="entry-pw-row">
      <span class="pw-display${shown?' visible':''}" id="pw-${e.id}">${shown?esc(e.password):masked}</span>
      <span class="strength-pill ${s.cls}">${s.label}</span>
      <button class="icon-btn" onclick="togglePw('${e.id}')">
        ${shown
          ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
          : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`}
      </button>
      <button class="icon-btn" id="copy-${e.id}" onclick="copyField('${e.id}','password')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
      </button>
    </div>
  </div>`;
}

function renderNoteCard(e, i) {
  const tags = (e.tags||[]).map(t=>`<span class="note-tag">${esc(t)}</span>`).join('');
  return `
  <div class="note-card" style="animation-delay:${i*0.04}s">
    <div class="note-main">
      <div class="note-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
      </div>
      <div class="entry-info">
        <div class="note-title">${esc(e.title||'Untitled Note')}</div>
        <div class="note-preview">${esc(e.body||'')}</div>
        ${tags?`<div class="note-tags">${tags}</div>`:''}
      </div>
      <div class="entry-actions">
        <button class="icon-btn" title="Edit" onclick="openEdit('${e.id}')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
        <button class="icon-btn del" title="Move to trash" onclick="askTrash('${e.id}','${esc(e.title||'Note').replace(/'/g,"\\'")}')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
        </button>
      </div>
    </div>
  </div>`;
}

// ── GENERATOR ──────────────────────────────────────────────
function renderGenerator(wrap) {
  wrap.innerHTML = `
    <div class="section-heading" style="margin-bottom:20px"><h2>Password Generator</h2></div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow-sm);overflow:hidden;">
      <div style="padding:28px 28px 24px;display:flex;flex-direction:column;gap:20px;">
        <div class="gen-output">
          <span class="gen-password" id="gen-pw-display">—</span>
          <div class="gen-actions">
            <button class="icon-btn" title="Regenerate" onclick="generatePassword()">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            </button>
            <button class="icon-btn" id="gen-copy-btn" onclick="copyGenPassword()">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
          </div>
        </div>
        <div class="gen-controls">
          <div class="gen-slider-row">
            <div class="gen-slider-label"><span>Length</span><strong id="gen-len-val">${genOpts.length}</strong></div>
            <input type="range" id="gen-length" min="8" max="40" value="${genOpts.length}"
              oninput="genOpts.length=+this.value;document.getElementById('gen-len-val').textContent=this.value;generatePassword()" />
          </div>
          <div class="gen-checkboxes">
            <div class="gen-check ${genOpts.upper?'on':''}" id="chk-upper" onclick="toggleGenOpt('upper')"><span class="gen-check-dot"></span> A–Z</div>
            <div class="gen-check ${genOpts.lower?'on':''}" id="chk-lower" onclick="toggleGenOpt('lower')"><span class="gen-check-dot"></span> a–z</div>
            <div class="gen-check ${genOpts.nums?'on':''}"  id="chk-nums"  onclick="toggleGenOpt('nums')"><span class="gen-check-dot"></span> 0–9</div>
            <div class="gen-check ${genOpts.syms?'on':''}"  id="chk-syms"  onclick="toggleGenOpt('syms')"><span class="gen-check-dot"></span> !@#</div>
          </div>
        </div>
      </div>
      <div style="border-top:1px solid var(--border);padding:18px 28px;background:var(--accent-bg);display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;">
        <div>
          <div style="font-size:14px;font-weight:600;color:var(--accent);margin-bottom:2px">Like this password?</div>
          <div style="font-size:12px;color:var(--text2)">Save it as a new entry with the password pre-filled.</div>
        </div>
        <button class="btn-primary" onclick="useGeneratedPassword()" style="white-space:nowrap;flex-shrink:0">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px;stroke-width:2.2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Use this password
        </button>
      </div>
    </div>`;
  setTimeout(generatePassword, 50);
}

function generatePassword() {
  const len = parseInt(document.getElementById('gen-length')?.value || genOpts.length);
  let chars = '';
  if (genOpts.upper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (genOpts.lower) chars += 'abcdefghijklmnopqrstuvwxyz';
  if (genOpts.nums)  chars += '0123456789';
  if (genOpts.syms)  chars += '!@#$%^&*()-_=+[]{}|;:,.<>?';
  if (!chars) return;
  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  const pw = Array.from(arr).map(n => chars[n % chars.length]).join('');
  const el = document.getElementById('gen-pw-display');
  if (el) el.textContent = pw;
  return pw;
}

function toggleGenOpt(key) {
  const onCount = ['upper','lower','nums','syms'].filter(k => genOpts[k]).length;
  if (genOpts[key] && onCount === 1) { showToast('At least one option required'); return; }
  genOpts[key] = !genOpts[key];
  document.getElementById('chk-'+key).classList.toggle('on', genOpts[key]);
  generatePassword();
}

function copyGenPassword() {
  const pw = document.getElementById('gen-pw-display')?.textContent;
  if (!pw || pw === '—') return;
  navigator.clipboard.writeText(pw).then(() => {
    const btn = document.getElementById('gen-copy-btn');
    if (btn) { btn.classList.add('copied'); setTimeout(() => btn.classList.remove('copied'), 1500); }
    showToast('Password copied');
  });
}

function useGeneratedPassword() {
  const pw = document.getElementById('gen-pw-display')?.textContent;
  if (!pw || pw === '—') { showToast('Generate a password first'); return; }
  activeView = 'all'; renderSidebar(); renderMain();
  setTimeout(() => {
    openModal('password');
    setTimeout(() => {
      const inp = document.getElementById('f-pw');
      if (inp) { inp.value = pw; inp.type = 'text'; updateStrength(); }
    }, 80);
  }, 50);
}

// ── HEALTH ─────────────────────────────────────────────────
function renderHealth(wrap) {
  const pw = entries.filter(e => e.type !== 'note');
  const weak   = pw.filter(e => getStrength(e.password).cls === 'weak');
  const medium = pw.filter(e => getStrength(e.password).cls === 'medium');
  const pwMap  = {};
  pw.forEach(e => { pwMap[e.password] = pwMap[e.password] || []; pwMap[e.password].push(e); });
  const reused = Object.values(pwMap).filter(g => g.length > 1).flat();
  const score  = pw.length === 0 ? 100
    : Math.max(0, Math.round(100 - weak.length*20 - reused.length*10 - medium.length*5));
  const scoreColor = score >= 80 ? 'var(--success)' : score >= 50 ? 'var(--warn)' : 'var(--danger)';
  const scoreLabel = score >= 80 ? 'Good' : score >= 50 ? 'Fair' : 'Needs work';

  const issueCard = (e) => `
    <div class="entry-card" style="animation-delay:0s">
      <div class="entry-main">
        <div class="entry-icon">${(e.site||'?').charAt(0).toUpperCase()}</div>
        <div class="entry-info"><div class="entry-site">${esc(e.site)}</div><div class="entry-user">${esc(e.username)}</div></div>
        <div class="entry-actions">
          <button class="icon-btn" title="Fix" onclick="openEdit('${e.id}')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          </button>
        </div>
      </div>
    </div>`;

  wrap.innerHTML = `
    <div class="section-heading" style="margin-bottom:20px">
      <h2>Password Health</h2>
      <span class="sub" style="font-size:14px;font-weight:600;color:${scoreColor}">${scoreLabel} · ${score}/100</span>
    </div>
    <div class="health-grid">
      <div class="health-card ${weak.length?'danger':'success'}">
        <div class="health-card-num" style="color:${weak.length?'var(--danger)':'var(--success)'}">${weak.length}</div>
        <div class="health-card-label">Weak</div><div class="health-card-sub">Should be fixed</div>
      </div>
      <div class="health-card ${reused.length?'warn':'success'}">
        <div class="health-card-num" style="color:${reused.length?'var(--warn)':'var(--success)'}">${reused.length}</div>
        <div class="health-card-label">Reused</div><div class="health-card-sub">Used on multiple sites</div>
      </div>
      <div class="health-card ${medium.length?'warn':'success'}">
        <div class="health-card-num" style="color:${medium.length?'var(--warn)':'var(--success)'}">${medium.length}</div>
        <div class="health-card-label">Medium</div><div class="health-card-sub">Could be stronger</div>
      </div>
    </div>
    ${weak.length ? `<div class="health-section-title" style="color:var(--danger)">⚠ Weak passwords</div><div class="entries">${weak.map(issueCard).join('')}</div>` : ''}
    ${reused.length ? `<div class="health-section-title" style="color:var(--warn)">↺ Reused passwords</div><div class="entries">${reused.map(issueCard).join('')}</div>` : ''}
    ${!weak.length && !reused.length ? `<div class="empty-state" style="padding:48px 24px">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" style="color:var(--success);opacity:0.6"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
      <p>All passwords look good!</p>
    </div>` : ''}
  `;
}

// ── TRASH VIEW ─────────────────────────────────────────────
function renderTrash(wrap, q) {
  const filtered = trashItems.filter(e => {
    const name = e.type === 'note' ? (e.title||'') : (e.site||'');
    return name.toLowerCase().includes(q);
  });

  const emptyBtn = trashItems.length ? `
    <div class="trash-actions">
      <button class="btn-ghost-danger" onclick="askEmptyTrash()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
        Empty Trash
      </button>
    </div>` : '';

  if (!filtered.length) {
    wrap.innerHTML = `<div class="section-heading"><h2>Trash</h2></div>${emptyBtn}
      <div class="entries"><div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
        <p>Trash is empty.</p>
      </div></div>`;
    return;
  }

  wrap.innerHTML = `
    <div class="section-heading"><h2>Trash</h2><span class="sub">${filtered.length} item${filtered.length!==1?'s':''} · auto-deleted after 30 days</span></div>
    ${emptyBtn}
    <div class="entries">${filtered.map((e,i) => {
      const name = e.type==='note' ? (e.title||'Untitled Note') : e.site;
      const sub  = e.type==='note' ? (e.body||'').slice(0,60) : (e.username||'');
      const daysLeft = Math.max(0, Math.ceil((e.deletedAt + 30*24*60*60*1000 - Date.now()) / (24*60*60*1000)));
      return `
      <div class="entry-card" style="animation-delay:${i*0.04}s;opacity:0.8">
        <div class="entry-main">
          <div class="entry-icon" style="opacity:0.5">${(name||'?').charAt(0).toUpperCase()}</div>
          <div class="entry-info"><div class="entry-site" style="color:var(--text2)">${esc(name)}</div><div class="entry-user">${esc(sub)}</div></div>
          <div class="entry-actions">
            <button class="icon-btn restore" onclick="restoreEntry('${e.id}')">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.07"/></svg>
            </button>
            <button class="icon-btn del" onclick="askPermDelete('${e.id}','${esc(name).replace(/'/g,"\\'")}')">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
        </div>
        <div class="trash-meta">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          <span>Deleted · <span class="trash-expire">${daysLeft} day${daysLeft!==1?'s':''} left</span></span>
        </div>
      </div>`;
    }).join('')}</div>`;
}

// ── COPY / TOGGLE ──────────────────────────────────────────
function copyField(id, field) {
  const e = entries.find(x => x.id === id);
  if (!e) return;
  const val = field === 'password' ? e.password : e.username;
  navigator.clipboard.writeText(val||'').then(() => {
    if (field === 'password') {
      const btn = document.getElementById('copy-'+id);
      if (btn) { btn.classList.add('copied'); setTimeout(() => btn.classList.remove('copied'), 1500); }
    }
    showToast(field === 'password' ? 'Password copied' : 'Username copied');
  });
}

function togglePw(id) { shownPasswords[id] = !shownPasswords[id]; renderMain(); }

// ── MODAL ──────────────────────────────────────────────────
function openModal(type) {
  editId = null; modalType = type; selectedTags = [];
  document.getElementById('modal-title').textContent = type==='note' ? 'New Secure Note' : 'New Entry';
  buildModalBody(type);
  document.getElementById('modal-overlay').classList.add('open');
  setTimeout(() => document.querySelector('#modal-body input, #modal-body textarea')?.focus(), 150);
}

function openEdit(id) {
  const e = entries.find(x => x.id === id);
  if (!e) return;
  editId = id; modalType = e.type==='note' ? 'note' : 'password';
  selectedTags = [...(e.tags||[])];
  document.getElementById('modal-title').textContent = e.type==='note' ? 'Edit Note' : 'Edit Entry';
  buildModalBody(modalType, e);
  document.getElementById('modal-overlay').classList.add('open');
  setTimeout(() => document.querySelector('#modal-body input, #modal-body textarea')?.focus(), 150);
}

function buildModalBody(type, e) {
  const body     = document.getElementById('modal-body');
  const titleVal = e&&e.type==='note' ? esc(e.title||'') : '';
  const bodyVal  = e&&e.type==='note' ? esc(e.body||'')  : '';
  const siteVal  = e&&e.type!=='note' ? esc(e.site||'')     : '';
  const userVal  = e&&e.type!=='note' ? esc(e.username||'') : '';
  const pwVal    = e&&e.type!=='note' ? esc(e.password||'') : '';

  body.innerHTML = `
    <div class="type-switcher">
      <button class="type-btn ${type==='password'?'active':''}" id="btn-pw" onclick="switchModalType('password')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3"/></svg>
        Password
      </button>
      <button class="type-btn ${type==='note'?'active':''}" id="btn-note" onclick="switchModalType('note')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
        Secure Note
      </button>
    </div>
    <div class="modal-divider"></div>
    <div class="panel ${type==='password'?'':'hidden'}" id="panel-password">
      <div class="field"><label>Website / App</label><input id="f-site" type="text" placeholder="e.g. GitHub, Netflix…" value="${siteVal}" /></div>
      <div class="field"><label>Username or Email</label><input id="f-user" type="text" placeholder="username@example.com" value="${userVal}" /></div>
      <div class="field">
        <label>Password</label>
        <div class="pw-input-wrap">
          <input id="f-pw" type="password" placeholder="Enter password" oninput="updateModalStrength()" style="padding-right:72px" />
          <button class="pw-toggle" type="button" onclick="toggleModalPw()" style="right:36px">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
          <button class="pw-toggle" type="button" onclick="fillGeneratedPw()" title="Generate password" style="right:8px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
          </button>
        </div>
        <div class="strength-bar-wrap"><div class="strength-bar"><div class="strength-fill" id="str-fill"></div></div><span class="strength-label" id="str-label">—</span></div>
      </div>
    </div>
    <div class="panel ${type==='note'?'':'hidden'}" id="panel-note">
      <div class="field"><label>Title</label><input id="f-title" type="text" placeholder="e.g. WiFi Password, License Key…" value="${titleVal}" /></div>
      <div class="field"><label>Note</label><textarea id="f-body" rows="5" placeholder="Your secure note content…">${bodyVal}</textarea></div>
    </div>
    <div class="modal-divider"></div>
    <div class="field">
      <label>Tags <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--text3);font-size:11px;">— optional</span></label>
      <div class="tag-picker">
        <div class="tag-chips" id="tag-chips"></div>
        <div class="tag-new-row">
          <input id="new-tag-input" type="text" placeholder="Type to create or pick a tag…"
            oninput="filterTagSuggestions(this.value)"
            onkeydown="if(event.key==='Enter'){addTagFromInput();event.preventDefault();}" />
          <button onclick="addTagFromInput()">Add</button>
        </div>
      </div>
    </div>`;
  renderTagChips();
  if (type==='password' && e) setTimeout(updateStrength, 0);
}

function switchModalType(type) {
  modalType = type;
  document.getElementById('btn-pw').classList.toggle('active', type==='password');
  document.getElementById('btn-note').classList.toggle('active', type==='note');
  document.getElementById('panel-password').classList.toggle('hidden', type!=='password');
  document.getElementById('panel-note').classList.toggle('hidden', type!=='note');
  const titles = { password: editId?'Edit Entry':'New Entry', note: editId?'Edit Note':'New Secure Note' };
  document.getElementById('modal-title').textContent = titles[type]||'New Entry';
}

function updateStrength() {
  const pw = document.getElementById('f-pw')?.value || '';
  const s  = getStrength(pw);
  const fill = document.getElementById('str-fill');
  const lbl  = document.getElementById('str-label');
  if (fill) fill.style.cssText = `width:${s.score}%;background:${s.color}`;
  if (lbl)  { lbl.textContent = s.label; lbl.style.color = s.color||'var(--text3)'; }
}

function toggleModalPw() {
  const inp = document.getElementById('f-pw');
  if (inp) inp.type = inp.type === 'password' ? 'text' : 'password';
}

function closeModal() { document.getElementById('modal-overlay').classList.remove('open'); }
function handleOverlayClick(ev) { if (ev.target.id === 'modal-overlay') closeModal(); }

async function saveEntry() {
  const tags = [...selectedTags];
  let plainObj;

  if (modalType === 'note') {
    const title = document.getElementById('f-title')?.value.trim() || '';
    const body  = document.getElementById('f-body')?.value.trim() || '';
    if (!title) { showToast('Please add a title'); return; }
    plainObj = { id: editId||uid(), type:'note', title, body, tags };
  } else {
    const site     = document.getElementById('f-site')?.value.trim() || '';
    const username = document.getElementById('f-user')?.value.trim() || '';
    const password = document.getElementById('f-pw')?.value || '';
    if (!site||!username||!password) { showToast('Please fill in all fields'); return; }
    plainObj = { id: editId||uid(), type:'password', site, username, password, tags };
  }

  try {
    const ciphertext = await Crypto.encrypt(encKey, plainObj);

    if (editId) {
      await API.entries.update(plainObj.id, ciphertext);
      entries = entries.map(e => e.id === editId ? {...plainObj, _dbId: e._dbId} : e);
      showToast(modalType==='note' ? 'Note updated' : 'Entry updated');
    } else {
      const row = await API.entries.create(plainObj.id, plainObj.type, ciphertext);
      entries.push({ ...plainObj, _dbId: row.id });
      showToast(modalType==='note' ? 'Note saved' : 'Entry added');
    }

    closeModal(); renderSidebar(); renderMain();
  } catch (err) {
    showToast('Failed to save: ' + err.message);
  }
}

// ── TAGS ───────────────────────────────────────────────────
function filterTagSuggestions(val) { renderTagChips(val.toLowerCase()); }

function renderTagChips(filter) {
  const el = document.getElementById('tag-chips');
  if (!el) return;
  const visible = filter ? allTags.filter(t => t.name.toLowerCase().includes(filter)) : allTags;
  if (!visible.length && !filter) {
    el.innerHTML = '<span style="font-size:12px;color:var(--text3)">No tags yet — type below to create one</span>';
    return;
  }
  el.innerHTML = visible.map(t => `
    <div class="tag-chip ${selectedTags.includes(t.name)?'selected':''}" onclick="toggleTag('${esc(t.name)}')">
      ${esc(t.name)}${selectedTags.includes(t.name)?' <span class="chip-x">×</span>':''}
    </div>`).join('');
}

function toggleTag(name) {
  selectedTags = selectedTags.includes(name)
    ? selectedTags.filter(x => x !== name)
    : [...selectedTags, name];
  renderTagChips();
}

async function addTagFromInput() {
  const inp = document.getElementById('new-tag-input');
  const name = inp.value.trim();
  if (!name) return;
  try {
    if (!allTags.find(t => t.name === name)) {
      const tag = await API.tags.create(name);
      allTags.push(tag);
      renderSidebar();
    }
    if (!selectedTags.includes(name)) selectedTags.push(name);
    inp.value = '';
    renderTagChips();
  } catch (err) {
    showToast('Could not create tag: ' + err.message);
  }
}

function toggleSidebarTagInput() {
  const wrap = document.getElementById('sidebar-tag-input-wrap');
  if (!wrap) return;
  const isOpen = wrap.style.display !== 'none';
  wrap.style.display = isOpen ? 'none' : '';
  if (!isOpen) setTimeout(() => document.getElementById('sidebar-tag-input')?.focus(), 50);
}

async function createSidebarTag() {
  const inp = document.getElementById('sidebar-tag-input');
  const name = inp?.value.trim();
  if (!name) return;
  try {
    if (!allTags.find(t => t.name === name)) {
      const tag = await API.tags.create(name);
      allTags.push(tag);
    }
    inp.value = '';
    renderSidebar();
    showToast(`Tag "${name}" created`);
  } catch (err) {
    showToast('Could not create tag: ' + err.message);
  }
}

async function deleteTag(id, name) {
  // If currently viewing this tag, switch to all
  if (activeView === name) activeView = 'all';
  try {
    await API.tags.remove(id);
    allTags = allTags.filter(t => t.id !== id);
    // Remove tag from all entries in memory (no re-encrypt needed for display)
    entries = entries.map(e => ({
      ...e,
      tags: (e.tags||[]).filter(t => t !== name)
    }));
    renderSidebar();
    renderMain();
    showToast(`Tag "${name}" deleted`);
  } catch (err) {
    showToast('Could not delete tag: ' + err.message);
  }
}

// ── TRASH ACTIONS ──────────────────────────────────────────
function askTrash(id, name) {
  confirmCallback = () => moveToTrash(id);
  document.getElementById('confirm-title').textContent = 'Move to trash?';
  document.getElementById('confirm-body').textContent = `"${name}" will be moved to trash. You can restore it within 30 days.`;
  document.getElementById('confirm-action-btn').textContent = 'Move to Trash';
  document.getElementById('confirm-overlay').classList.add('open');
}

function askPermDelete(id, name) {
  confirmCallback = () => permDelete(id);
  document.getElementById('confirm-title').textContent = 'Delete permanently?';
  document.getElementById('confirm-body').textContent = `"${name}" will be permanently deleted.`;
  document.getElementById('confirm-action-btn').textContent = 'Delete Forever';
  document.getElementById('confirm-overlay').classList.add('open');
}

function askEmptyTrash() {
  confirmCallback = async () => {
    try {
      await API.trash.empty();
      trashItems = [];
      renderSidebar(); renderMain(); showToast('Trash emptied');
    } catch (err) { showToast(err.message); }
  };
  document.getElementById('confirm-title').textContent = 'Empty trash?';
  document.getElementById('confirm-body').textContent = `All ${trashItems.length} item${trashItems.length!==1?'s':''} will be permanently deleted.`;
  document.getElementById('confirm-action-btn').textContent = 'Empty Trash';
  document.getElementById('confirm-overlay').classList.add('open');
}

async function moveToTrash(id) {
  try {
    await API.entries.remove(id);
    const e = entries.find(x => x.id === id);
    if (e) trashItems.push({ ...e, deletedAt: Date.now() });
    entries = entries.filter(x => x.id !== id);
    renderSidebar(); renderMain(); showToast('Moved to trash');
  } catch (err) { showToast(err.message); }
}

async function permDelete(id) {
  try {
    await API.trash.remove(id);
    trashItems = trashItems.filter(x => x.id !== id);
    renderSidebar(); renderMain(); showToast('Permanently deleted');
  } catch (err) { showToast(err.message); }
}

async function restoreEntry(id) {
  try {
    await API.trash.restore(id);
    const e = trashItems.find(x => x.id === id);
    if (e) { const { deletedAt, ...restored } = e; entries.push(restored); }
    trashItems = trashItems.filter(x => x.id !== id);
    renderSidebar(); renderMain(); showToast('Entry restored');
  } catch (err) { showToast(err.message); }
}

function closeConfirm() { document.getElementById('confirm-overlay').classList.remove('open'); confirmCallback = null; }
function confirmAction() { if (confirmCallback) confirmCallback(); closeConfirm(); }


// ── TOAST & UTILS ──────────────────────────────────────────
let toastTimer;
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2400);
}

function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2); }
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

document.addEventListener('keydown', ev => { if (ev.key === 'Escape') { closeModal(); closeConfirm(); } });


function fillGeneratedPw() {
  const pw = generatePassword(genOpts);
  const input = document.getElementById('f-pw');
  if (!input) return;
  input.value = pw;
  input.type = 'text';
  updateModalStrength();
  showToast('Password generated!');
}
