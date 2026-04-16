// ============================================================
// KeyNest — API Client
// All communication with the PHP backend goes through here.
// app.js never calls fetch() directly.
// ============================================================

const API = (() => {

  const BASE = './api';

  async function request(url, options = {}) {
    const res = await fetch(url, {
      credentials: 'same-origin',    // send PHP session cookie
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options,
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || `Request failed (${res.status})`);
    }

    return data;
  }

  // ── AUTH ──────────────────────────────────────────────────

  const auth = {
    async register(email, password) {
      return request(`${BASE}/auth.php?action=register`, {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
    },

    async login(email, password) {
      return request(`${BASE}/auth.php?action=login`, {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
    },

    async logout() {
      return request(`${BASE}/auth.php?action=logout`, { method: 'POST' });
    },

    async check() {
      return request(`${BASE}/auth.php?action=check`);
    },
  };

  // ── ENTRIES ───────────────────────────────────────────────

  const entries = {
    async list() {
      return request(`${BASE}/entries.php?resource=entries`);
    },

    async create(id, type, ciphertext) {
      return request(`${BASE}/entries.php?resource=entries`, {
        method: 'POST',
        body: JSON.stringify({ id, type, ciphertext }),
      });
    },

    async update(id, ciphertext) {
      return request(`${BASE}/entries.php?resource=entries&id=${id}`, {
        method: 'PUT',
        body: JSON.stringify({ ciphertext }),
      });
    },

    async remove(id) {
      return request(`${BASE}/entries.php?resource=entries&id=${id}`, {
        method: 'DELETE',
      });
    },
  };

  // ── TRASH ──────────────────────────────────────────────────

  const trash = {
    async list() {
      return request(`${BASE}/entries.php?resource=trash`);
    },

    async restore(id) {
      return request(`${BASE}/entries.php?resource=trash&id=${id}`, {
        method: 'POST',
      });
    },

    async remove(id) {
      return request(`${BASE}/entries.php?resource=trash&id=${id}`, {
        method: 'DELETE',
      });
    },

    async empty() {
      return request(`${BASE}/entries.php?resource=trash`, {
        method: 'DELETE',
      });
    },
  };

  // ── TAGS ───────────────────────────────────────────────────

  const tags = {
    async list() {
      return request(`${BASE}/entries.php?resource=tags`);
    },

    async create(name) {
      return request(`${BASE}/entries.php?resource=tags`, {
        method: 'POST',
        body: JSON.stringify({ name }),
      });
    },

    async remove(id) {
      return request(`${BASE}/entries.php?resource=tags&id=${id}`, {
        method: 'DELETE',
      });
    },
  };

  return { auth, entries, trash, tags };

})();
