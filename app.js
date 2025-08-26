
async function api(url, options={}) {
  const opts = { headers: { 'Content-Type': 'application/json' }, credentials: 'include', ...options };
  if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
  const res = await fetch(url, opts);
  if (!res.ok) {
    let msg = 'Error ' + res.status;
    try { const j = await res.json(); if (j.error) msg = j.error; } catch {}
    throw new Error(msg);
  }
  return res.json();
}

document.getElementById('logout')?.addEventListener('click', async (e) => {
  e.preventDefault();
  try { await api('/api/auth/logout', { method: 'POST' }); } catch {}
  location.href = '/welcome.html';
});

(async () => {
  const nameEl = document.getElementById('username');
  if (nameEl) {
    try {
      const me = await api('/api/me');
      nameEl.textContent = me.username;
    } catch (e) {
      location.href = '/welcome.html';
    }
  }
})();
