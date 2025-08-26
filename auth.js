
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

document.getElementById('do-signup')?.addEventListener('click', async () => {
  const username = document.getElementById('su-user').value.trim();
  const password = document.getElementById('su-pass').value;
  const msg = document.getElementById('su-msg');
  try {
    await api('/api/auth/signup', { method:'POST', body:{ username, password } });
    location.href = '/home.html';
  } catch (e) {
    msg.textContent = e.message;
  }
});

document.getElementById('do-login')?.addEventListener('click', async () => {
  const username = document.getElementById('li-user').value.trim();
  const password = document.getElementById('li-pass').value;
  const msg = document.getElementById('li-msg');
  try {
    await api('/api/auth/login', { method:'POST', body:{ username, password } });
    location.href = '/home.html';
  } catch (e) {
    msg.textContent = e.message;
  }
});
