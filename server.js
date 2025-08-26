
import fs from 'fs';
import path from 'path';
import express from 'express';
import session from 'express-session';
import SQLiteStoreFactory from 'connect-sqlite3';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: { origin: "*" }
});

app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json());
app.use(cookieParser());

const SQLiteStore = SQLiteStoreFactory(session);

const DB_FILE = path.join(__dirname, 'data.db');
const db = await open({ filename: DB_FILE, driver: sqlite3.Database });

// Initialize tables
await db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  points INTEGER NOT NULL DEFAULT 100,
  opened INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS collectibles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  rarity TEXT NOT NULL CHECK (rarity IN ('common','uncommon','rare','epic','legendary')),
  base_value INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_collectibles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  collectible_id INTEGER NOT NULL,
  quantity INTEGER NOT NULL DEFAULT 0,
  UNIQUE(user_id, collectible_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(collectible_id) REFERENCES collectibles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS trades (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_user_id INTEGER NOT NULL,
  to_user_id INTEGER NOT NULL,
  offer_json TEXT NOT NULL,
  request_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open', -- open, accepted, declined, canceled
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(from_user_id) REFERENCES users(id),
  FOREIGN KEY(to_user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chat_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

// Seed collectibles if empty
const row = await db.get('SELECT COUNT(*) as c FROM collectibles');
if (row.c === 0) {
  const items = [
    ['Pebble', 'common', 1],
    ['Rusty Coin', 'common', 2],
    ['Leaf Badge', 'uncommon', 5],
    ['Glowing Shard', 'uncommon', 8],
    ['Crystal Chunk', 'rare', 15],
    ['Ancient Relic', 'epic', 30],
    ['Dragon Sigil', 'legendary', 100]
  ];
  const stmt = await db.prepare('INSERT INTO collectibles(name, rarity, base_value) VALUES (?, ?, ?)');
  for (const [n, r, v] of items) await stmt.run(n, r, v);
  await stmt.finalize();
}

const sess = session({
  store: new SQLiteStore({ db: 'sessions.db', dir: __dirname }),
  secret: process.env.SESSION_SECRET || 'dev_secret_change_me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    httpOnly: true,
    sameSite: 'lax',
    secure: false
  }
});

app.use(sess);

function requireAuth(req, res, next) {
  if (req.session?.userId) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

// Static files (protect everything except welcome + assets)
app.use((req, res, next) => {
  const openPaths = ['/welcome.html','/css/','/js/','/api/auth/login','/api/auth/signup','/'];
  if (openPaths.some(p => req.path.startsWith(p))) return next();
  if (req.session?.userId) return next();
  res.redirect('/welcome.html');
});
app.use(express.static(path.join(__dirname, 'public')));

// Auth routes
app.post('/api/auth/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: 'Invalid username' });
  const hash = await bcrypt.hash(password, 10);
  try {
    const result = await db.run('INSERT INTO users(username, password_hash) VALUES (?,?)', username, hash);
    req.session.userId = result.lastID;
    req.session.username = username;
    res.json({ ok: true, userId: result.lastID, username });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Username taken' });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.get('SELECT * FROM users WHERE username=?', username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ ok: true, userId: user.id, username: user.username });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const u = await db.get('SELECT id, username, points, opened, created_at FROM users WHERE id=?', req.session.userId);
  res.json(u);
});

// Stats + inventory
app.get('/api/stats', requireAuth, async (req, res) => {
  const u = await db.get('SELECT id, username, points, opened, created_at FROM users WHERE id=?', req.session.userId);
  const inv = await db.all(`
    SELECT c.id, c.name, c.rarity, c.base_value, uc.quantity
    FROM user_collectibles uc
    JOIN collectibles c ON uc.collectible_id = c.id
    WHERE uc.user_id=?
    ORDER BY 
      CASE c.rarity
        WHEN 'legendary' THEN 1
        WHEN 'epic' THEN 2
        WHEN 'rare' THEN 3
        WHEN 'uncommon' THEN 4
        ELSE 5
      END, c.name ASC
  `, req.session.userId);
  res.json({ user: u, inventory: inv });
});

// Leaderboard
app.get('/api/leaderboard', async (req, res) => {
  const top = await db.all('SELECT username, points, opened FROM users ORDER BY points DESC, opened DESC LIMIT 50');
  res.json(top);
});

// RNG Open Box
const BOX_COST = 10;
const WEIGHTS = { common: 60, uncommon: 25, rare: 10, epic: 4, legendary: 1 };

function weightedPick(weights) {
  const total = Object.values(weights).reduce((a,b)=>a+b,0);
  let r = Math.random() * total;
  for (const [k, w] of Object.entries(weights)) {
    if (r < w) return k;
    r -= w;
  }
  return 'common';
}

app.post('/api/rng/open', requireAuth, async (req, res) => {
  const user = await db.get('SELECT * FROM users WHERE id=?', req.session.userId);
  if (user.points < BOX_COST) return res.status(400).json({ error: 'Not enough points' });
  const rarity = weightedPick(WEIGHTS);
  const item = await db.get('SELECT * FROM collectibles WHERE rarity=? ORDER BY RANDOM() LIMIT 1', rarity);
  await db.run('UPDATE users SET points=points-?, opened=opened+1 WHERE id=?', BOX_COST, user.id);
  const existing = await db.get('SELECT * FROM user_collectibles WHERE user_id=? AND collectible_id=?', user.id, item.id);
  if (existing) {
    await db.run('UPDATE user_collectibles SET quantity=quantity+1 WHERE id=?', existing.id);
  } else {
    await db.run('INSERT INTO user_collectibles(user_id, collectible_id, quantity) VALUES (?,?,1)', user.id, item.id);
  }
  res.json({ ok: true, rarity, item });
});

// Trades
app.get('/api/trades', requireAuth, async (req, res) => {
  const rows = await db.all(`
    SELECT t.*, u1.username as from_user, u2.username as to_user
    FROM trades t
    JOIN users u1 ON u1.id = t.from_user_id
    JOIN users u2 ON u2.id = t.to_user_id
    WHERE (from_user_id=? OR to_user_id=?) AND status='open'
    ORDER BY t.created_at DESC`, req.session.userId, req.session.userId);
  res.json(rows);
});

app.post('/api/trades/create', requireAuth, async (req, res) => {
  const { toUsername, offer, request } = req.body; // arrays of {collectible_id, quantity}
  const toUser = await db.get('SELECT id FROM users WHERE username=?', toUsername);
  if (!toUser) return res.status(404).json({ error: 'Recipient not found' });
  // Basic validation user has offered quantities
  for (const o of (offer || [])) {
    const inv = await db.get('SELECT quantity FROM user_collectibles WHERE user_id=? AND collectible_id=?', req.session.userId, o.collectible_id);
    if (!inv || inv.quantity < o.quantity) return res.status(400).json({ error: 'Insufficient items to offer' });
  }
  const result = await db.run('INSERT INTO trades(from_user_id, to_user_id, offer_json, request_json) VALUES (?,?,?,?)',
    req.session.userId, toUser.id, JSON.stringify(offer || []), JSON.stringify(request || []));
  io.to('user:' + toUser.id).emit('trade:new', { id: result.lastID });
  res.json({ ok: true, id: result.lastID });
});

app.post('/api/trades/accept', requireAuth, async (req, res) => {
  const { tradeId } = req.body;
  const t = await db.get('SELECT * FROM trades WHERE id=?', tradeId);
  if (!t || t.to_user_id !== req.session.userId || t.status !== 'open') {
    return res.status(400).json({ error: 'Invalid trade' });
  }
  const offer = JSON.parse(t.offer_json);
  const request = JSON.parse(t.request_json);

  // Verify ownership
  for (const o of offer) {
    const inv = await db.get('SELECT quantity FROM user_collectibles WHERE user_id=? AND collectible_id=?', t.from_user_id, o.collectible_id);
    if (!inv || inv.quantity < o.quantity) return res.status(400).json({ error: 'Offer no longer valid' });
  }
  for (const r of request) {
    const inv = await db.get('SELECT quantity FROM user_collectibles WHERE user_id=? AND collectible_id=?', t.to_user_id, r.collectible_id);
    if (!inv || inv.quantity < r.quantity) return res.status(400).json({ error: 'You no longer have required items' });
  }

  // Transfer items
  async function transfer(from, to, itemId, qty) {
    const fromInv = await db.get('SELECT * FROM user_collectibles WHERE user_id=? AND collectible_id=?', from, itemId);
    if (!fromInv || fromInv.quantity < qty) throw new Error('Transfer error');
    await db.run('UPDATE user_collectibles SET quantity=quantity-? WHERE id=?', qty, fromInv.id);
    const toInv = await db.get('SELECT * FROM user_collectibles WHERE user_id=? AND collectible_id=?', to, itemId);
    if (toInv) {
      await db.run('UPDATE user_collectibles SET quantity=quantity+? WHERE id=?', qty, toInv.id);
    } else {
      await db.run('INSERT INTO user_collectibles(user_id, collectible_id, quantity) VALUES (?,?,?)', to, itemId, qty);
    }
  }

  for (const o of offer) await transfer(t.from_user_id, t.to_user_id, o.collectible_id, o.quantity);
  for (const r of request) await transfer(t.to_user_id, t.from_user_id, r.collectible_id, r.quantity);

  await db.run('UPDATE trades SET status="accepted" WHERE id=?', tradeId);
  io.to('user:' + t.from_user_id).emit('trade:update', { id: tradeId, status: 'accepted' });
  io.to('user:' + t.to_user_id).emit('trade:update', { id: tradeId, status: 'accepted' });

  res.json({ ok: true });
});

app.post('/api/trades/decline', requireAuth, async (req, res) => {
  const { tradeId } = req.body;
  const t = await db.get('SELECT * FROM trades WHERE id=?', tradeId);
  if (!t || t.to_user_id !== req.session.userId || t.status !== 'open') {
    return res.status(400).json({ error: 'Invalid trade' });
  }
  await db.run('UPDATE trades SET status="declined" WHERE id=?', tradeId);
  res.json({ ok: true });
});

// Chat via socket.io
io.use((socket, next) => {
  const userId = socket.handshake.auth?.userId;
  const username = socket.handshake.auth?.username;
  if (!userId || !username) return next(new Error('unauthorized'));
  socket.userId = userId;
  socket.username = username;
  next();
});

io.on('connection', (socket) => {
  socket.join('global');
  socket.join('user:' + socket.userId);

  socket.on('chat:message', async (msg) => {
    const trimmed = String(msg || '').slice(0, 400);
    await db.run('INSERT INTO chat_messages(user_id, message) VALUES (?,?)', socket.userId, trimmed);
    io.to('global').emit('chat:message', { from: socket.username, message: trimmed, ts: Date.now() });
  });

  socket.on('disconnect', () => {});
});

// Fallback home redirect
app.get('/', (req, res) => {
  if (req.session?.userId) res.redirect('/home.html');
  else res.redirect('/welcome.html');
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
