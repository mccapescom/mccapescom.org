/*
--- Endpoints overview ---
* Public
  GET  /offers                 - list public offers
  GET  /offers/:id             - get a single offer
* Auth (provide `Authorization: Bearer <token>`)
  POST /auth/register          - { username, password }
  POST /auth/login             - { username, password } -> { token }
  GET  /accounts/me            - returns user profile
  PUT  /accounts/me            - update profile
  POST /offers                 - create new offer
  PUT  /offers/:id             - update offer (owner or admin)
  DELETE /offers/:id          - delete offer (owner or admin)
  POST /admin/promote         - promote user to admin (admin only)
*/

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const DB_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const DB_PATH = path.join(DB_DIR, 'db.sqlite');

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) throw err;
  console.log('Connected to SQLite DB at', DB_PATH);
});

// Create tables if they don't exist
const initSql = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  is_admin INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS offers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  image TEXT,
  type TEXT CHECK(type IN ('sell','trade')) DEFAULT 'sell',
  official INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);
`;

db.exec(initSql, (err) => {
  if (err) console.error('Failed to initialize DB:', err);
});

const app = express();
app.use(helmet());
app.use(express.json({ limit: '200kb' }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use(apiLimiter);

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const TOKEN_EXPIRES_IN = process.env.TOKEN_EXPIRES_IN || '7d';

// Helper: run SQL with Promise
function runSql(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
function getSql(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}
function allSql(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

// Auth helpers
async function createUser(username, password, display_name = null) {
  const password_hash = await bcrypt.hash(password, 10);
  const res = await runSql('INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)', [username, password_hash, display_name]);
  return res.lastID;
}

async function verifyUser(username, password) {
  const user = await getSql('SELECT * FROM users WHERE username = ?', [username]);
  if (!user) return null;
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return null;
  delete user.password_hash;
  return user;
}

function signToken(user) {
  const payload = { id: user.id, username: user.username, is_admin: !!user.is_admin };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRES_IN });
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing Authorization header' });
  const token = h.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // id, username, is_admin
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ---------- AUTH ROUTES ----------
app.post('/auth/register', async (req, res) => {
  try {
    const { username, password, display_name } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    const exists = await getSql('SELECT id FROM users WHERE username = ?', [username]);
    if (exists) return res.status(409).json({ error: 'username already exists' });
    const id = await createUser(username, password, display_name || null);
    const user = await getSql('SELECT id, username, display_name, is_admin FROM users WHERE id = ?', [id]);
    const token = signToken(user);
    res.json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    const user = await verifyUser(username, password);
    if (!user) return res.status(401).json({ error: 'invalid credentials' });
    const token = signToken(user);
    res.json({ token, user: { id: user.id, username: user.username, display_name: user.display_name, is_admin: !!user.is_admin } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// ---------- OFFERS (public load) ----------
// Public list (with optional query params)
app.get('/offers', async (req, res) => {
  try {
    // Support filtering and paging
    const { q, type, official, limit = 50, offset = 0 } = req.query;
    let sql = 'SELECT o.id, o.name, o.description, o.image, o.type, o.official, o.created_at, o.updated_at, u.id AS owner_id, u.username AS owner_username, u.display_name AS owner_display_name FROM offers o JOIN users u ON o.owner_id = u.id';
    const where = [];
    const params = [];
    if (q) { where.push('(o.name LIKE ? OR o.description LIKE ?)'); params.push(`%${q}%`); params.push(`%${q}%`); }
    if (type) { where.push('o.type = ?'); params.push(type); }
    if (official !== undefined) { where.push('o.official = ?'); params.push(official ? 1 : 0); }
    if (where.length) sql += ' WHERE ' + where.join(' AND ');
    sql += ' ORDER BY o.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit)); params.push(parseInt(offset));
    const rows = await allSql(sql, params);
    res.json({ offers: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

app.get('/offers/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const row = await getSql('SELECT o.id, o.name, o.description, o.image, o.type, o.official, o.created_at, o.updated_at, u.id AS owner_id, u.username AS owner_username, u.display_name AS owner_display_name FROM offers o JOIN users u ON o.owner_id = u.id WHERE o.id = ?', [id]);
    if (!row) return res.status(404).json({ error: 'not found' });
    res.json({ offer: row });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// ---------- AUTH REQUIRED for writing ----------
app.post('/offers', authMiddleware, async (req, res) => {
  try {
    const { name, description, image, type = 'sell', official = 0 } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });

    // If user is admin, force official to 1
    const isOfficial = req.user.is_admin ? 1 : (official ? 1 : 0);

    const sql = 'INSERT INTO offers (owner_id, name, description, image, type, official) VALUES (?, ?, ?, ?, ?, ?)';
    const r = await runSql(sql, [
      req.user.id,
      name,
      description || null,
      image || null,
      type === 'trade' ? 'trade' : 'sell',
      isOfficial,
    ]);
    const offer = await getSql('SELECT * FROM offers WHERE id = ?', [r.lastID]);
    res.status(201).json({ offer });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});


// Update offer (only owner or admin)
app.put('/offers/:id', authMiddleware, async (req, res) => {
  try {
    const id = req.params.id;
    const offer = await getSql('SELECT * FROM offers WHERE id = ?', [id]);
    if (!offer) return res.status(404).json({ error: 'not found' });
    if (offer.owner_id !== req.user.id && !req.user.is_admin) return res.status(403).json({ error: 'forbidden' });

    const { name, description, image, type, official } = req.body;
    const updates = [];
    const params = [];
    if (name !== undefined) { updates.push('name = ?'); params.push(name); }
    if (description !== undefined) { updates.push('description = ?'); params.push(description); }
    if (image !== undefined) { updates.push('image = ?'); params.push(image); }
    if (type !== undefined) { updates.push("type = ?"); params.push(type === 'trade' ? 'trade' : 'sell'); }
    if (official !== undefined && req.user.is_admin) { updates.push('official = ?'); params.push(official ? 1 : 0); }

    if (updates.length === 0) return res.status(400).json({ error: 'nothing to update' });
    params.push(id);
    const sql = `UPDATE offers SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
    await runSql(sql, params);
    const updated = await getSql('SELECT * FROM offers WHERE id = ?', [id]);
    res.json({ offer: updated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// Delete offer (owner or admin)
app.delete('/offers/:id', authMiddleware, async (req, res) => {
  try {
    const id = req.params.id;
    const offer = await getSql('SELECT * FROM offers WHERE id = ?', [id]);
    if (!offer) return res.status(404).json({ error: 'not found' });
    if (offer.owner_id !== req.user.id && !req.user.is_admin) return res.status(403).json({ error: 'forbidden' });
    await runSql('DELETE FROM offers WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// ---------- Accounts ----------
app.get('/accounts/me', authMiddleware, async (req, res) => {
  try {
    const user = await getSql('SELECT id, username, display_name, created_at, is_admin FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ error: 'not found' });
    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

app.put('/accounts/me', authMiddleware, async (req, res) => {
  try {
    const { display_name, password } = req.body;
    const updates = [];
    const params = [];
    if (display_name !== undefined) { updates.push('display_name = ?'); params.push(display_name); }
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      updates.push('password_hash = ?'); params.push(hash);
    }
    if (updates.length === 0) return res.status(400).json({ error: 'nothing to update' });
    params.push(req.user.id);
    const sql = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;
    await runSql(sql, params);
    const user = await getSql('SELECT id, username, display_name, created_at, is_admin FROM users WHERE id = ?', [req.user.id]);
    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// Admin helper: promote user to admin
app.post('/admin/promote', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_admin) return res.status(403).json({ error: 'admin only' });
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'username required' });
    await runSql('UPDATE users SET is_admin = 1 WHERE username = ?', [username]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// Lightweight health
app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
