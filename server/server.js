const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cookieParser = require('cookie-parser');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || '/var/lib/ame-decor';
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const DB_PATH = path.join(DATA_DIR, 'ame-decor.db');

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS bookings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT DEFAULT (datetime('now')),
  status TEXT NOT NULL DEFAULT 'new',
  event_type TEXT NOT NULL,
  services_json TEXT NOT NULL,
  event_date TEXT,
  event_time_start TEXT,
  event_time_end TEXT,
  location_address TEXT,
  location_city TEXT,
  venue_type TEXT,
  indoor_outdoor TEXT,
  guest_count INTEGER,
  budget_range TEXT,
  notes TEXT,
  customer_name TEXT NOT NULL,
  customer_phone TEXT NOT NULL,
  customer_email TEXT,
  admin_notes TEXT,
  quoted_price REAL
);

CREATE TABLE IF NOT EXISTS gallery_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT DEFAULT (datetime('now')),
  title TEXT NOT NULL,
  category TEXT,
  description TEXT,
  image_path TEXT NOT NULL,
  display_order INTEGER DEFAULT 0,
  published INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);
`);

const adminCount = db.prepare('SELECT COUNT(*) AS n FROM admin_users').get().n;
if (adminCount === 0) {
  const initialPassword = process.env.ADMIN_INITIAL_PASSWORD || 'amedecor2026';
  const hash = bcrypt.hashSync(initialPassword, 10);
  db.prepare('INSERT INTO admin_users (username, password_hash) VALUES (?, ?)').run('admin', hash);
  console.log(`[init] Created default admin user 'admin' with password '${initialPassword}'`);
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'ame-decor-session-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 1000 * 60 * 60 * 12
  }
}));

app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d' }));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, '');
    const safeExt = ['.jpg', '.jpeg', '.png', '.webp', '.gif'].includes(ext) ? ext : '.jpg';
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2, 8)}${safeExt}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)) return cb(new Error('Only image files allowed'));
    cb(null, true);
  }
});

function requireAdmin(req, res, next) {
  if (req.session && req.session.adminId) return next();
  return res.status(401).json({ error: 'unauthorized' });
}

app.post('/api/bookings', (req, res) => {
  const b = req.body || {};
  if (!b.event_type || !b.customer_name || !b.customer_phone) {
    return res.status(400).json({ error: 'missing_required_fields' });
  }
  if (!Array.isArray(b.services) || b.services.length === 0) {
    return res.status(400).json({ error: 'services_required' });
  }
  const stmt = db.prepare(`INSERT INTO bookings (
    event_type, services_json, event_date, event_time_start, event_time_end,
    location_address, location_city, venue_type, indoor_outdoor,
    guest_count, budget_range, notes,
    customer_name, customer_phone, customer_email
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  const info = stmt.run(
    b.event_type,
    JSON.stringify(b.services),
    b.event_date || null,
    b.event_time_start || null,
    b.event_time_end || null,
    b.location_address || null,
    b.location_city || null,
    b.venue_type || null,
    b.indoor_outdoor || null,
    b.guest_count ? Number(b.guest_count) : null,
    b.budget_range || null,
    b.notes || null,
    String(b.customer_name).trim(),
    String(b.customer_phone).trim(),
    b.customer_email || null
  );
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.get('/api/gallery', (req, res) => {
  const rows = db.prepare(`SELECT id, title, category, description, image_path, created_at
    FROM gallery_items WHERE published = 1
    ORDER BY display_order DESC, created_at DESC`).all();
  res.json(rows.map(r => ({ ...r, image_url: `/uploads/${path.basename(r.image_path)}` })));
});

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing_credentials' });
  const row = db.prepare('SELECT * FROM admin_users WHERE username = ?').get(username);
  if (!row) return res.status(401).json({ error: 'invalid_credentials' });
  if (!bcrypt.compareSync(password, row.password_hash)) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  req.session.adminId = row.id;
  req.session.adminUsername = row.username;
  res.json({ ok: true, username: row.username });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/admin/me', (req, res) => {
  if (req.session && req.session.adminId) {
    return res.json({ ok: true, username: req.session.adminUsername });
  }
  res.status(401).json({ error: 'unauthorized' });
});

app.post('/api/admin/change-password', requireAdmin, (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!new_password || new_password.length < 6) return res.status(400).json({ error: 'weak_password' });
  const row = db.prepare('SELECT * FROM admin_users WHERE id = ?').get(req.session.adminId);
  if (!bcrypt.compareSync(current_password || '', row.password_hash)) {
    return res.status(401).json({ error: 'invalid_current_password' });
  }
  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare('UPDATE admin_users SET password_hash = ? WHERE id = ?').run(hash, row.id);
  res.json({ ok: true });
});

app.get('/api/admin/bookings', requireAdmin, (req, res) => {
  const status = req.query.status;
  let sql = `SELECT * FROM bookings`;
  const params = [];
  if (status && status !== 'all') {
    sql += ` WHERE status = ?`;
    params.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT 500`;
  const rows = db.prepare(sql).all(...params);
  res.json(rows.map(r => ({ ...r, services: JSON.parse(r.services_json) })));
});

app.get('/api/admin/bookings/:id', requireAdmin, (req, res) => {
  const r = db.prepare('SELECT * FROM bookings WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'not_found' });
  res.json({ ...r, services: JSON.parse(r.services_json) });
});

app.patch('/api/admin/bookings/:id', requireAdmin, (req, res) => {
  const allowed = ['status', 'admin_notes', 'quoted_price'];
  const updates = [];
  const values = [];
  for (const key of allowed) {
    if (req.body[key] !== undefined) {
      updates.push(`${key} = ?`);
      values.push(req.body[key]);
    }
  }
  if (updates.length === 0) return res.json({ ok: true });
  values.push(req.params.id);
  db.prepare(`UPDATE bookings SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  res.json({ ok: true });
});

app.delete('/api/admin/bookings/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM bookings WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const counts = db.prepare(`SELECT status, COUNT(*) AS n FROM bookings GROUP BY status`).all();
  const total = db.prepare('SELECT COUNT(*) AS n FROM bookings').get().n;
  const recent = db.prepare(`SELECT COUNT(*) AS n FROM bookings WHERE created_at >= datetime('now','-30 days')`).get().n;
  res.json({ total, recent_30_days: recent, by_status: counts });
});

app.post('/api/admin/gallery', requireAdmin, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'image_required' });
  const { title, category, description, display_order } = req.body || {};
  if (!title) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'title_required' });
  }
  const info = db.prepare(`INSERT INTO gallery_items (title, category, description, image_path, display_order)
    VALUES (?, ?, ?, ?, ?)`).run(
    title,
    category || null,
    description || null,
    req.file.filename,
    display_order ? Number(display_order) : 0
  );
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.get('/api/admin/gallery', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT * FROM gallery_items ORDER BY display_order DESC, created_at DESC`).all();
  res.json(rows.map(r => ({ ...r, image_url: `/uploads/${path.basename(r.image_path)}` })));
});

app.patch('/api/admin/gallery/:id', requireAdmin, (req, res) => {
  const allowed = ['title', 'category', 'description', 'display_order', 'published'];
  const updates = [];
  const values = [];
  for (const key of allowed) {
    if (req.body[key] !== undefined) {
      updates.push(`${key} = ?`);
      values.push(req.body[key]);
    }
  }
  if (updates.length === 0) return res.json({ ok: true });
  values.push(req.params.id);
  db.prepare(`UPDATE gallery_items SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  res.json({ ok: true });
});

app.delete('/api/admin/gallery/:id', requireAdmin, (req, res) => {
  const row = db.prepare('SELECT image_path FROM gallery_items WHERE id = ?').get(req.params.id);
  if (row) {
    const filePath = path.join(UPLOAD_DIR, path.basename(row.image_path));
    fs.unlink(filePath, () => {});
  }
  db.prepare('DELETE FROM gallery_items WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'server_error' });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`AME Decor API listening on http://127.0.0.1:${PORT}`);
});
