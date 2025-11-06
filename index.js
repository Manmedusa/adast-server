require('dotenv').config();
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || './keys.db';
const JWT_PRIVATE_PATH = process.env.JWT_PRIVATE_PATH || './jwt_private.pem';
const JWT_PUBLIC_PATH  = process.env.JWT_PUBLIC_PATH  || './jwt_public.pem';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '30d';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || '';

const PRIVATE_KEY = fs.readFileSync(JWT_PRIVATE_PATH, 'utf8');
const PUBLIC_KEY  = fs.readFileSync(JWT_PUBLIC_PATH, 'utf8');

const db = new Database(DB_PATH, { fileMustExist: true });
const app = express();

app.use(helmet());
app.use(express.json({ limit: '100kb' }));

const activateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
});

function isAdmin(req) {
  const k = req.headers['x-admin-key'];
  return ADMIN_API_KEY && k === ADMIN_API_KEY;
}

app.get('/health', (req, res) => res.json({ ok: true }));

app.post('/activate', activateLimiter, (req, res) => {
  try {
    const { key, deviceId } = req.body || {};
    if (!key || !deviceId) return res.status(400).json({ error: 'Missing key or deviceId' });

    const row = db.prepare('SELECT key, used, device_id AS deviceId, revoked FROM keys WHERE key = ?').get(key);
    if (!row) return res.status(400).json({ error: 'Key not found' });
    if (row.revoked) return res.status(403).json({ error: 'Key revoked' });
    if (row.used && row.deviceId && row.deviceId !== deviceId) {
      return res.status(409).json({ error: 'Key already used on a different device' });
    }

    db.prepare(`
      UPDATE keys
      SET used = 1,
          device_id = ?,
          used_at = datetime('now')
      WHERE key = ?
    `).run(deviceId, key);

    const token = jwt.sign({ k: key, d: deviceId }, PRIVATE_KEY, {
      algorithm: 'RS256',
      expiresIn: JWT_EXPIRES
    });

    return res.json({ token, expiresIn: JWT_EXPIRES });
  } catch (e) {
    console.error('activate error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/validate', (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'Missing token' });

    const decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
    const row = db.prepare('SELECT revoked FROM keys WHERE key = ?').get(decoded.k);
    if (!row) return res.status(400).json({ error: 'Key not found' });
    if (row.revoked) return res.status(403).json({ error: 'Key revoked' });

    return res.json({ valid: true, payload: decoded });
  } catch (e) {
    return res.status(401).json({ valid: false, error: e.message });
  }
});

app.post('/revoke', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { key } = req.body || {};
  if (!key) return res.status(400).json({ error: 'Missing key' });

  const r = db.prepare('UPDATE keys SET revoked = 1 WHERE key = ?').run(key);
  if (!r.changes) return res.status(404).json({ error: 'Key not found' });
  return res.json({ ok: true });
});

app.get('/status/:key', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Unauthorized' });
  const k = req.params.key;
  const row = db.prepare('SELECT key, used, device_id AS deviceId, used_at, revoked FROM keys WHERE key = ?').get(k);
  if (!row) return res.status(404).json({ error: 'Key not found' });
  return res.json(row);
});

app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});