import express from 'express';
import crypto from 'crypto';
import { query } from '../db.js';
import { verifyPassword, sha256 } from '../utils/password.js';
import { loginLimiter } from '../middleware/rateLimit.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();
const JWT_EXPIRES_IN = parseInt(process.env.JWT_EXPIRES_IN || '3600', 10);

async function isMaintenance() {
  const r = await query(`SELECT value FROM config WHERE key = 'maintenance' LIMIT 1`);
  return r.rows[0]?.value === 'true';
}

router.post('/login', loginLimiter, async (req, res) => {
  try {
    if (await isMaintenance()) {
      return res.status(503).json({ ok: false, code: 'MAINTENANCE' });
    }

    const { username, password, key, device_id, device_info } = req.body || {};
    if (!device_id) return res.status(400).json({ ok: false, code: 'INVALID_CREDENTIALS' });

    let user = null;

    if (key) {
      const normalized = String(key).trim().toUpperCase();
      const keyHash = sha256(normalized);

      const kr = await query(
        `SELECT id, role, status, expires_at FROM access_keys WHERE key_hash = $1 LIMIT 1`,
        [keyHash]
      );
      const foundKey = kr.rows[0];

      if (!foundKey || foundKey.status === 'REVOKED' || foundKey.status === 'EXPIRED')
        return res.status(401).json({ ok: false, code: 'INVALID_CREDENTIALS' });

      if (foundKey.expires_at && new Date(foundKey.expires_at) < new Date()) {
        await query(`UPDATE access_keys SET status = 'EXPIRED' WHERE id = $1`, [foundKey.id]);
        return res.status(401).json({ ok: false, code: 'INVALID_CREDENTIALS' });
      }

      const ur = await query(`SELECT id, role FROM users WHERE access_key_hash = $1 LIMIT 1`, [keyHash]);
      if (ur.rows[0]) {
        user = ur.rows[0];
      } else {
        const ins = await query(
          `INSERT INTO users (access_key_hash, role) VALUES ($1, $2) RETURNING id, role`,
          [keyHash, foundKey.role || 'VIP']
        );
        user = ins.rows[0];
        await query(
          `UPDATE access_keys SET status = 'USED', used_by = $1, used_at = NOW() WHERE id = $2`,
          [user.id, foundKey.id]
        );
      }
    } else if (username && password) {
      const ur = await query(
        `SELECT id, username, password_hash, role, is_active FROM users WHERE username = $1 LIMIT 1`,
        [username]
      );
      const found = ur.rows[0];
      const valid = found?.password_hash ? await verifyPassword(found.password_hash, password) : false;
      if (!found || !valid || !found.is_active)
        return res.status(401).json({ ok: false, code: 'INVALID_CREDENTIALS' });
      user = found;
    } else {
      return res.status(400).json({ ok: false, code: 'INVALID_CREDENTIALS' });
    }

    const devRes = await query(`SELECT device_id FROM user_devices WHERE user_id = $1`, [user.id]);
    if (devRes.rows.length === 0) {
      await query(
        `INSERT INTO user_devices (user_id, device_id, first_ip, last_ip, device_label)
         VALUES ($1, $2, $3, $3, $4)`,
        [user.id, device_id, req.ip, (device_info || '').substring(0, 200)]
      );
    } else if (devRes.rows[0].device_id !== device_id) {
      return res.status(403).json({ ok: false, code: 'DEVICE_MISMATCH' });
    } else {
      await query(
        `UPDATE user_devices SET last_ip = $1, last_seen_at = NOW() WHERE user_id = $2`,
        [req.ip, user.id]
      );
    }

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = sha256(rawToken);
    const expiresAt = new Date(Date.now() + JWT_EXPIRES_IN * 1000);

    await query(
      `INSERT INTO sessions (token_hash, user_id, device_id, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [tokenHash, user.id, device_id, req.ip,
       (req.headers['user-agent'] || '').substring(0, 500), expiresAt]
    );

    const isProd = process.env.NODE_ENV === 'production';
    res.cookie('hyr_token', rawToken, {
      httpOnly: true, secure: isProd, sameSite: 'strict',
      maxAge: JWT_EXPIRES_IN * 1000, path: '/'
    });

    const label = user.username || ('User-' + user.id);
    return res.json({
      ok: true, token: rawToken, expires_in: JWT_EXPIRES_IN,
      user: { username: label, role: user.role || 'FREE' }
    });
  } catch (e) {
    console.error('login error:', e);
    return res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

router.post('/logout', requireAuth, async (req, res) => {
  try {
    let token = null;
    if (req.cookies?.hyr_token) token = req.cookies.hyr_token;
    else if (req.headers.authorization?.startsWith('Bearer '))
      token = req.headers.authorization.slice(7);

    if (token) {
      const th = sha256(token);
      await query(`UPDATE sessions SET revoked = TRUE WHERE token_hash = $1`, [th]);
    }
    res.clearCookie('hyr_token', { path: '/' });
    res.json({ ok: true });
  } catch (_) {
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

router.get('/me', requireAuth, (req, res) => {
  res.json({ ok: true, user: { username: req.user.username, role: req.user.role } });
});

export default router;
