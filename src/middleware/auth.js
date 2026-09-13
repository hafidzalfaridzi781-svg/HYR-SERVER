import crypto from 'crypto';
import { query } from '../db.js';

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

export async function requireAuth(req, res, next) {
  try {
    let token = null;
    if (req.cookies && req.cookies.hyr_token) token = req.cookies.hyr_token;
    else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.slice(7);
    }
    if (!token) return res.status(401).json({ ok: false, code: 'UNAUTHENTICATED' });

    const tokenHash = sha256(token);
    const r = await query(
      `SELECT s.user_id, s.device_id, s.expires_at, s.revoked,
              u.role, u.username, u.access_key_hash
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1 LIMIT 1`, [tokenHash]
    );
    if (r.rows.length === 0) return res.status(401).json({ ok: false, code: 'UNAUTHENTICATED' });
    const s = r.rows[0];
    if (s.revoked || new Date(s.expires_at) < new Date())
      return res.status(401).json({ ok: false, code: 'SESSION_EXPIRED' });

    req.user = {
      id: s.user_id,
      username: s.username || (s.access_key_hash ? s.access_key_hash.substring(0, 8) + '...' : 'User'),
      role: s.role,
      deviceId: s.device_id
    };
    next();
  } catch (e) {
    console.error('auth error:', e);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
}
