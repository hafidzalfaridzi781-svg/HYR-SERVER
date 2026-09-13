import express from 'express';
import { query } from '../db.js';
import { sha256, generateKey } from '../utils/password.js';

const router = express.Router();

router.post('/generate', async (req, res) => {
  try {
    const { count = 30, role = 'VIP' } = req.body;
    const n = Math.min(Math.max(parseInt(count), 1), 100);
    const generated = [];

    for (let i = 0; i < n; i++) {
      const key = generateKey();
      const keyHash = sha256(key);
      const label = key.substring(0, 16);
      await query(
        `INSERT INTO access_keys (key_hash, key_label, role, status)
         VALUES ($1, $2, $3, 'ACTIVE')
         ON CONFLICT (key_hash) DO NOTHING`,
        [keyHash, label, role]
      );
      generated.push(key);
    }

    res.json({ ok: true, count: generated.length, keys: generated });
  } catch (e) {
    console.error('generate error:', e);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

router.get('/list', async (_req, res) => {
  try {
    const r = await query(
      `SELECT id, key_label, role, status, created_at, used_at FROM access_keys ORDER BY id DESC LIMIT 100`
    );
    res.json({ ok: true, keys: r.rows });
  } catch (_) {
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

export default router;
