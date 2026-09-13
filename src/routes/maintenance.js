import express from 'express';
import { query } from '../db.js';

const router = express.Router();

router.get('/status', async (_req, res) => {
  try {
    const r = await query(`SELECT value FROM config WHERE key = 'maintenance' LIMIT 1`);
    res.json({ ok: true, maintenance: r.rows[0]?.value === 'true' });
  } catch (_) {
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

export default router;
