import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import maintenanceRoutes from './routes/maintenance.js';
import keyRoutes from './routes/keys.js';

const app = express();
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

app.use(cors({
  origin: (process.env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean),
  credentials: true
}));

app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());

app.get('/', (_req, res) => res.json({ ok: true, service: 'hyr-injector-api', version: '2.0' }));
app.use('/api/auth', authRoutes);
app.use('/api/maintenance', maintenanceRoutes);
app.use('/api/keys', keyRoutes);

app.use((err, _req, res, _next) => {
  console.error('unhandled:', err);
  res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
});

const port = parseInt(process.env.PORT || '3000', 10);
app.listen(port, () => console.log(`HYR API v2.0 listening on :${port}`));
