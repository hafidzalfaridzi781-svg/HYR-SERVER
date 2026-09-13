import argon2 from 'argon2';
import crypto from 'crypto';

export async function hashPassword(plain) {
  return argon2.hash(plain, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
  });
}

export async function verifyPassword(hash, plain) {
  try { return await argon2.verify(hash, plain); }
  catch (_) { return false; }
}

export function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

export function generateKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const gen = (n) => Array.from({ length: n }, () =>
    chars[Math.floor(Math.random() * chars.length)]
  ).join('');
  const prefixes = ['HYR-ZYE', 'ZYE-HYR', 'HYR-VIP-ZYE', 'ZYE-VIP-HYR', 'HYR-INJECT-ZYE'];
  const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
  return `${prefix}-${gen(4)}-${gen(4)}`;
}
