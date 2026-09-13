import 'dotenv/config';
import crypto from 'crypto';
import { query } from './db.js';
import { hashPassword, sha256, generateKey } from './utils/password.js';

const VIP_ACCOUNTS = [
  { u: 'VIP-BY-ZYE',     p: 'HYRINJECT'    },
  { u: 'ZYE-INJECT',     p: 'ZYEHYPER'     },
  { u: 'KAIZYE-INJECT',  p: 'ZYESETTINGS'  },
  { u: 'ZYE-CITER',      p: 'ZYECITEDZ'    },
  { u: 'GACOR-BY-ZYE',   p: 'INJECTZYE'    },
  { u: 'ZYE-VIP-INJECT', p: 'VIPINJECTZYE' }
];

const FREE_ACCOUNT = { u: 'FREE-USER', p: 'HYRFREE-1HARI' };

console.log('=== Seeding VIP accounts ===');
for (const acc of VIP_ACCOUNTS) {
  const hash = await hashPassword(acc.p);
  await query(
    `INSERT INTO users (username, password_hash, role)
     VALUES ($1, $2, 'VIP')
     ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
    [acc.u, hash]
  );
  console.log('OK VIP:', acc.u);
}

console.log('\n=== Seeding FREE account ===');
{
  const hash = await hashPassword(FREE_ACCOUNT.p);
  await query(
    `INSERT INTO users (username, password_hash, role)
     VALUES ($1, $2, 'FREE')
     ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
    [FREE_ACCOUNT.u, hash]
  );
  console.log('OK FREE:', FREE_ACCOUNT.u, 'password: HYRFREE-1HARI');
}

console.log('\n=== Generating 30 random keys ===');
const generatedKeys = [];
for (let i = 0; i < 30; i++) {
  const key = generateKey();
  const keyHash = sha256(key);
  const label = key.substring(0, 16);
  await query(
    `INSERT INTO access_keys (key_hash, key_label, role, status)
     VALUES ($1, $2, 'VIP', 'ACTIVE')
     ON CONFLICT (key_hash) DO NOTHING`,
    [keyHash, label]
  );
  generatedKeys.push(key);
}

console.log('\n=== 30 GENERATED KEYS ===');
generatedKeys.forEach((k, i) => console.log(`${i+1}. ${k}`));

console.log('\nSelesai.');
process.exit(0);
