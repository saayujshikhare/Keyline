#!/usr/bin/env node
// Entry point.  Configuration (all optional):
//   PORT=8787  HOST=127.0.0.1  DATA_DIR=./data  SECRETS_DIR=./secrets
//   MSGR_PEPPER=<64 hex chars>   keyed-hash secret; if unset one is generated in SECRETS_DIR
//   TRUST_PROXY=1                use X-Forwarded-For from your reverse proxy for rate limiting

if (Number(process.versions.node.split('.')[0]) < 22) {
  console.error('Node.js 22.13 or newer is required (built-in SQLite). You have ' + process.versions.node);
  process.exit(1);
}

const fs = await import('node:fs');
const path = await import('node:path');
const crypto = await import('node:crypto');
const { createApp } = await import('./lib/app.js');

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const SECRETS_DIR = path.resolve(process.env.SECRETS_DIR || './secrets');

function loadPepper() {
  if (process.env.MSGR_PEPPER) {
    const b = Buffer.from(process.env.MSGR_PEPPER, 'hex');
    if (b.length < 32) {
      console.error('MSGR_PEPPER must be at least 64 hex characters (32 bytes).');
      process.exit(1);
    }
    return b;
  }
  const file = path.join(SECRETS_DIR, 'pepper.key');
  if (fs.existsSync(file)) return Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex');
  fs.mkdirSync(SECRETS_DIR, { recursive: true, mode: 0o700 });
  const b = crypto.randomBytes(32);
  fs.writeFileSync(file, b.toString('hex') + '\n', { mode: 0o600 });
  console.log(`Generated a new pepper at ${file}`);
  console.log('Back it up, and for production keep it OFF the database disk (use MSGR_PEPPER instead).');
  return b;
}

const app = createApp({ dataDir: DATA_DIR, pepper: loadPepper(), trustProxy: process.env.TRUST_PROXY === '1' });
const addr = await app.listen(PORT, HOST);
console.log(`Messenger listening on http://${addr.address}:${addr.port}`);
if (!['127.0.0.1', '::1', 'localhost'].includes(HOST)) {
  console.log('Listening on a public interface: put this behind HTTPS (e.g. Caddy or nginx). Browsers refuse WebCrypto over plain HTTP.');
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    await app.close();
    process.exit(0);
  });
}
