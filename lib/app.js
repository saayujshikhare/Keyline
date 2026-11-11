// HTTP application: accounts, mailboxes, delivery. Zero npm dependencies.
//
// What the server can see:   ciphertext, public keys, and (transiently, in RAM) who is calling.
// What the server stores:    see lib/db.js. No usernames, passwords, 10-digit keys, senders,
//                            plaintext, private keys or sessions are ever written to disk.
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { openDb } from './db.js';
import { RateLimiter } from './ratelimit.js';

const scrypt = promisify(crypto.scrypt);
const HERE = path.dirname(fileURLToPath(import.meta.url));

export const LIMITS = {
  register:      [5, 3_600_000],   // new accounts per IP per hour
  login:         [10, 600_000],    // login attempts per IP per 10 min
  loginUid:      [10, 900_000],    // login attempts per username per 15 min
  mailboxCreate: [10, 3_600_000],  // new mailboxes per IP per hour
  open:          [10, 600_000],    // mailbox-open attempts per IP per 10 min
  openBox:       [10, 600_000],    // mailbox-open attempts per mailbox per 10 min
  lookup:        [60, 60_000],     // key lookups per mailbox session per minute
  send:          [120, 60_000],    // messages per mailbox session per minute
  global:        [1200, 60_000],   // all API calls per IP per minute
};

const MAX_QUEUE = 500;                 // undelivered messages per mailbox
const TTL_DAYS = 30;                   // undelivered messages are dropped after this
const RAW_MSG_MIN = 65 + 12 + 16 + 256;      // ephemeral key + iv + tag + smallest padded payload
const RAW_MSG_MAX = 65 + 12 + 16 + 16384;    // ... + largest padded payload
const IDLE_MS = 12 * 3_600_000;
const MAX_AGE_MS = 7 * 24 * 3_600_000;
const DAY_MS = 86_400_000;
export const REPLACED = 'signed-in-elsewhere'; // a newer sign-in took over this mailbox

const B64U = /^[A-Za-z0-9_-]+$/;
const isB64u = (s, len) => typeof s === 'string' && s.length === len && B64U.test(s);
const isKey = (k) => typeof k === 'string' && /^\d{10}$/.test(k);
const validVault = (v) => typeof v === 'string' && v.length >= 40 && v.length <= 262_144 && B64U.test(v);

// DER prefix of a P-256 SubjectPublicKeyInfo; used to make OpenSSL validate that a submitted
// public key really is a point on the curve.
const SPKI_P256 = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
function validP256(pub) {
  if (!isB64u(pub, 87)) return false;
  const raw = Buffer.from(pub, 'base64url');
  if (raw.length !== 65 || raw[0] !== 4) return false;
  try {
    crypto.createPublicKey({ key: Buffer.concat([SPKI_P256, raw]), format: 'der', type: 'spki' });
    return true;
  } catch {
    return false;
  }
}

const SEC_HEADERS = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
};

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

class Sessions {
  constructor() {
    this.map = new Map();
    this.replaced = new Map(); // hash of a displaced mailbox token -> when, so its owner can be told why
  }
  static #h(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }
  create(kind, ref) {
    const token = crypto.randomBytes(32).toString('base64url');
    const now = Date.now();
    this.map.set(Sessions.#h(token), { kind, ref, born: now, last: now });
    return token;
  }
  get(token, kind) {
    const k = Sessions.#h(token);
    const s = this.map.get(k);
    if (!s || s.kind !== kind) return null;
    const now = Date.now();
    if (now - s.last > IDLE_MS || now - s.born > MAX_AGE_MS) {
      this.map.delete(k);
      return null;
    }
    s.last = now;
    return s;
  }
  drop(token) {
    this.map.delete(Sessions.#h(token));
  }
  dropRef(kind, ref, markReplaced = false) {
    for (const [k, s] of this.map) {
      if (s.kind !== kind || s.ref !== ref) continue;
      this.map.delete(k);
      if (markReplaced) this.replaced.set(k, Date.now());
    }
    if (this.replaced.size > 100_000) this.replaced.clear(); // memory guard
  }
  wasReplaced(token) {
    return this.replaced.has(Sessions.#h(token));
  }
  sweep() {
    const now = Date.now();
    for (const [k, s] of this.map) if (now - s.last > IDLE_MS || now - s.born > MAX_AGE_MS) this.map.delete(k);
    for (const [k, t] of this.replaced) if (now - t > DAY_MS) this.replaced.delete(k);
  }
}

function loadStatic(dir) {
  const files = new Map();
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    const type = TYPES[path.extname(name)];
    if (!type || !fs.statSync(full).isFile()) continue;
    files.set('/' + name, { body: fs.readFileSync(full), type });
  }
  if (files.has('/index.html')) files.set('/', files.get('/index.html'));
  return files;
}

function json(res, status, obj, extra = {}) {
  const data = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    'Cache-Control': 'no-store',
    ...SEC_HEADERS,
    ...extra,
  });
  res.end(data);
}

async function readJson(req, limit = 65_536) {
  const ct = String(req.headers['content-type'] || '');
  if (!ct.startsWith('application/json')) throw new HttpError(415, 'application/json required');
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > limit) throw new HttpError(413, 'request too large');
    chunks.push(c);
  }
  let v;
  try {
    v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'invalid JSON');
  }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new HttpError(400, 'invalid request');
  return v;
}

export function createApp({ dataDir, pepper, limits = LIMITS, trustProxy = false } = {}) {
  if (!dataDir) throw new Error('dataDir is required');
  if (!pepper || pepper.length < 32) throw new Error('pepper must be at least 32 bytes');

  const db = openDb(dataDir);
  const rl = new RateLimiter();
  const sessions = new Sessions();
  const waiters = new Map(); // box -> Set<wake fn> for long-polling
  const files = loadStatic(path.join(HERE, '..', 'public'));
  const DUMMY_SALT = crypto.randomBytes(16);
  const DUMMY_SECRET = crypto.randomBytes(32);

  // Keyed hashes: without the pepper (kept outside the database) a stolen DB cannot be
  // matched against guessed usernames or keys.
  const mac = (label, value) => crypto.createHmac('sha256', pepper).update(`${label}|${value}`).digest();
  const hashAuth = (auth, salt) => scrypt(mac('auth', auth), salt, 32, { N: 16384, r: 8, p: 1 });

  const today = () => Math.floor(Date.now() / DAY_MS);

  function clientIp(req) {
    if (trustProxy) {
      const parts = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
      if (parts.length) return parts[parts.length - 1]; // the hop added by our own proxy
    }
    return req.socket.remoteAddress || 'unknown';
  }

  function limit(name, id) {
    const [max, windowMs] = limits[name];
    if (!rl.hit(`${name}:${id}`, max, windowMs)) throw new HttpError(429, 'Too many requests, slow down');
  }

  function authenticate(req, kind) {
    const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization || '');
    const s = m && sessions.get(m[1], kind);
    if (!s) throw new HttpError(401, m && kind === 'box' && sessions.wasReplaced(m[1]) ? REPLACED : 'unauthorized');
    return { ...s, token: m[1] };
  }

  function sameOrigin(req) {
    const origin = req.headers.origin;
    if (!origin) return;
    let host;
    try { host = new URL(origin).host; } catch { throw new HttpError(403, 'bad origin'); }
    if (host !== req.headers.host) throw new HttpError(403, 'cross-origin request refused');
  }

  function notify(box) {
    const set = waiters.get(box);
    if (set) for (const wake of [...set]) wake();
  }

  function waitFor(box, ms, res) {
    return new Promise((resolve) => {
      let set = waiters.get(box);
      if (!set) waiters.set(box, (set = new Set()));
      const done = () => {
        clearTimeout(timer);
        set.delete(done);
        if (!set.size) waiters.delete(box);
        res.off('close', done);
        resolve();
      };
      const timer = setTimeout(done, ms);
      set.add(done);
      res.on('close', done);
    });
  }

  // ---------------------------------------------------------------- handlers

  async function register(ctx) {
    limit('register', ctx.ip);
    const { uid, auth } = await readJson(ctx.req);
    if (!isB64u(uid, 43) || !isB64u(auth, 43)) throw new HttpError(400, 'invalid request');
    const id = mac('uid', uid).toString('hex');
    const salt = crypto.randomBytes(16);
    const hash = await hashAuth(auth, salt);
    try {
      db.addAccount(id, salt, hash);
    } catch (e) {
      if (/UNIQUE|constraint/i.test(e.message)) throw new HttpError(409, 'That username is taken');
      throw e;
    }
    json(ctx.res, 201, { token: sessions.create('acct', id) });
  }

  async function login(ctx) {
    limit('login', ctx.ip);
    const { uid, auth } = await readJson(ctx.req);
    if (!isB64u(uid, 43) || !isB64u(auth, 43)) throw new HttpError(400, 'invalid request');
    const id = mac('uid', uid).toString('hex');
    limit('loginUid', id);
    const acc = db.getAccount(id);
    const hash = await hashAuth(auth, acc ? Buffer.from(acc.salt) : DUMMY_SALT); // same work either way
    if (!acc || !crypto.timingSafeEqual(hash, Buffer.from(acc.hash))) throw new HttpError(401, 'Wrong username or password');
    json(ctx.res, 200, { token: sessions.create('acct', id), vault: acc.vault ?? null, version: acc.version });
  }

  async function putVault(ctx) {
    const s = authenticate(ctx.req, 'acct');
    const { vault, version } = await readJson(ctx.req, 300_000);
    if (!validVault(vault)) throw new HttpError(400, 'invalid vault');
    if (!Number.isInteger(version) || version < 0) throw new HttpError(400, 'invalid version');
    if (!db.setVault(s.ref, vault, version)) throw new HttpError(409, 'vault changed elsewhere');
    json(ctx.res, 200, { version: version + 1 });
  }

  // Replaces the login proof and the vault together, in one statement, so they can never disagree.
  async function changePassword(ctx) {
    const s = authenticate(ctx.req, 'acct');
    limit('loginUid', s.ref); // a stolen session token must not become an unlimited password-guessing oracle
    const { auth, newAuth, vault, version } = await readJson(ctx.req, 300_000);
    if (!isB64u(auth, 43) || !isB64u(newAuth, 43) || !validVault(vault) || !Number.isInteger(version) || version < 0) {
      throw new HttpError(400, 'invalid request');
    }
    const acc = db.getAccount(s.ref);
    if (!acc) throw new HttpError(401, 'unauthorized');
    const hash = await hashAuth(auth, Buffer.from(acc.salt));
    // 403 rather than 401: a 401 makes the client log in again, which would just repeat the mistake
    if (!crypto.timingSafeEqual(hash, Buffer.from(acc.hash))) throw new HttpError(403, 'Current password is wrong');
    const salt = crypto.randomBytes(16);
    if (!db.setCredentials(s.ref, salt, await hashAuth(newAuth, salt), vault, version)) {
      throw new HttpError(409, 'vault changed elsewhere');
    }
    sessions.dropRef('acct', s.ref); // every other login session for this account ends here
    json(ctx.res, 200, { token: sessions.create('acct', s.ref), version: version + 1 });
  }

  async function deleteAccount(ctx) {
    const s = authenticate(ctx.req, 'acct');
    db.deleteAccount(s.ref);
    sessions.dropRef('acct', s.ref);
    json(ctx.res, 200, { ok: true });
  }

  async function createMailbox(ctx) {
    authenticate(ctx.req, 'acct');
    limit('mailboxCreate', ctx.ip);
    const { ecdh, ecdsa, secret } = await readJson(ctx.req);
    if (!validP256(ecdh) || !validP256(ecdsa) || !isB64u(secret, 43)) throw new HttpError(400, 'invalid request');
    const secretMac = mac('mbs', secret);
    for (let i = 0; i < 20; i++) {
      const key = String(crypto.randomInt(1_000_000_000, 10_000_000_000)); // 10 digits, never a leading zero
      try {
        db.addMailbox(mac('box', key).toString('hex'), ecdh, ecdsa, secretMac);
        return json(ctx.res, 201, { key });
      } catch (e) {
        if (!/UNIQUE|constraint/i.test(e.message)) throw e; // collision: draw another key
      }
    }
    throw new HttpError(503, 'could not allocate a key, try again');
  }

  async function openMailbox(ctx) {
    limit('open', ctx.ip);
    const { key, secret } = await readJson(ctx.req);
    if (!isKey(key) || !isB64u(secret, 43)) throw new HttpError(400, 'invalid request');
    const box = mac('box', key).toString('hex');
    limit('openBox', box);
    const mb = db.getMailbox(box);
    const given = mac('mbs', secret);
    const expected = mb ? Buffer.from(mb.secret) : DUMMY_SECRET;
    const ok = crypto.timingSafeEqual(given, expected) && !!mb;
    if (!ok) throw new HttpError(401, 'invalid mailbox credentials');
    // Latest sign-in wins. A mailbox is drained by exactly one device; if two polled at once each
    // message would reach only one of them and the other would never see it.
    sessions.dropRef('box', box, true);
    notify(box); // wake the displaced device's long-poll so it finds out immediately
    json(ctx.res, 200, { token: sessions.create('box', box) });
  }

  function lookup(ctx, key) {
    const s = authenticate(ctx.req, 'box');
    limit('lookup', s.ref);
    const mb = isKey(key) ? db.getMailbox(mac('box', key).toString('hex')) : null;
    if (!mb) throw new HttpError(404, 'No user with that key');
    json(ctx.res, 200, { key, ecdh: mb.ecdh, ecdsa: mb.ecdsa });
  }

  async function send(ctx) {
    const s = authenticate(ctx.req, 'box');
    limit('send', s.ref);
    const { to, blob } = await readJson(ctx.req, 48_000);
    if (!isKey(to) || typeof blob !== 'string' || !B64U.test(blob)) throw new HttpError(400, 'invalid request');
    const rawLen = Buffer.from(blob, 'base64url').length;
    if (rawLen < RAW_MSG_MIN || rawLen > RAW_MSG_MAX) throw new HttpError(400, 'invalid message size');
    const box = mac('box', to).toString('hex');
    if (!db.getMailbox(box)) throw new HttpError(404, 'No user with that key');
    if (db.countMessages(box) >= MAX_QUEUE) throw new HttpError(429, "Recipient's mailbox is full");
    const id = crypto.randomBytes(16).toString('base64url');
    // Note what is NOT stored: the sender. The sender's identity travels inside the ciphertext.
    db.addMessage(id, box, blob, today() + TTL_DAYS);
    notify(box);
    json(ctx.res, 202, { id });
  }

  async function inbox(ctx) {
    const s = authenticate(ctx.req, 'box');
    const wait = Math.min(25, Math.max(0, parseInt(ctx.url.searchParams.get('wait') || '0', 10) || 0));
    let messages = db.listMessages(s.ref, 100);
    if (!messages.length && wait > 0) {
      await waitFor(s.ref, wait * 1000, ctx.res);
      if (ctx.res.destroyed) return;
      authenticate(ctx.req, 'box'); // we may have been displaced, or logged out, while waiting
      messages = db.listMessages(s.ref, 100);
    }
    json(ctx.res, 200, { messages: messages.map(({ id, blob }) => ({ id, blob })) });
  }

  async function ack(ctx) {
    const s = authenticate(ctx.req, 'box');
    const { ids } = await readJson(ctx.req);
    if (!Array.isArray(ids) || ids.length > 100 || !ids.every((x) => isB64u(x, 22))) throw new HttpError(400, 'invalid request');
    json(ctx.res, 200, { deleted: db.deleteMessages(s.ref, ids) });
  }

  async function deleteMailbox(ctx) {
    const s = authenticate(ctx.req, 'box');
    db.deleteMailbox(s.ref);
    sessions.dropRef('box', s.ref);
    notify(s.ref);
    json(ctx.res, 200, { ok: true });
  }

  async function logout(ctx) {
    const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(ctx.req.headers.authorization || '');
    if (m) sessions.drop(m[1]);
    json(ctx.res, 200, { ok: true });
  }

  const routes = {
    'POST /api/account': register,
    'POST /api/login': login,
    'PUT /api/vault': putVault,
    'POST /api/account/password': changePassword,
    'DELETE /api/account': deleteAccount,
    'POST /api/mailbox': createMailbox,
    'POST /api/mailbox/open': openMailbox,
    'DELETE /api/mailbox': deleteMailbox,
    'POST /api/send': send,
    'GET /api/inbox': inbox,
    'POST /api/ack': ack,
    'POST /api/logout': logout,
  };

  function serveStatic(req, res, pathname) {
    if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'method not allowed');
    if (pathname === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store', ...SEC_HEADERS });
      return res.end('ok');
    }
    const f = files.get(pathname); // exact-match lookup only: no filesystem path is ever built from the URL
    if (!f) {
      res.writeHead(404, { 'Content-Type': 'text/plain', ...SEC_HEADERS });
      return res.end('Not found');
    }
    res.writeHead(200, {
      'Content-Type': f.type,
      'Content-Length': f.body.length,
      'Cache-Control': 'no-cache',
      ...SEC_HEADERS,
    });
    res.end(req.method === 'HEAD' ? undefined : f.body);
  }

  async function handle(req, res) {
    const url = new URL(req.url, 'http://localhost');
    if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url.pathname);
    const ctx = { req, res, url, ip: clientIp(req) };
    limit('global', ctx.ip);
    sameOrigin(req);
    if (req.method === 'GET' && url.pathname.startsWith('/api/lookup/')) {
      return lookup(ctx, url.pathname.slice('/api/lookup/'.length));
    }
    const fn = routes[`${req.method} ${url.pathname}`];
    if (!fn) throw new HttpError(404, 'not found');
    return fn(ctx);
  }

  function fail(res, err) {
    if (res.headersSent) return res.destroy();
    if (err instanceof HttpError) {
      const extra = {};
      if (err.status === 413) extra.Connection = 'close';
      if (err.status === 429) extra['Retry-After'] = '60';
      return json(res, err.status, { error: err.message }, extra);
    }
    console.error('internal error:', err.message); // never log request data
    json(res, 500, { error: 'internal error' });
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => fail(res, err));
  });
  server.headersTimeout = 20_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 30_000;

  let lastPurge = 0;
  const timer = setInterval(() => {
    rl.sweep();
    sessions.sweep();
    if (Date.now() - lastPurge > 3_600_000) {
      lastPurge = Date.now();
      db.purgeExpired(today());
    }
  }, 60_000);
  timer.unref();
  db.purgeExpired(today());

  return {
    server,
    dbPath: db.file,
    listen: (port, host) =>
      new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => resolve(server.address()));
      }),
    async close() {
      clearInterval(timer);
      for (const set of waiters.values()) for (const wake of [...set]) wake();
      await new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections();
      });
      db.close();
    },
  };
}
