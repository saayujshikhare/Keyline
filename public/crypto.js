// All cryptography lives here and runs on the user's device (browsers and Node 22+ via WebCrypto).
// The server never sees a password, a username, a private key, or a plaintext message.
//
//   password + username --PBKDF2--> master --HKDF--> auth (login proof) | vaultKey | localKey
//   message: fresh ephemeral ECDH key -> shared secret with recipient -> HKDF -> AES-256-GCM,
//            signed inside the ciphertext with the sender's ECDSA identity key, padded to hide length.

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();

export const PBKDF2_ITERATIONS = 600_000;
export const UNAME_ITERATIONS = 210_000;
export const MIN_PADDED = 256;
export const MAX_PADDED = 16_384;
export const MAX_TEXT_CHARS = 2000;
export const MIN_PASSWORD_LENGTH = 12;

// ------------------------------------------------------------------ encoding helpers

export function b64uEncode(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function b64uDecode(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) throw new Error('bad base64url');
  const s = atob(str.replaceAll('-', '+').replaceAll('_', '/'));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
export const randomId = () => b64uEncode(rand(16)); // 22 chars
export const randomSecret = () => b64uEncode(rand(32)); // 43 chars

export function parseKey(input) {
  const digits = String(input ?? '').replace(/\D/g, '');
  if (!/^\d{10}$/.test(digits)) throw new Error('A key is exactly 10 digits.');
  return digits;
}

export const formatKey = (k) => String(k).replace(/^(\d{3})(\d{3})(\d{4})$/, '$1-$2-$3');

// ------------------------------------------------------------------ account credentials

export function normalizeUsername(name) {
  const u = String(name ?? '').normalize('NFKC').trim().toLowerCase();
  if (!/^[a-z0-9_.-]{3,32}$/.test(u)) {
    throw new Error('Username must be 3-32 characters: letters, numbers, dot, dash or underscore.');
  }
  return u;
}

export function checkPassword(password) {
  if ([...String(password ?? '')].length < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters. A few random words works well.`);
  }
}

async function pbkdf2(secretBytes, saltBytes, iterations) {
  const k = await subtle.importKey('raw', secretBytes, 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations }, k, 256));
}

async function hkdfBytes(secret, salt, info, bits = 256) {
  const k = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) }, k, bits));
}

const aesKey = (bytes) => subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);

/** Derive everything from username + password. This is the only place a password is used. */
export async function deriveCredentials(username, password) {
  const u = normalizeUsername(username);
  const [uidBits, master] = await Promise.all([
    pbkdf2(te.encode(u), te.encode('msgr1/uid'), UNAME_ITERATIONS),
    pbkdf2(te.encode(String(password).normalize('NFKC')), te.encode('msgr1/master/' + u), PBKDF2_ITERATIONS),
  ]);
  const none = new Uint8Array(0);
  return {
    uid: b64uEncode(uidBits), // identifies the account; the server only ever stores a keyed hash of it
    auth: b64uEncode(await hkdfBytes(master, none, 'msgr1/auth')), // login proof
    vaultKey: await aesKey(await hkdfBytes(master, none, 'msgr1/vault')),
    localKey: await aesKey(await hkdfBytes(master, none, 'msgr1/local')),
  };
}

/**
 * Key for the history saved on this device. It comes from a random secret kept inside the vault, NOT
 * from the password, so changing your password does not make history saved on other devices unreadable.
 */
export async function localKeyFromSecret(secretB64) {
  return aesKey(await hkdfBytes(b64uDecode(secretB64), new Uint8Array(0), 'msgr1/local2'));
}

// ------------------------------------------------------------------ sealed JSON (vault, local history)

export async function sealJson(key, obj, aad) {
  const iv = rand(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(aad) }, key, te.encode(JSON.stringify(obj)));
  return b64uEncode(concat(iv, new Uint8Array(ct)));
}

export async function openJson(key, blob, aad) {
  const raw = b64uDecode(blob);
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: raw.slice(0, 12), additionalData: te.encode(aad) },
    key,
    raw.slice(12),
  );
  return JSON.parse(td.decode(pt));
}

// ------------------------------------------------------------------ identity keys

export async function generateIdentity() {
  const ecdh = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const ecdsa = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return {
    ecdh: {
      priv: await subtle.exportKey('jwk', ecdh.privateKey),
      pub: b64uEncode(await subtle.exportKey('raw', ecdh.publicKey)),
    },
    ecdsa: {
      priv: await subtle.exportKey('jwk', ecdsa.privateKey),
      pub: b64uEncode(await subtle.exportKey('raw', ecdsa.publicKey)),
    },
  };
}

export async function importIdentity(id) {
  return {
    ecdhPriv: await subtle.importKey('jwk', id.ecdh.priv, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']),
    signKey: await subtle.importKey('jwk', id.ecdsa.priv, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']),
  };
}

const importEcdhPub = (b64) => subtle.importKey('raw', b64uDecode(b64), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
const importEcdsaPub = (b64) => subtle.importKey('raw', b64uDecode(b64), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);

/** 30-digit number both parties can read to each other to confirm nobody swapped keys. */
export async function safetyNumber(a, b) {
  const parts = [a, b].map((x) => `${x.key}|${x.ecdh}|${x.ecdsa}`).sort();
  const d = new Uint8Array(await subtle.digest('SHA-256', te.encode('msgr1/safety|' + parts.join('|'))));
  const dv = new DataView(d.buffer);
  const groups = [];
  for (let i = 0; i < 6; i++) groups.push(String(dv.getUint32(i * 4) % 100000).padStart(5, '0'));
  return groups.join(' ');
}

// ------------------------------------------------------------------ messages

export function pad(bytes) {
  const need = 4 + bytes.length;
  let size = MIN_PADDED;
  while (size < need) size *= 2;
  if (size > MAX_PADDED) throw new Error('That message is too large to send.');
  const out = new Uint8Array(size);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

export function unpad(padded) {
  if (padded.length < 4) throw new Error('bad padding');
  const len = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0);
  if (len > padded.length - 4) throw new Error('bad padding');
  return padded.slice(4, 4 + len);
}

async function messageKey(sharedBits, ephPub) {
  return aesKey(await hkdfBytes(new Uint8Array(sharedBits), ephPub, 'msgr1/msg'));
}

/**
 * Seal a text message for one recipient. The result is: ephemeral public key (65) | iv (12) | ciphertext+tag.
 * The sender's identity and signature are INSIDE the ciphertext, so the server cannot see who wrote it.
 */
export async function encryptMessage({ fromKey, signKey, toKey, toEcdhPub, text, id, ts }) {
  const signed = JSON.stringify({ v: 1, id, from: fromKey, ts, body: text });
  const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signKey, te.encode(`msgr1|to:${toKey}|${signed}`));
  const padded = pad(te.encode(JSON.stringify({ m: signed, s: b64uEncode(sig) })));

  const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const ephPub = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
  const shared = await subtle.deriveBits({ name: 'ECDH', public: await importEcdhPub(toEcdhPub) }, eph.privateKey, 256);
  const iv = rand(12);
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: te.encode(`msgr1|to:${toKey}`) },
    await messageKey(shared, ephPub),
    padded,
  );
  return b64uEncode(concat(ephPub, iv, new Uint8Array(ct)));
}

/** Decrypt a message addressed to us. Throws on anything malformed or tampered. Does NOT check the sender. */
export async function decryptMessage({ ecdhPriv, myKey, blob }) {
  const raw = b64uDecode(blob);
  if (raw.length < 65 + 12 + 16 + MIN_PADDED) throw new Error('too short');
  const ephPub = raw.slice(0, 65);
  const iv = raw.slice(65, 77);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: await importEcdhPub(b64uEncode(ephPub)) }, ecdhPriv, 256);
  const padded = new Uint8Array(
    await subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: te.encode(`msgr1|to:${myKey}`) },
      await messageKey(shared, ephPub),
      raw.slice(77),
    ),
  );
  const outer = JSON.parse(td.decode(unpad(padded)));
  const inner = JSON.parse(outer.m);
  const ok =
    inner && inner.v === 1 &&
    typeof inner.id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(inner.id) &&
    typeof inner.from === 'string' && /^\d{10}$/.test(inner.from) &&
    Number.isFinite(inner.ts) &&
    typeof inner.body === 'string' && inner.body.length <= 20_000;
  if (!ok) throw new Error('malformed message');
  return {
    inner: { id: inner.id, from: inner.from, ts: inner.ts, body: inner.body },
    signed: outer.m,
    sig: b64uDecode(outer.s),
  };
}

/** Check that `msg` really was signed by the holder of senderEcdsaPub and was meant for toKey. */
export async function verifyMessage(msg, toKey, senderEcdsaPub) {
  try {
    return await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      await importEcdsaPub(senderEcdsaPub),
      msg.sig,
      te.encode(`msgr1|to:${toKey}|${msg.signed}`),
    );
  } catch {
    return false;
  }
}
