// End-to-end tests. The real client code (public/client.js + crypto.js) talks to the real server
// over HTTP, and the database file is then inspected as an attacker with a full disk copy would.
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { createApp, LIMITS, REPLACED as SERVER_REPLACED } from '../lib/app.js';
import { createApi } from '../public/api.js';
import { Messenger, KeyChangedError, REPLACED } from '../public/client.js';
import * as C from '../public/crypto.js';

const PEPPER = crypto.randomBytes(32);
const LOOSE = Object.fromEntries(Object.entries(LIMITS).map(([k, [, w]]) => [k, [100_000, w]]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const PW = {
  alice: 'correct horse battery staple',
  bob: 'another very long passphrase',
  carol: 'carol has a twelve char pass',
  eve: 'eve is the one who snoops!!',
  dave: 'dave will delete this account',
  frank: 'frank pokes at the http api',
  gina: 'gina blocks unwanted people',
  hank: 'hank keeps on messaging gina',
  iris: 'iris will change this soon',
  legacy: 'a password from the old days',
};
const NEW_PW = 'iris picked something new';
const SECRET_TEXT = 'meet me at the old lighthouse at midnight ' + crypto.randomUUID();
const REPLY_TEXT = 'bring the blue notebook ' + crypto.randomUUID();

function memoryStorage() {
  const m = new Map();
  return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, v), removeItem: (k) => m.delete(k) };
}

let app, base, dataDir;
let capturedBlob; // ciphertext exactly as the server held it, to prove it is gone after delivery
const events = {};
const people = {};

function newClient(name = 'anon', storage = memoryStorage()) {
  events[name] = [];
  return new Messenger({ api: createApi(base), storage, onEvent: (e) => events[name].push(e) });
}
const boxHash = (key) => crypto.createHmac('sha256', PEPPER).update('box|' + key).digest('hex');
const rawDb = () => new DatabaseSync(app.dbPath);
const msgCount = () => rawDb().prepare('SELECT COUNT(*) AS n FROM messages').get().n;

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'msgr-test-'));
  app = createApp({ dataDir, pepper: PEPPER, limits: LOOSE });
  const addr = await app.listen(0, '127.0.0.1');
  base = `http://127.0.0.1:${addr.port}`;
  for (const name of ['alice', 'bob', 'carol', 'eve', 'dave', 'frank', 'gina', 'hank']) {
    people[name] = newClient(name);
    await people[name].register(name + '_user', PW[name]);
  }
});

after(async () => {
  try {
    for (const p of Object.values(people)) p.stopPolling();
  } finally {
    await app.close(); // always release the port, even if a hook above misbehaves
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('every account gets a random, unique 10-digit key', () => {
  const keys = Object.values(people).map((p) => p.key);
  for (const k of keys) assert.match(k, /^[1-9]\d{9}$/);
  assert.equal(new Set(keys).size, keys.length);
});

test('alice -> bob: end-to-end message arrives, verifies, and is deleted from the server on delivery', async () => {
  const { alice, bob } = people;
  await alice.addContact(bob.key, 'Bob');
  await alice.sendText(bob.key, SECRET_TEXT);
  assert.equal(msgCount(), 1);

  // read the ciphertext straight out of the database (what a thief would see), so we can prove it vanishes later
  const rows = rawDb().prepare('SELECT blob FROM messages').all();
  assert.equal(rows.length, 1);
  capturedBlob = rows[0].blob;
  assert.ok(!Buffer.from(capturedBlob, 'base64url').includes(Buffer.from(SECRET_TEXT)), 'ciphertext must not contain plaintext');

  assert.equal(await bob.pollOnce(0), 1);
  const t = bob.thread(alice.key);
  assert.equal(t.length, 1);
  assert.equal(t[0].body, SECRET_TEXT);
  assert.equal(t[0].dir, 'in');
  assert.equal(bob.unread(alice.key), 1);
  assert.ok(bob.vault.contacts[alice.key].request, 'unknown sender shows up as a message request');

  assert.equal(msgCount(), 0, 'server copy is deleted once the client acknowledges');
  assert.equal(await bob.pollOnce(0), 0);

  await bob.sendText(alice.key, REPLY_TEXT);
  assert.equal(await alice.pollOnce(0), 1);
  assert.equal(alice.thread(bob.key).at(-1).body, REPLY_TEXT);
});

test('latest sign-in wins: a second device restores keys and contacts, and the first is told it was replaced', async () => {
  const { alice, bob } = people;
  assert.equal(REPLACED, SERVER_REPLACED, 'client and server agree on the marker');

  // alice's first device is long-polling when she signs in somewhere else
  events.alice.length = 0;
  const outcome = alice.pollOnce(25).then(() => 'still polling', (e) => e);
  await sleep(200);
  const alice2 = newClient('alice2');
  const t0 = Date.now();
  await alice2.login('alice_user', PW.alice);
  const err = await outcome;
  assert.equal(err.message, REPLACED);
  assert.ok(Date.now() - t0 < 5000, 'the displaced long-poll ends right away, not after 25 s');
  assert.ok(events.alice.some((e) => e.type === 'replaced'));

  assert.equal(alice2.key, alice.key);
  assert.ok(alice2.vault.contacts[bob.key], 'contacts live in the encrypted vault');
  assert.equal(alice2.thread(bob.key).length, 0, 'history stays on the original device only');

  // the displaced device cannot take mail away from the live one
  await assert.rejects(alice.pollOnce(0), { status: 401, message: REPLACED });
  await bob.sendText(alice.key, 'hello second device');
  assert.equal(await alice2.pollOnce(0), 1);
  assert.equal(alice2.thread(bob.key)[0].body, 'hello second device');
  people.alice = alice2; // the newest sign-in is the live one from here on
});

test('local history is encrypted at rest and survives a re-login on the same device', async () => {
  const storage = memoryStorage();
  const bobAgain = newClient('bobAgain', storage);
  await bobAgain.login('bob_user', PW.bob);
  await bobAgain.sendText(people.alice.key, 'stored locally ' + crypto.randomUUID());
  const blobs = [...[storage.getItem('msgr:h:' + (await C.deriveCredentials('bob_user', PW.bob)).uid.slice(0, 16))]];
  assert.ok(blobs[0] && !Buffer.from(blobs[0], 'base64url').includes(Buffer.from('stored locally')));
  await bobAgain.logout();

  const bobThird = newClient('bobThird', storage);
  await bobThird.login('bob_user', PW.bob);
  assert.ok(bobThird.thread(people.alice.key).some((m) => m.body.startsWith('stored locally')));
  people.bob = bobThird; // the newest sign-in is the live one from here on
  await people.alice.pollOnce(0); // drain
});

test('wrong password, unknown user and duplicate usernames are refused', async () => {
  const wrong = newClient();
  await assert.rejects(wrong.login('alice_user', 'definitely the wrong one'), { status: 401 });
  await assert.rejects(wrong.login('nobody_here', 'definitely the wrong one'), { status: 401 });
  await assert.rejects(newClient().register('alice_user', 'some other long password'), { status: 409 });
  await assert.rejects(newClient().register('shortpw', 'tiny'), /at least 12/);
  await assert.rejects(newClient().register('a!', 'a long enough password'), /Username/);
});

test('crypto: wrong recipient, wrong address, tampering and replays all fail; sizes are padded', async () => {
  const { alice, bob, carol } = people;
  const aliceKeys = await C.importIdentity(alice.vault.identity);
  const bobKeys = await C.importIdentity(bob.vault.identity);
  const carolKeys = await C.importIdentity(carol.vault.identity);
  const mk = (text) => C.encryptMessage({
    fromKey: alice.key, signKey: aliceKeys.signKey, toKey: bob.key,
    toEcdhPub: bob.vault.identity.ecdh.pub, text, id: C.randomId(), ts: Date.now(),
  });
  const blob = await mk('hi');

  const ok = await C.decryptMessage({ ecdhPriv: bobKeys.ecdhPriv, myKey: bob.key, blob });
  assert.equal(ok.inner.body, 'hi');
  assert.equal(ok.inner.from, alice.key);
  assert.ok(await C.verifyMessage(ok, bob.key, alice.vault.identity.ecdsa.pub));
  assert.ok(!(await C.verifyMessage(ok, bob.key, carol.vault.identity.ecdsa.pub)), 'wrong signer is rejected');
  assert.ok(!(await C.verifyMessage(ok, carol.key, alice.vault.identity.ecdsa.pub)), 'signature is bound to the recipient');

  await assert.rejects(C.decryptMessage({ ecdhPriv: carolKeys.ecdhPriv, myKey: bob.key, blob }), 'another person cannot decrypt');
  await assert.rejects(C.decryptMessage({ ecdhPriv: bobKeys.ecdhPriv, myKey: carol.key, blob }), 'ciphertext is bound to the address');

  const raw = C.b64uDecode(blob);
  raw[raw.length - 5] ^= 1;
  await assert.rejects(C.decryptMessage({ ecdhPriv: bobKeys.ecdhPriv, myKey: bob.key, blob: C.b64uEncode(raw) }), 'tampering is detected');

  // the signed envelope costs ~190 bytes, so up to ~60 characters share the smallest 256-byte bucket
  const short1 = C.b64uDecode(await mk('a')).length;
  const short2 = C.b64uDecode(await mk('b'.repeat(40))).length;
  assert.equal(short1, short2, 'short messages are padded to one size');
  assert.ok(C.b64uDecode(await mk('x'.repeat(1000))).length > short1, 'longer messages use a larger bucket');
  assert.notEqual(await mk('same'), await mk('same'), 'every encryption is unique');

  assert.deepEqual([...C.unpad(C.pad(new Uint8Array([1, 2, 3])))], [1, 2, 3]);
  assert.throws(() => C.pad(new Uint8Array(C.MAX_PADDED)), /too large/);
  assert.equal(C.formatKey('1234567890'), '123-456-7890');
  assert.equal(C.parseKey('(123) 456-7890'), '1234567890');
  assert.throws(() => C.parseKey('12345'), /10 digits/);
});

test('a forged sender is dropped and never shown in the victim contact\'s thread', async () => {
  const { alice, bob, eve } = people;
  const forgerSign = (await C.importIdentity(eve.vault.identity)).signKey;
  const api = createApi(base);
  const { token } = await api.openMailbox(eve.vault.key, eve.vault.secret);
  const blob = await C.encryptMessage({
    fromKey: alice.key, signKey: forgerSign, toKey: bob.key,
    toEcdhPub: bob.vault.identity.ecdh.pub, text: 'send me your money', id: C.randomId(), ts: Date.now(),
  });
  await api.send(token, bob.key, blob);
  assert.equal(msgCount(), 1);
  await bob.pollOnce(0);
  assert.ok(!bob.thread(alice.key).some((m) => m.body === 'send me your money'));
  assert.equal(msgCount(), 0, 'forgery is acknowledged away so it cannot clog the mailbox');
});

test('long-polling delivers a message the moment it is sent', async () => {
  const { alice, bob } = people;
  const started = Date.now();
  const waiting = bob.pollOnce(10);
  await sleep(300);
  await alice.sendText(bob.key, 'instant');
  assert.equal(await waiting, 1);
  assert.ok(Date.now() - started < 5000);
});

test('the server cannot be tricked into delivering to or deleting from the wrong mailbox', async () => {
  const { alice, bob, carol } = people;
  await alice.sendText(bob.key, 'only for bob');
  const api = createApi(base);
  const { token } = await api.openMailbox(carol.vault.key, carol.vault.secret);
  assert.equal((await api.inbox(token, 0)).messages.length, 0, 'carol sees nothing');
  const m = rawDb().prepare('SELECT id FROM messages WHERE box = ?').get(boxHash(bob.key));
  assert.ok(m, "bob's message is queued under bob's mailbox");
  assert.equal((await api.ack(token, [m.id])).deleted, 0, 'carol cannot delete bob\'s mail');
  assert.equal(await bob.pollOnce(0), 1);
});

test('deleting an account removes the login, the key and queued mail', async () => {
  const { alice, dave } = people;
  const daveKey = dave.key;
  await alice.addContact(daveKey, 'Dave');
  await alice.sendText(daveKey, 'queued for dave');
  await dave.deleteAccount();
  assert.equal(dave.loggedIn, false);
  await assert.rejects(newClient().login('dave_user', PW.dave), { status: 401 });
  await assert.rejects(newClient('x').addContact(daveKey), /./);
  assert.equal(rawDb().prepare('SELECT COUNT(*) AS n FROM messages WHERE box = ?').get(boxHash(daveKey)).n, 0);
  assert.equal(rawDb().prepare('SELECT COUNT(*) AS n FROM mailboxes WHERE box = ?').get(boxHash(daveKey)).n, 0);
  await assert.rejects(alice.sendText(daveKey, 'anyone there?'), { status: 404 });
});

test('HTTP hardening: headers, token separation, input validation, no path traversal', async () => {
  const res = await fetch(base + '/');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy'), /default-src 'none'/);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.match(res.headers.get('x-frame-options'), /DENY/);

  for (const p of ['/lib/app.js', '/server.js', '/data/messenger.db', '/..%2fserver.js', '/%2e%2e/server.js', '/public/../server.js']) {
    assert.equal((await fetch(base + p)).status, 404, p);
  }
  assert.equal((await fetch(base + '/api/nope')).status, 404);
  assert.equal((await fetch(base + '/api/inbox')).status, 401);
  assert.equal((await fetch(base + '/api/login', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'x' })).status, 415);
  assert.equal((await fetch(base + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{nope' })).status, 400);
  assert.equal((await fetch(base + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ uid: 'x', auth: 'y' }) })).status, 400);
  assert.equal((await fetch(base + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: 'x'.repeat(70_000) })).status, 413);
  assert.equal((await fetch(base + '/api/login', {
    method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://evil.example' }, body: '{}',
  })).status, 403);

  // an account session cannot act as a mailbox session and vice versa
  const api = createApi(base);
  const alice = people.frank; // a dedicated account: opening its mailbox here must not displace anyone else
  const creds = await C.deriveCredentials('frank_user', PW.frank);
  const login = await api.login(creds.uid, creds.auth);
  await assert.rejects(api.inbox(login.token, 0), { status: 401 });
  const box = await api.openMailbox(alice.vault.key, alice.vault.secret);
  await assert.rejects(api.putVault(box.token, login.vault, login.version), { status: 401 });

  // message size limits are enforced server-side
  await assert.rejects(api.send(box.token, alice.key, 'AAAA'), { status: 400 });
  await assert.rejects(api.send(box.token, alice.key, 'A'.repeat(40_000)), { status: 400 });
  await assert.rejects(api.send(box.token, '0000000000', 'A'.repeat(500)), { status: 404 });

  // vault updates are optimistic-concurrency checked
  await assert.rejects(api.putVault(login.token, login.vault, login.version + 7), { status: 409 });
  // public keys must be real curve points
  await assert.rejects(api.createMailbox(login.token, { ecdh: 'A'.repeat(87), ecdsa: 'A'.repeat(87), secret: C.randomSecret() }), { status: 400 });
});

test('a swapped server-side key is caught: sending warns, receiving holds messages until the user accepts', async () => {
  const { alice, bob, carol, eve } = people;
  const db = rawDb();
  const saved = db.prepare('SELECT ecdh, ecdsa FROM mailboxes WHERE box = ?').get(boxHash(bob.key));
  const swap = (key, ident) => db.prepare('UPDATE mailboxes SET ecdh = ?, ecdsa = ? WHERE box = ?').run(ident.ecdh.pub, ident.ecdsa.pub, boxHash(key));

  // sending: a fresh session compares the server's key for bob with the pinned one
  swap(bob.key, carol.vault.identity);
  const aliceFresh = newClient('aliceFresh');
  await aliceFresh.login('alice_user', PW.alice);
  await assert.rejects(aliceFresh.sendText(bob.key, 'hello?'), KeyChangedError);
  assert.equal(msgCount(), 0, 'nothing was sent');
  db.prepare('UPDATE mailboxes SET ecdh = ?, ecdsa = ? WHERE box = ?').run(saved.ecdh, saved.ecdsa, boxHash(bob.key));
  people.alice = aliceFresh; // the newest sign-in is the live one from here on

  // receiving: eve signs a message "from alice" and the server pretends eve's keys are alice's
  const savedAlice = db.prepare('SELECT ecdh, ecdsa FROM mailboxes WHERE box = ?').get(boxHash(alice.key));
  swap(alice.key, eve.vault.identity);
  const api = createApi(base);
  const { token } = await api.openMailbox(eve.vault.key, eve.vault.secret);
  const eveSign = (await C.importIdentity(eve.vault.identity)).signKey;
  const blob = await C.encryptMessage({
    fromKey: alice.key, signKey: eveSign, toKey: bob.key,
    toEcdhPub: bob.vault.identity.ecdh.pub, text: 'from a swapped key', id: C.randomId(), ts: Date.now(),
  });
  await api.send(token, bob.key, blob);
  events.bobThird.length = 0; // bob is now the newest sign-in (bobThird)
  await bob.pollOnce(0);
  assert.ok(!bob.thread(alice.key).some((m) => m.body === 'from a swapped key'), 'held back, not shown');
  assert.ok(bob.hasPendingKeyChange(alice.key));
  assert.ok(events.bobThird.some((e) => e.type === 'key-changed' && e.key === alice.key));
  await bob.acceptKeyChange(alice.key);
  assert.ok(bob.thread(alice.key).some((m) => m.body === 'from a swapped key'));
  assert.ok(!bob.hasPendingKeyChange(alice.key));
  db.prepare('UPDATE mailboxes SET ecdh = ?, ecdsa = ? WHERE box = ?').run(savedAlice.ecdh, savedAlice.ecdsa, boxHash(alice.key));
  db.close();
});

test('safety numbers match on both sides and differ for different pairs', async () => {
  const { alice, bob, carol } = people;
  await bob.addContact(carol.key, 'Carol');
  await alice.addContact(carol.key, 'Carol');
  const a = await alice.safetyNumber(bob.key);
  assert.match(a, /^\d{5}( \d{5}){5}$/);
  const bobsView = await C.safetyNumber(
    { key: bob.key, ecdh: bob.vault.identity.ecdh.pub, ecdsa: bob.vault.identity.ecdsa.pub },
    { key: alice.key, ecdh: alice.vault.identity.ecdh.pub, ecdsa: alice.vault.identity.ecdsa.pub },
  );
  assert.equal(a, bobsView);
  assert.notEqual(a, await alice.safetyNumber(carol.key));
});

test('blocking: blocked senders are discarded unseen and still cleared from the server; the block list follows the account', async () => {
  const { gina, hank } = people;
  await hank.sendText(gina.key, 'first hello');
  assert.equal(await gina.pollOnce(0), 1);
  assert.equal(gina.thread(hank.key).length, 1);
  assert.ok(gina.vault.contacts[hank.key].request);

  await gina.blockContact(hank.key);
  assert.ok(gina.isBlocked(hank.key));
  assert.equal(gina.thread(hank.key).length, 0, 'the conversation is deleted from this device');
  assert.ok(!gina.vault.contacts[hank.key]);

  // the server cannot know about blocks (it does not know who sent what), so it still accepts the message...
  await hank.sendText(gina.key, 'please answer me');
  assert.equal(msgCount(), 1);
  assert.equal(await gina.pollOnce(0), 1);
  assert.equal(msgCount(), 0, '...but it is acknowledged away, so it cannot clog the mailbox');
  assert.equal(gina.thread(hank.key).length, 0, 'never shown');
  assert.ok(!gina.vault.contacts[hank.key], 'and does not create a new message request');

  await assert.rejects(gina.addContact(hank.key), /blocked/);
  await assert.rejects(gina.sendText(hank.key, 'hi'), /blocked/);
  await assert.rejects(gina.blockContact(gina.key), /yourself/);

  // the block list lives in the encrypted vault, so a new device has it too
  const gina2 = newClient('gina2');
  await gina2.login('gina_user', PW.gina);
  assert.ok(gina2.isBlocked(hank.key));
  await gina2.unblock(hank.key);
  assert.ok(!gina2.isBlocked(hank.key));
  await hank.sendText(gina.key, 'thanks for unblocking');
  assert.equal(await gina2.pollOnce(0), 1);
  assert.equal(gina2.thread(hank.key)[0].body, 'thanks for unblocking');
  people.gina = gina2;
});

test('changing the password re-keys the account but keeps the key, contacts and saved history', async () => {
  const { bob } = people;
  const storage = memoryStorage();
  const iris = newClient('iris', storage);
  await iris.register('iris_user', PW.iris);
  const key = iris.key;
  await iris.addContact(bob.key, 'Bob');
  await iris.sendText(bob.key, 'before the change');

  // an account session that exists before the change must not survive it
  const api = createApi(base);
  const oldCreds = await C.deriveCredentials('iris_user', PW.iris);
  const oldSession = await api.login(oldCreds.uid, oldCreds.auth);

  await assert.rejects(iris.changePassword('not my password!!', NEW_PW), /current password is wrong/);
  await assert.rejects(iris.changePassword(PW.iris, 'short'), /at least 12/);
  await assert.rejects(iris.changePassword(PW.iris, PW.iris), /different/);
  assert.ok((await api.login(oldCreds.uid, oldCreds.auth)).token, 'failed attempts changed nothing');

  await iris.changePassword(PW.iris, NEW_PW);

  await assert.rejects(newClient().login('iris_user', PW.iris), { status: 401 }, 'the old password is dead');
  await assert.rejects(api.putVault(oldSession.token, oldSession.vault, oldSession.version), { status: 401 }, 'old sessions end');

  const again = newClient('iris2', storage);
  await again.login('iris_user', NEW_PW);
  assert.equal(again.key, key, 'same 10-digit key');
  assert.ok(again.vault.contacts[bob.key], 'contacts survived');
  assert.equal(again.thread(bob.key)[0].body, 'before the change', 'history saved on this device is still readable');
  await again.sendText(bob.key, 'after the change');
  assert.equal(await bob.pollOnce(0), 2);

  // the server also re-checks the current password itself (a stale or hostile client gets a clear 403, not a 401 loop)
  const newCreds = await C.deriveCredentials('iris_user', NEW_PW);
  const live = await api.login(newCreds.uid, newCreds.auth);
  await assert.rejects(
    api.changePassword(live.token, { auth: C.randomSecret(), newAuth: C.randomSecret(), vault: live.vault, version: live.version }),
    { status: 403 },
  );
  await assert.rejects(
    api.changePassword(live.token, { auth: newCreds.auth, newAuth: C.randomSecret(), vault: live.vault, version: live.version + 3 }),
    { status: 409 },
  );
  await again.logout();
});

test('accounts made before the random history key existed are upgraded in place without losing history', async () => {
  const creds = await C.deriveCredentials('legacy_user', PW.legacy);
  const api = createApi(base);
  const { token } = await api.createAccount(creds.uid, creds.auth);
  const identity = await C.generateIdentity();
  const secret = C.randomSecret();
  const { key } = await api.createMailbox(token, { ecdh: identity.ecdh.pub, ecdsa: identity.ecdsa.pub, secret });
  const oldVault = { v: 1, key, secret, identity, contacts: {} }; // no `local`, no `blocked`
  await api.putVault(token, await C.sealJson(creds.vaultKey, oldVault, 'msgr1/vault'), 0);

  const histName = 'msgr:h:' + creds.uid.slice(0, 16);
  const storage = memoryStorage();
  const hist = { threads: { [people.bob.key]: [{ id: 'x1', dir: 'in', ts: 1, at: 1, body: 'saved long ago' }] }, pending: {}, unread: {} };
  storage.setItem(histName, await C.sealJson(creds.localKey, hist, 'msgr1/local')); // sealed the old way

  const first = newClient('legacy1', storage);
  await first.login('legacy_user', PW.legacy);
  assert.equal(first.thread(people.bob.key)[0].body, 'saved long ago');
  assert.ok(first.vault.local, 'the vault now carries a random history secret');

  const blob = storage.getItem(histName);
  await assert.rejects(C.openJson(creds.localKey, blob, 'msgr1/local'), 'no longer sealed under the password-derived key');
  await C.openJson(await C.localKeyFromSecret(first.vault.local), blob, 'msgr1/local');

  const second = newClient('legacy2', storage);
  await second.login('legacy_user', PW.legacy);
  assert.equal(second.vault.local, first.vault.local, 'the upgrade was saved to the server');
  assert.equal(second.thread(people.bob.key)[0].body, 'saved long ago');
  await second.logout();
});

test('HACKED SERVER: a full copy of the data directory contains no usernames, passwords, keys, plaintext or private keys', async () => {
  const needles = new Map();
  const add = (label, value) => value && needles.set(label, Buffer.from(String(value)));

  for (const name of ['alice', 'bob', 'carol', 'eve', 'dave', 'frank', 'gina', 'hank']) {
    add(`username ${name}`, name + '_user');
    add(`password ${name}`, PW[name]);
    const p = people[name];
    if (!p.vault) continue;
    add(`10-digit key ${name}`, p.key);
    add(`formatted key ${name}`, C.formatKey(p.key));
    add(`mailbox secret ${name}`, p.vault.secret);
    add(`history key ${name}`, p.vault.local);
    add(`ecdh private ${name}`, p.vault.identity.ecdh.priv.d);
    add(`ecdsa private ${name}`, p.vault.identity.ecdsa.priv.d);
  }
  add('username iris', 'iris_user');
  add('old password iris', PW.iris);
  add('new password iris', NEW_PW);
  add('username legacy', 'legacy_user');
  add('password legacy', PW.legacy);
  for (const phrase of ['first hello', 'please answer me', 'thanks for unblocking', 'before the change', 'after the change', 'saved long ago']) {
    add(`message text "${phrase}"`, phrase);
  }
  for (const name of ['alice', 'bob']) {
    const creds = await C.deriveCredentials(name + '_user', PW[name]);
    add(`uid ${name}`, creds.uid);
    add(`auth ${name}`, creds.auth);
  }
  add('message 1 plaintext', SECRET_TEXT);
  add('message 2 plaintext', REPLY_TEXT);
  add('message 1 plaintext (word)', 'lighthouse');
  add('delivered ciphertext', capturedBlob);

  const files = fs.readdirSync(dataDir).map((f) => path.join(dataDir, f));
  assert.ok(files.length >= 1);
  const found = [];
  for (const f of files) {
    const buf = fs.readFileSync(f);
    for (const [label, needle] of needles) if (buf.includes(needle)) found.push(`${label} in ${path.basename(f)}`);
  }
  assert.deepEqual(found, [], 'secrets leaked into the database files');

  // control: the scan itself works, and public keys (which are meant to be public) ARE there
  const control = fs.readFileSync(app.dbPath);
  assert.ok(control.includes(Buffer.from(people.bob.vault.identity.ecdh.pub)), 'scan control failed');
});

test('rate limiting blocks password guessing', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'msgr-rl-'));
  const limited = createApp({ dataDir: dir, pepper: PEPPER, limits: { ...LOOSE, login: [3, 60_000], register: [2, 60_000] } });
  const addr = await limited.listen(0, '127.0.0.1');
  const api = createApi(`http://127.0.0.1:${addr.port}`);
  try {
    const guess = () => api.login(C.randomSecret(), C.randomSecret());
    for (let i = 0; i < 3; i++) await assert.rejects(guess(), { status: 401 });
    await assert.rejects(guess(), { status: 429 });
    await api.createAccount(C.randomSecret(), C.randomSecret());
    await api.createAccount(C.randomSecret(), C.randomSecret());
    await assert.rejects(api.createAccount(C.randomSecret(), C.randomSecret()), { status: 429 });
  } finally {
    await limited.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
