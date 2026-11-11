// Messenger: the whole client-side protocol (register, login, send, receive, verify).
// It has no DOM code, so the browser UI (app.js) and the automated tests drive the exact same logic.
import * as C from './crypto.js';

const VAULT_AAD = 'msgr1/vault';
const HIST_AAD = 'msgr1/local';
const MAX_PER_THREAD = 500;
const MAX_CONTACTS = 500;
const MAX_BLOCKED = 1000;
export const REPLACED = 'signed-in-elsewhere'; // must match the server: a newer sign-in took over this mailbox

export class KeyChangedError extends Error {
  constructor(key) {
    super("This contact's safety number has changed. Verify it before sending anything.");
    this.name = 'KeyChangedError';
    this.key = key;
  }
}

const sleep = (ms, signal) =>
  new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => { clearTimeout(t); resolve(); }, { once: true });
  });

export class Messenger {
  #api;
  #storage;
  #emit;
  #creds = null;
  #keys = null;
  #acctToken = null;
  #boxToken = null;
  #vaultVersion = 0;
  #vaultLock = Promise.resolve();
  #histLock = Promise.resolve();
  #checked = new Set(); // peers whose server-side keys we already compared with our pinned copy this session
  #changed = {}; // key -> proposed new public keys awaiting the user's decision
  #polling = null;
  #offline = false;
  #username = null;
  #localKey = null; // encrypts the history saved on this device
  vault = null;
  hist = { threads: {}, pending: {}, unread: {} };

  constructor({ api, storage, onEvent = () => {} }) {
    this.#api = api;
    this.#storage = storage;
    this.#emit = onEvent;
  }

  get loggedIn() { return !!this.vault; }
  get key() { return this.vault?.key; }

  // ------------------------------------------------------------ account lifecycle

  async register(username, password) {
    C.checkPassword(password);
    const creds = await C.deriveCredentials(username, password);
    this.#username = C.normalizeUsername(username);
    const { token } = await this.#api.createAccount(creds.uid, creds.auth);
    await this.#provision(creds, token);
  }

  async login(username, password) {
    const creds = await C.deriveCredentials(username, password);
    this.#username = C.normalizeUsername(username);
    const r = await this.#api.login(creds.uid, creds.auth);
    if (!r.vault) return this.#provision(creds, r.token); // an earlier signup was interrupted: finish it
    let vault;
    try {
      vault = await C.openJson(creds.vaultKey, r.vault, VAULT_AAD);
    } catch {
      throw new Error('Your vault could not be decrypted.');
    }
    this.#acctToken = r.token;
    this.#vaultVersion = r.version;
    await this.#start(creds, vault);
  }

  async #provision(creds, acctToken) {
    const identity = await C.generateIdentity();
    const secret = C.randomSecret();
    const { key } = await this.#api.createMailbox(acctToken, { ecdh: identity.ecdh.pub, ecdsa: identity.ecdsa.pub, secret });
    const vault = { v: 1, key, secret, identity, contacts: {}, blocked: {}, local: C.randomSecret() };
    const blob = await C.sealJson(creds.vaultKey, vault, VAULT_AAD);
    const { version } = await this.#api.putVault(acctToken, blob, 0);
    this.#acctToken = acctToken;
    this.#vaultVersion = version;
    await this.#start(creds, vault);
  }

  async #start(creds, vault) {
    try {
      this.#creds = creds;
      this.vault = vault;
      this.#keys = await C.importIdentity(vault.identity);
      // Accounts made before the random history key existed keep the password-derived one until upgraded.
      this.#localKey = vault.local ? await C.localKeyFromSecret(vault.local) : creds.localKey;
      this.#boxToken = (await this.#api.openMailbox(vault.key, vault.secret)).token;
      await this.#loadHistory();
      if (!vault.local) await this.#upgradeLocalKey();
    } catch (e) {
      this.#reset();
      throw e;
    }
  }

  async #upgradeLocalKey() {
    this.vault.local = C.randomSecret();
    try {
      await this.#saveVault(); // if another device upgraded first, this adopts its secret instead
    } catch {
      delete this.vault.local; // stay on the old key and try again at the next login
      return;
    }
    this.#localKey = await C.localKeyFromSecret(this.vault.local);
    await this.#saveHistory();
  }

  #reset() {
    this.#localKey = this.#username = null;
    this.#creds = this.#keys = this.#acctToken = this.#boxToken = this.vault = null;
    this.#vaultVersion = 0;
    this.#checked.clear();
    this.#changed = {};
    this.hist = { threads: {}, pending: {}, unread: {} };
  }

  async logout() {
    this.stopPolling();
    const tokens = [this.#acctToken, this.#boxToken].filter(Boolean);
    this.#reset();
    await Promise.allSettled(tokens.map((t) => this.#api.logout(t)));
  }

  async deleteAccount() {
    this.stopPolling();
    const name = this.#histName();
    await this.#box((t) => this.#api.deleteMailbox(t));
    await this.#acct((t) => this.#api.deleteAccount(t));
    this.#storage.removeItem(name);
    this.#reset();
  }

  // ------------------------------------------------------------ sessions that renew themselves

  async #relogin() {
    const r = await this.#api.login(this.#creds.uid, this.#creds.auth);
    this.#acctToken = r.token;
    return r;
  }

  async #acct(fn) {
    try {
      return await fn(this.#acctToken);
    } catch (e) {
      if (e.status !== 401) throw e;
      await this.#relogin();
      return fn(this.#acctToken);
    }
  }

  async #box(fn) {
    try {
      return await fn(this.#boxToken);
    } catch (e) {
      if (e.status !== 401) throw e;
      if (e.message === REPLACED) { // someone signed in on another device: do NOT fight for the mailbox
        this.#emit({ type: 'replaced' });
        throw e;
      }
      this.#boxToken = (await this.#api.openMailbox(this.vault.key, this.vault.secret)).token;
      return fn(this.#boxToken);
    }
  }

  // ------------------------------------------------------------ persistence

  #histName() { return 'msgr:h:' + this.#creds.uid.slice(0, 16); }

  async #loadHistory() {
    this.hist = { threads: {}, pending: {}, unread: {} };
    const raw = this.#storage.getItem(this.#histName());
    if (!raw) return;
    try {
      Object.assign(this.hist, await C.openJson(this.#localKey, raw, HIST_AAD));
    } catch { /* unreadable local copy: start fresh */ }
  }

  #saveHistory() {
    const run = this.#histLock.then(async () => {
      if (!this.#creds) return;
      this.#storage.setItem(this.#histName(), await C.sealJson(this.#localKey, this.hist, HIST_AAD));
    });
    this.#histLock = run.catch(() => {});
    return run;
  }

  #saveVault() {
    const run = this.#vaultLock.then(async () => {
      for (let attempt = 0; attempt < 3; attempt++) {
        const blob = await C.sealJson(this.#creds.vaultKey, this.vault, VAULT_AAD);
        try {
          const r = await this.#acct((t) => this.#api.putVault(t, blob, this.#vaultVersion));
          this.#vaultVersion = r.version;
          return;
        } catch (e) {
          if (e.status !== 409) throw e;
          // Another device changed the vault: merge its contacts into ours and try again.
          const fresh = await this.#relogin();
          this.#vaultVersion = fresh.version;
          if (fresh.vault) {
            const remote = await C.openJson(this.#creds.vaultKey, fresh.vault, VAULT_AAD);
            this.vault.contacts = { ...remote.contacts, ...this.vault.contacts };
            this.vault.blocked = { ...remote.blocked, ...this.vault.blocked };
            if (remote.local) this.vault.local = remote.local; // never fork the history key
          }
        }
      }
      throw new Error('Could not sync your contacts, try again.');
    });
    this.#vaultLock = run.catch(() => {});
    return run;
  }

  // ------------------------------------------------------------ contacts

  contacts() {
    return Object.entries(this.vault.contacts).map(([key, c]) => ({ key, ...c }));
  }

  async addContact(rawKey, name = '') {
    const key = C.parseKey(rawKey);
    if (this.isBlocked(key)) throw new Error('You blocked this key. Unblock it first (Account menu, Blocked people).');
    const label = String(name).trim().slice(0, 40);
    const existing = this.vault.contacts[key];
    if (existing) {
      if (label) { existing.name = label; delete existing.request; await this.#saveVault(); this.#emit({ type: 'contacts' }); }
      return key;
    }
    if (Object.keys(this.vault.contacts).length >= MAX_CONTACTS) throw new Error('Contact limit reached.');
    const info = await this.#box((t) => this.#api.lookup(t, key)); // 404 -> "No user with that key"
    this.vault.contacts[key] = { name: label, ecdh: info.ecdh, ecdsa: info.ecdsa, added: Date.now() };
    this.#checked.add(key);
    await this.#saveVault();
    this.#emit({ type: 'contacts' });
    return key;
  }

  async renameContact(key, name) {
    const c = this.vault.contacts[key];
    if (!c) return;
    c.name = String(name).trim().slice(0, 40);
    delete c.request;
    await this.#saveVault();
    this.#emit({ type: 'contacts' });
  }

  async removeContact(key) {
    delete this.vault.contacts[key];
    delete this.hist.threads[key];
    delete this.hist.pending[key];
    delete this.hist.unread[key];
    this.#checked.delete(key);
    await this.#saveVault();
    await this.#saveHistory();
    this.#emit({ type: 'contacts' });
  }

  // ------------------------------------------------------------ blocking

  isBlocked(key) { return !!this.vault.blocked?.[key]; }
  blockedKeys() { return Object.keys(this.vault.blocked ?? {}); }

  /** Their messages are discarded unseen from now on, and the conversation is deleted from this device. */
  async blockContact(rawKey) {
    const key = C.parseKey(rawKey);
    if (key === this.key) throw new Error("You can't block yourself.");
    if (!this.isBlocked(key) && this.blockedKeys().length >= MAX_BLOCKED) throw new Error('Block list is full.');
    (this.vault.blocked ??= {})[key] = Date.now();
    delete this.vault.contacts[key];
    delete this.hist.threads[key];
    delete this.hist.pending[key];
    delete this.hist.unread[key];
    delete this.#changed[key];
    this.#checked.delete(key);
    await this.#saveVault();
    await this.#saveHistory();
    this.#emit({ type: 'contacts' });
  }

  async unblock(rawKey) {
    const key = C.parseKey(rawKey);
    if (!this.vault.blocked?.[key]) return;
    delete this.vault.blocked[key];
    await this.#saveVault();
    this.#emit({ type: 'contacts' });
  }

  // ------------------------------------------------------------ password

  /** Re-keys the vault under the new password. The 10-digit key and all contacts stay exactly as they are. */
  async changePassword(current, next) {
    C.checkPassword(next);
    if (current === next) throw new Error('Choose a password that is different from your current one.');
    const [cur, nxt] = await Promise.all([
      C.deriveCredentials(this.#username, current),
      C.deriveCredentials(this.#username, next),
    ]);
    if (cur.auth !== this.#creds.auth) throw new Error('Your current password is wrong.');
    await this.#vaultLock; // let any save in flight finish, so the new vault has the latest contacts
    const blob = await C.sealJson(nxt.vaultKey, this.vault, VAULT_AAD);
    const r = await this.#acct((t) =>
      this.#api.changePassword(t, { auth: cur.auth, newAuth: nxt.auth, vault: blob, version: this.#vaultVersion }),
    );
    this.#creds = nxt;
    this.#acctToken = r.token;
    this.#vaultVersion = r.version;
  }

  /** Safety number with a contact. With useProposed, the number for the NEW keys awaiting the user's decision. */
  async safetyNumber(key, useProposed = false) {
    const me = this.vault.identity;
    let keys = this.vault.contacts[key];
    if (useProposed) {
      this.#changed[key] ??= await this.#box((t) => this.#api.lookup(t, key)); // e.g. after a page reload
      keys = this.#changed[key];
    }
    return C.safetyNumber(
      { key: this.key, ecdh: me.ecdh.pub, ecdsa: me.ecdsa.pub },
      { key, ecdh: keys.ecdh, ecdsa: keys.ecdsa },
    );
  }

  thread(key) { return this.hist.threads[key] ?? []; }
  unread(key) { return this.hist.unread[key] ?? 0; }
  hasPendingKeyChange(key) { return (this.hist.pending[key]?.length ?? 0) > 0 || !!this.#changed[key]; }

  async markRead(key) {
    if (!this.hist.unread[key]) return;
    this.hist.unread[key] = 0;
    await this.#saveHistory();
  }

  /** The user reviewed the new safety number and trusts it: pin the new keys and release held messages. */
  async acceptKeyChange(key) {
    const c = this.vault.contacts[key];
    if (!c) return;
    const next = this.#changed[key] ?? (await this.#box((t) => this.#api.lookup(t, key)));
    c.ecdh = next.ecdh;
    c.ecdsa = next.ecdsa;
    delete this.#changed[key];
    this.#checked.add(key);
    await this.#saveVault();
    for (const p of this.hist.pending[key] ?? []) {
      const msg = { signed: p.signed, sig: C.b64uDecode(p.sig) };
      if (await C.verifyMessage(msg, this.key, c.ecdsa)) {
        this.#append(key, { id: p.id, dir: 'in', ts: p.ts, at: p.at, body: p.body });
        this.hist.unread[key] = (this.hist.unread[key] ?? 0) + 1;
      }
    }
    delete this.hist.pending[key];
    await this.#saveHistory();
    this.#emit({ type: 'contacts' });
    this.#emit({ type: 'message', key });
  }

  // ------------------------------------------------------------ sending

  async sendText(rawKey, text) {
    const key = C.parseKey(rawKey);
    if (this.isBlocked(key)) throw new Error('You blocked this key. Unblock it first to send a message.');
    const body = String(text).trim();
    if (!body) throw new Error('Message is empty.');
    if ([...body].length > C.MAX_TEXT_CHARS) throw new Error(`Messages are limited to ${C.MAX_TEXT_CHARS} characters.`);

    let contact = this.vault.contacts[key];
    if (!this.#checked.has(key)) {
      const info = await this.#box((t) => this.#api.lookup(t, key));
      if (!contact) {
        contact = this.vault.contacts[key] = { name: '', ecdh: info.ecdh, ecdsa: info.ecdsa, added: Date.now() };
        await this.#saveVault();
        this.#emit({ type: 'contacts' });
      } else if (contact.ecdh !== info.ecdh || contact.ecdsa !== info.ecdsa) {
        this.#changed[key] = { ecdh: info.ecdh, ecdsa: info.ecdsa };
        throw new KeyChangedError(key);
      }
      this.#checked.add(key);
    }

    const id = C.randomId();
    const ts = Date.now();
    const blob = await C.encryptMessage({
      fromKey: this.key,
      signKey: this.#keys.signKey,
      toKey: key,
      toEcdhPub: contact.ecdh,
      text: body,
      id,
      ts,
    });
    await this.#box((t) => this.#api.send(t, key, blob));
    const item = { id, dir: 'out', ts, at: ts, body };
    this.#append(key, item);
    await this.#saveHistory();
    this.#emit({ type: 'message', key });
    return item;
  }

  #append(key, item) {
    const t = (this.hist.threads[key] ??= []);
    t.push(item);
    if (t.length > MAX_PER_THREAD) t.splice(0, t.length - MAX_PER_THREAD);
  }

  // ------------------------------------------------------------ receiving

  /** Fetch waiting messages (optionally long-polling), store them locally, then tell the server to delete them. */
  async pollOnce(waitSec = 0, signal) {
    const { messages } = await this.#box((t) => this.#api.inbox(t, waitSec, signal));
    if (!messages.length) return 0;
    const done = [];
    let transient = null;
    let changed = false;
    for (const m of messages) {
      try {
        if ((await this.#receive(m)).changed) changed = true;
        done.push(m.id);
      } catch (e) {
        transient = e; // e.g. network hiccup during a key lookup: leave it on the server for next time
      }
    }
    if (changed) await this.#saveHistory(); // persist locally BEFORE the server deletes its copy
    if (done.length) await this.#box((t) => this.#api.ack(t, done));
    if (transient) throw transient;
    return done.length;
  }

  #hasMessage(key, id) {
    return (this.hist.threads[key] ?? []).some((x) => x.id === id) || (this.hist.pending[key] ?? []).some((x) => x.id === id);
  }

  async #lookupOrNull(key) {
    try {
      return await this.#box((t) => this.#api.lookup(t, key));
    } catch (e) {
      if (e.status === 404) return null;
      throw e;
    }
  }

  async #receive(m) {
    let msg;
    try {
      msg = await C.decryptMessage({ ecdhPriv: this.#keys.ecdhPriv, myKey: this.key, blob: m.blob });
    } catch {
      return { changed: false }; // garbage or tampered: drop it
    }
    const { id, from, ts, body } = msg.inner;
    if (this.isBlocked(from)) return { changed: false }; // discarded unseen (and acknowledged, so it leaves the server)
    if (this.#hasMessage(from, id)) return { changed: false }; // replayed by the server

    const me = this.vault.identity;
    let pinned = from === this.key ? { ecdh: me.ecdh.pub, ecdsa: me.ecdsa.pub } : this.vault.contacts[from];
    let isNew = false;
    if (!pinned) {
      pinned = await this.#lookupOrNull(from);
      if (!pinned) return { changed: false };
      isNew = true;
    }

    if (await C.verifyMessage(msg, this.key, pinned.ecdsa)) {
      if (isNew) {
        if (Object.keys(this.vault.contacts).length >= MAX_CONTACTS) return { changed: false };
        this.vault.contacts[from] = { name: '', ecdh: pinned.ecdh, ecdsa: pinned.ecdsa, added: Date.now(), request: true };
        await this.#saveVault();
        this.#emit({ type: 'contacts' });
      }
      this.#append(from, { id, dir: 'in', ts, at: Date.now(), body });
      this.hist.unread[from] = (this.hist.unread[from] ?? 0) + 1;
      this.#emit({ type: 'message', key: from, incoming: true });
      return { changed: true };
    }

    // Signature does not match the key we pinned. Either a forgery, or the sender really changed keys.
    if (!isNew && from !== this.key) {
      const info = await this.#lookupOrNull(from);
      if (info && (info.ecdsa !== pinned.ecdsa || info.ecdh !== pinned.ecdh) && (await C.verifyMessage(msg, this.key, info.ecdsa))) {
        (this.hist.pending[from] ??= []).push({ id, ts, at: Date.now(), body, signed: msg.signed, sig: C.b64uEncode(msg.sig) });
        this.#changed[from] = { ecdh: info.ecdh, ecdsa: info.ecdsa };
        this.#emit({ type: 'key-changed', key: from });
        return { changed: true }; // held back until the user accepts the new safety number
      }
    }
    return { changed: false }; // forged: dropped, never shown
  }

  // ------------------------------------------------------------ background polling

  startPolling() {
    if (this.#polling) return;
    const ctl = (this.#polling = new AbortController());
    const { signal } = ctl;
    (async () => {
      let backoff = 1000;
      while (!signal.aborted) {
        try {
          await this.pollOnce(25, signal);
          backoff = 1000;
          if (this.#offline) { this.#offline = false; this.#emit({ type: 'online' }); }
        } catch (e) {
          if (signal.aborted) break;
          if (e.status === 401) {
            if (e.message !== REPLACED) this.#emit({ type: 'session-expired' }); // 'replaced' was announced by #box
            break;
          }
          if (!this.#offline) { this.#offline = true; this.#emit({ type: 'offline' }); }
          await sleep(backoff, signal);
          backoff = Math.min(backoff * 2, 30_000);
        }
      }
    })();
  }

  stopPolling() {
    this.#polling?.abort();
    this.#polling = null;
  }
}
