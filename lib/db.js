// Storage layer. The database only ever holds:
//   accounts   - HMAC'd username id, scrypt'd login proof, and an opaque encrypted vault
//   mailboxes  - HMAC'd 10-digit key, the two PUBLIC keys, and an HMAC'd mailbox secret
//   messages   - end-to-end encrypted blobs addressed to an HMAC'd mailbox id, deleted on delivery
// There is deliberately no link between an account row and a mailbox row.
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

export function openDb(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const file = path.join(dataDir, 'messenger.db');
  const db = new DatabaseSync(file);
  try { fs.chmodSync(file, 0o600); } catch { /* best effort (e.g. on Windows) */ }

  db.exec(`
    PRAGMA journal_mode = DELETE;
    PRAGMA secure_delete = ON;
    PRAGMA synchronous = FULL;

    CREATE TABLE IF NOT EXISTS accounts (
      uid     TEXT PRIMARY KEY,
      salt    BLOB NOT NULL,
      hash    BLOB NOT NULL,
      vault   TEXT,
      version INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS mailboxes (
      box    TEXT PRIMARY KEY,
      ecdh   TEXT NOT NULL,
      ecdsa  TEXT NOT NULL,
      secret BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
      id      TEXT PRIMARY KEY,
      box     TEXT NOT NULL,
      blob    TEXT NOT NULL,
      expires INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS messages_box ON messages(box);
  `);

  const q = {
    addAccount: db.prepare('INSERT INTO accounts (uid, salt, hash) VALUES (?, ?, ?)'),
    getAccount: db.prepare('SELECT salt, hash, vault, version FROM accounts WHERE uid = ?'),
    setVault: db.prepare('UPDATE accounts SET vault = ?, version = version + 1 WHERE uid = ? AND version = ?'),
    setCreds: db.prepare('UPDATE accounts SET salt = ?, hash = ?, vault = ?, version = version + 1 WHERE uid = ? AND version = ?'),
    delAccount: db.prepare('DELETE FROM accounts WHERE uid = ?'),
    addBox: db.prepare('INSERT INTO mailboxes (box, ecdh, ecdsa, secret) VALUES (?, ?, ?, ?)'),
    getBox: db.prepare('SELECT ecdh, ecdsa, secret FROM mailboxes WHERE box = ?'),
    delBox: db.prepare('DELETE FROM mailboxes WHERE box = ?'),
    addMsg: db.prepare('INSERT INTO messages (id, box, blob, expires) VALUES (?, ?, ?, ?)'),
    listMsgs: db.prepare('SELECT id, blob FROM messages WHERE box = ? ORDER BY rowid LIMIT ?'),
    countMsgs: db.prepare('SELECT COUNT(*) AS n FROM messages WHERE box = ?'),
    delMsg: db.prepare('DELETE FROM messages WHERE id = ? AND box = ?'),
    delBoxMsgs: db.prepare('DELETE FROM messages WHERE box = ?'),
    purge: db.prepare('DELETE FROM messages WHERE expires < ?'),
  };

  return {
    file,
    addAccount: (uid, salt, hash) => q.addAccount.run(uid, salt, hash),
    getAccount: (uid) => q.getAccount.get(uid),
    setVault: (uid, vault, version) => Number(q.setVault.run(vault, uid, version).changes),
    setCredentials: (uid, salt, hash, vault, version) => Number(q.setCreds.run(salt, hash, vault, uid, version).changes),
    deleteAccount: (uid) => q.delAccount.run(uid),
    addMailbox: (box, ecdh, ecdsa, secret) => q.addBox.run(box, ecdh, ecdsa, secret),
    getMailbox: (box) => q.getBox.get(box),
    deleteMailbox(box) {
      q.delBoxMsgs.run(box);
      q.delBox.run(box);
    },
    addMessage: (id, box, blob, expires) => q.addMsg.run(id, box, blob, expires),
    listMessages: (box, limit = 100) => q.listMsgs.all(box, limit),
    countMessages: (box) => Number(q.countMsgs.get(box).n),
    deleteMessages(box, ids) {
      let n = 0;
      db.exec('BEGIN');
      try {
        for (const id of ids) n += Number(q.delMsg.run(id, box).changes);
        db.exec('COMMIT');
      } catch (e) {
        db.exec('ROLLBACK');
        throw e;
      }
      return n;
    },
    purgeExpired: (today) => Number(q.purge.run(today).changes),
    close: () => db.close(),
  };
}
